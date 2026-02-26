"""
NHI Shield — Lifecycle Manager v2.0
=====================================
Automated identity lifecycle: dormancy detection, expiry enforcement,
auto-offboarding, scheduled reviews, owner notifications.

Rules:
  - Dormant 90d  → create review task + alert owner
  - Dormant 180d → auto-suggest offboard + HIGH alert
  - Expired      → auto-disable + CRITICAL alert
  - No owner 30d → escalate to org admin
  - No rotation 90d → flag + recommend rotation
"""

import asyncio, json, logging, os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List

import asyncpg
import redis.asyncio as aioredis

logger = logging.getLogger(__name__)

DB_URL    = os.getenv("DATABASE_URL", "postgresql://nhiadmin:nhi_secure_password_2026@localhost:5432/nhishield")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")


@dataclass
class LifecycleAction:
    identity_id: str
    org_id: str
    action: str         # ALERT | FLAG | DISABLE | OFFBOARD_SUGGESTED | REVIEW_REQUIRED
    reason: str
    severity: str
    metadata: Dict


class LifecycleManager:

    # Thresholds (days)
    DORMANT_WARN   = 90
    DORMANT_CRIT   = 180
    NO_OWNER_DAYS  = 30
    NO_ROTATION_DAYS = 90

    def __init__(self, pg: asyncpg.Pool, redis: aioredis.Redis):
        self.pg = pg
        self.redis = redis

    async def run_checks(self, org_id: str) -> List[LifecycleAction]:
        """Run all lifecycle checks for an org. Returns list of actions taken."""
        actions = []
        actions += await self._check_dormant(org_id)
        actions += await self._check_expired(org_id)
        actions += await self._check_no_owner(org_id)
        actions += await self._check_no_rotation(org_id)
        actions += await self._check_pending_reviews(org_id)

        for action in actions:
            await self._persist_action(action)
            await self._publish_action(action)

        logger.info(f"Lifecycle check for {org_id}: {len(actions)} actions")
        return actions

    async def offboard(self, identity_id: str, org_id: str, reason: str, user_id: str) -> bool:
        """Perform immediate offboarding of an identity."""
        try:
            async with self.pg.acquire() as conn:
                await conn.execute("""
                    UPDATE identities
                    SET is_active=false, offboarded_at=NOW(),
                        offboarded_by=$3, offboard_reason=$4, updated_at=NOW()
                    WHERE id=$1 AND org_id=$2
                """, identity_id, org_id, user_id, reason)

                await conn.execute("""
                    INSERT INTO audit_logs(org_id,user_id,identity_id,action,description,created_at)
                    VALUES($1,$2,$3,'IDENTITY_OFFBOARDED',$4,NOW())
                """, org_id, user_id, identity_id,
                    f"Identity offboarded: {reason}")

            await self.redis.publish("risk:recalculate",
                json.dumps({"identity_id": identity_id, "org_id": org_id}))
            await self.redis.publish("identity:offboarded",
                json.dumps({"identity_id": identity_id, "org_id": org_id, "reason": reason}))
            return True
        except Exception as e:
            logger.error(f"Offboard error: {e}")
            return False

    async def assign_owner(self, identity_id: str, org_id: str, owner_email: str, user_id: str) -> bool:
        """Assign or change the owner of an identity."""
        try:
            async with self.pg.acquire() as conn:
                await conn.execute("""
                    UPDATE identities SET owner=$1, updated_at=NOW()
                    WHERE id=$2 AND org_id=$3
                """, owner_email, identity_id, org_id)
                await conn.execute("""
                    INSERT INTO audit_logs(org_id,user_id,identity_id,action,description,created_at)
                    VALUES($1,$2,$3,'OWNER_ASSIGNED',$4,NOW())
                """, org_id, user_id, identity_id, f"Owner assigned: {owner_email}")
            return True
        except Exception as e:
            logger.error(f"Assign owner error: {e}")
            return False

    async def schedule_review(self, identity_id: str, org_id: str,
                               review_date: datetime, assigned_to: str) -> bool:
        """Schedule a mandatory access review for an identity."""
        try:
            async with self.pg.acquire() as conn:
                await conn.execute("""
                    INSERT INTO identity_reviews
                    (identity_id, org_id, review_date, assigned_to, status, created_at)
                    VALUES($1,$2,$3,$4,'PENDING',NOW())
                    ON CONFLICT (identity_id) DO UPDATE
                    SET review_date=$3, assigned_to=$4, status='PENDING', updated_at=NOW()
                """, identity_id, org_id, review_date, assigned_to)
            return True
        except Exception as e:
            logger.warning(f"Schedule review error (table may not exist yet): {e}")
            return False

    # ── Private Checks ────────────────────────────────────────────────────────

    async def _check_dormant(self, org_id: str) -> List[LifecycleAction]:
        actions = []
        rows = await self.pg.fetch("""
            SELECT id, name, platform, owner, last_used
            FROM identities
            WHERE org_id=$1 AND is_active=true
            AND (last_used IS NULL OR last_used < NOW()-INTERVAL '90 days')
        """, org_id)

        for r in rows:
            dormant_days = (
                (datetime.now(timezone.utc) - r["last_used"].replace(tzinfo=timezone.utc)).days
                if r["last_used"] else 999
            )

            if dormant_days >= self.DORMANT_CRIT:
                actions.append(LifecycleAction(
                    identity_id=str(r["id"]), org_id=org_id,
                    action="OFFBOARD_SUGGESTED",
                    reason=f"Identity dormant for {dormant_days} days (180d threshold)",
                    severity="HIGH",
                    metadata={"dormant_days": dormant_days, "last_used": str(r["last_used"]),
                              "platform": r["platform"], "name": r["name"]}
                ))
            elif dormant_days >= self.DORMANT_WARN:
                actions.append(LifecycleAction(
                    identity_id=str(r["id"]), org_id=org_id,
                    action="REVIEW_REQUIRED",
                    reason=f"Identity dormant for {dormant_days} days — review required",
                    severity="MEDIUM",
                    metadata={"dormant_days": dormant_days, "platform": r["platform"], "name": r["name"]}
                ))
        return actions

    async def _check_expired(self, org_id: str) -> List[LifecycleAction]:
        actions = []
        rows = await self.pg.fetch("""
            SELECT id, name, platform,
                   (metadata->>'expiry_date')::timestamp as expiry_date
            FROM identities
            WHERE org_id=$1 AND is_active=true
            AND (metadata->>'expiry_date') IS NOT NULL
            AND (metadata->>'expiry_date')::timestamp < NOW()
        """, org_id)

        for r in rows:
            # Auto-disable expired identities
            await self.pg.execute(
                "UPDATE identities SET is_active=false, updated_at=NOW() WHERE id=$1",
                r["id"])
            actions.append(LifecycleAction(
                identity_id=str(r["id"]), org_id=org_id,
                action="DISABLE",
                reason=f"Identity expired on {r['expiry_date']} — auto-disabled",
                severity="CRITICAL",
                metadata={"expiry_date": str(r["expiry_date"]), "platform": r["platform"], "name": r["name"]}
            ))
        return actions

    async def _check_no_owner(self, org_id: str) -> List[LifecycleAction]:
        rows = await self.pg.fetch("""
            SELECT id, name, platform,
                   NOW() - created_at AS age
            FROM identities
            WHERE org_id=$1 AND is_active=true AND owner IS NULL
            AND created_at < NOW()-INTERVAL '30 days'
        """, org_id)
        return [
            LifecycleAction(
                identity_id=str(r["id"]), org_id=org_id,
                action="FLAG",
                reason=f"Identity without owner for {r['age'].days} days",
                severity="MEDIUM",
                metadata={"platform": r["platform"], "name": r["name"],
                          "age_days": r["age"].days}
            ) for r in rows
        ]

    async def _check_no_rotation(self, org_id: str) -> List[LifecycleAction]:
        rows = await self.pg.fetch("""
            SELECT id, name, platform, last_rotated,
                   EXTRACT(DAY FROM NOW()-COALESCE(last_rotated, created_at)) as days_since
            FROM identities
            WHERE org_id=$1 AND is_active=true
            AND COALESCE(last_rotated, created_at) < NOW()-INTERVAL '90 days'
        """, org_id)
        return [
            LifecycleAction(
                identity_id=str(r["id"]), org_id=org_id,
                action="FLAG",
                reason=f"Credential not rotated for {int(r['days_since'])} days",
                severity="MEDIUM",
                metadata={"platform": r["platform"], "name": r["name"],
                          "days_since_rotation": int(r["days_since"])}
            ) for r in rows
        ]

    async def _check_pending_reviews(self, org_id: str) -> List[LifecycleAction]:
        try:
            rows = await self.pg.fetch("""
                SELECT ir.identity_id, i.name, i.platform, ir.review_date
                FROM identity_reviews ir
                JOIN identities i ON i.id=ir.identity_id
                WHERE i.org_id=$1 AND ir.status='PENDING' AND ir.review_date <= NOW()
            """, org_id)
            return [
                LifecycleAction(
                    identity_id=str(r["identity_id"]), org_id=org_id,
                    action="ALERT",
                    reason="Scheduled access review overdue",
                    severity="MEDIUM",
                    metadata={"platform": r["platform"], "name": r["name"],
                              "review_date": str(r["review_date"])}
                ) for r in rows
            ]
        except Exception:
            return []

    async def _persist_action(self, action: LifecycleAction):
        try:
            await self.pg.execute("""
                INSERT INTO anomaly_alerts
                (org_id,identity_id,alert_type,severity,description,evidence,created_at)
                VALUES($1,$2,$3,$4,$5,$6,NOW())
            """, action.org_id, action.identity_id,
                f"LIFECYCLE_{action.action}", action.severity,
                action.reason, json.dumps(action.metadata))
        except Exception as e:
            logger.warning(f"Persist lifecycle action: {e}")

    async def _publish_action(self, action: LifecycleAction):
        try:
            await self.redis.publish("lifecycle:action", json.dumps({
                "identity_id": action.identity_id,
                "org_id": action.org_id,
                "action": action.action,
                "reason": action.reason,
                "severity": action.severity,
                "metadata": action.metadata,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }))
        except Exception: pass


async def run_lifecycle_scheduler():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    pg = await asyncpg.create_pool(DB_URL)
    redis = await aioredis.from_url(REDIS_URL, decode_responses=True)
    mgr = LifecycleManager(pg, redis)

    logger.info("Lifecycle Manager running — checking every 6 hours")
    while True:
        try:
            orgs = await pg.fetch("SELECT id FROM organizations WHERE is_active=true")
            for org in orgs:
                actions = await mgr.run_checks(str(org["id"]))
                if actions:
                    logger.info(f"Org {org['id']}: {len(actions)} lifecycle actions")
        except Exception as e:
            logger.error(f"Lifecycle scheduler error: {e}")

        await asyncio.sleep(6 * 3600)  # Run every 6 hours


if __name__ == "__main__":
    asyncio.run(run_lifecycle_scheduler())
