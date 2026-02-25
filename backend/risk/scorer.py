"""
NHI Shield — Predictive Risk Scoring Engine v2.0
================================================
6 weighted scoring factors + historical trend analysis + 7-day forecast.
Factors: dormancy (20%), permissions (20%), anomalies (25%),
         hygiene (15%), age (10%), exposure (10%)
"""

import asyncio, json, logging, os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

import asyncpg
import numpy as np
from sklearn.linear_model import LinearRegression

logger = logging.getLogger(__name__)

DB_URL    = os.getenv("DATABASE_URL", "postgresql://nhiadmin:nhi_secure_password_2026@localhost:5432/nhishield")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")

FACTOR_WEIGHTS = {
    "dormancy": 0.20, "permissions": 0.20, "anomalies": 0.25,
    "hygiene": 0.15, "age": 0.10, "exposure": 0.10,
}


@dataclass
class RiskScore:
    identity_id: str
    org_id: str
    total_score: float
    level: str
    factors: Dict[str, float]
    is_current: bool = True
    calculated_at: Optional[datetime] = None


@dataclass
class RiskTrend:
    identity_id: str
    current_score: float
    trend: str          # INCREASING | DECREASING | STABLE | VOLATILE
    velocity: float     # points per period
    forecast_7d: float
    forecast_30d: float
    confidence: float   # R²
    recommendations: List[str] = field(default_factory=list)


class PredictiveRiskScorer:

    def __init__(self, pg: asyncpg.Pool):
        self.pg = pg

    async def score_identity(self, identity_id: str, org_id: str) -> RiskScore:
        row = await self.pg.fetchrow("""
            SELECT id, name, platform, type, permissions, owner, last_used,
                   is_active, created_at, last_rotated, metadata
            FROM identities WHERE id=$1 AND org_id=$2
        """, identity_id, org_id)
        if not row:
            return RiskScore(identity_id, org_id, 0, "LOW", {})

        factors = {
            "dormancy":    self._score_dormancy(row),
            "permissions": self._score_permissions(row),
            "anomalies":   await self._score_anomalies(identity_id),
            "hygiene":     self._score_hygiene(row),
            "age":         self._score_age(row),
            "exposure":    self._score_exposure(row),
        }
        total = round(min(100.0, max(0.0,
            sum(factors[k] * FACTOR_WEIGHTS[k] for k in factors))), 1)
        level = ("CRITICAL" if total >= 75 else "HIGH" if total >= 50
                 else "MEDIUM" if total >= 25 else "LOW")

        score = RiskScore(identity_id=identity_id, org_id=org_id,
                          total_score=total, level=level, factors=factors,
                          calculated_at=datetime.now(timezone.utc))
        await self._persist(score)
        return score

    async def get_trend(self, identity_id: str) -> Optional[RiskTrend]:
        history = await self.pg.fetch("""
            SELECT total_score, calculated_at FROM risk_scores
            WHERE identity_id=$1 ORDER BY calculated_at DESC LIMIT 30
        """, identity_id)
        if len(history) < 3:
            return None

        scores = [float(r["total_score"]) for r in reversed(history)]
        X = np.arange(len(scores)).reshape(-1, 1)
        y = np.array(scores)
        model = LinearRegression().fit(X, y)
        slope  = float(model.coef_[0])
        r_sq   = float(model.score(X, y))
        n      = len(scores)
        f7d  = float(np.clip(model.predict([[n+7]])[0], 0, 100))
        f30d = float(np.clip(model.predict([[n+30]])[0], 0, 100))

        std = float(np.std(scores))
        trend = ("VOLATILE" if std > 15 else "INCREASING" if slope > 1.5
                 else "DECREASING" if slope < -1.5 else "STABLE")

        recs = []
        if trend == "INCREASING":
            recs.append(f"Risk increasing {slope:.1f}pts/period. Predicted {f7d:.0f} in 7 days.")
        if f7d >= 75: recs.append("⚠ Forecast CRITICAL in 7 days — immediate review required.")
        elif f7d >= 50: recs.append("Forecast HIGH in 7 days — schedule review within 3 days.")
        if trend == "VOLATILE": recs.append("Volatile risk pattern — investigate intermittent anomalies.")

        return RiskTrend(identity_id=identity_id, current_score=scores[-1],
                         trend=trend, velocity=slope, forecast_7d=f7d, forecast_30d=f30d,
                         confidence=min(r_sq, 0.95), recommendations=recs)

    async def score_all_org(self, org_id: str):
        rows = await self.pg.fetch(
            "SELECT id FROM identities WHERE org_id=$1 AND is_active=true", org_id)
        for i in range(0, len(rows), 10):
            batch = rows[i:i+10]
            await asyncio.gather(*[self.score_identity(str(r["id"]), org_id) for r in batch])
        logger.info(f"Scored {len(rows)} identities for {org_id}")

    # ── Factor scorers ───────────────────────────────────────────────────────

    def _score_dormancy(self, row) -> float:
        lu = row.get("last_used")
        if lu is None: return 100.0
        if isinstance(lu, str):
            try: lu = datetime.fromisoformat(lu.replace('Z', '+00:00'))
            except Exception: lu = None
        if isinstance(lu, datetime) and lu.tzinfo is None:
            lu = lu.replace(tzinfo=timezone.utc)
        d = (datetime.now(timezone.utc) - lu).days
        return 100.0 if d >= 180 else 60.0 if d >= 90 else 30.0 if d >= 30 else 0.0

    def _score_permissions(self, row) -> float:
        raw = row.get("permissions")
        if not raw: return 0.0
        if isinstance(raw, str):
            try: perms = json.loads(raw)
            except Exception: perms = [p.strip() for p in raw.split(",") if p.strip()]
        else: perms = list(raw)
        pl = [str(p).lower() for p in perms]
        if any(p in ["administratoraccess","admin","root","*:*","*"] for p in pl): return 100.0
        if any("*" in p for p in pl): return 90.0
        if any(p in ["iam:*","iam:createuser","iam:createaccesskey"] for p in pl): return 80.0
        if len(perms) > 20: return 60.0
        if len(perms) > 10: return 40.0
        return 0.0

    async def _score_anomalies(self, identity_id: str) -> float:
        try:
            r = await self.pg.fetchrow("""
                SELECT COUNT(*) FILTER (WHERE severity='CRITICAL' AND resolved=false) c,
                       COUNT(*) FILTER (WHERE severity='HIGH' AND resolved=false) h,
                       COUNT(*) FILTER (WHERE severity='MEDIUM' AND resolved=false) m
                FROM anomaly_alerts WHERE identity_id=$1 AND created_at>NOW()-INTERVAL '30 days'
            """, identity_id)
            if r["c"] >= 1: return 100.0
            if r["h"] >= 1: return 75.0
            if r["m"] >= 3: return 50.0
            if r["m"] >= 1: return 30.0
        except Exception: pass
        return 0.0

    def _score_hygiene(self, row) -> float:
        s = 0.0
        if not row.get("owner"): s += 30.0
        meta = row.get("metadata") or {}
        if isinstance(meta, str):
            try: meta = json.loads(meta)
            except Exception: meta = {}
        if not meta.get("expiry_date"): s += 25.0
        lr = row.get("last_rotated")
        if lr is None: s += 30.0
        else:
            try:
                # lr may be a datetime object or a string from DB
                if isinstance(lr, str):
                    lr = datetime.fromisoformat(lr.replace('Z', '+00:00'))
                if isinstance(lr, datetime):
                    if lr.tzinfo is None:
                        lr = lr.replace(tzinfo=timezone.utc)
                    if (datetime.now(timezone.utc) - lr).days > 90:
                        s += 30.0
            except Exception:
                s += 15.0  # unknown rotation date → partial penalty
        return min(s, 100.0)

    def _score_age(self, row) -> float:
        c = row.get("created_at")
        if not c: return 0.0
        if isinstance(c, str):
            try: c = datetime.fromisoformat(c.replace('Z', '+00:00'))
            except Exception: return 0.0
        if isinstance(c, datetime) and c.tzinfo is None:
            c = c.replace(tzinfo=timezone.utc)
        d = (datetime.now(timezone.utc) - c).days
        return 75.0 if d > 730 else 50.0 if d > 365 else 25.0 if d > 180 else 0.0

    def _score_exposure(self, row) -> float:
        meta = row.get("metadata") or {}
        if isinstance(meta, str):
            try: meta = json.loads(meta)
            except Exception: meta = {}
        s = 0.0
        if meta.get("internet_accessible"): s += 60.0
        if meta.get("public_webhook"):      s += 40.0
        return min(s, 100.0)

    async def _persist(self, score: RiskScore):
        try:
            async with self.pg.acquire() as conn:
                await conn.execute(
                    "UPDATE risk_scores SET is_current=false WHERE identity_id=$1 AND is_current=true",
                    score.identity_id)
                await conn.execute("""
                    INSERT INTO risk_scores(identity_id,total_score,level,factors,is_current,calculated_at)
                    VALUES($1,$2,$3,$4,true,NOW())
                """, score.identity_id, score.total_score, score.level, json.dumps(score.factors))
        except Exception as e: logger.warning(f"Persist score: {e}")


async def run_risk_scheduler():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    pg = await asyncpg.create_pool(DB_URL)
    scorer = PredictiveRiskScorer(pg)
    import redis.asyncio as aioredis
    redis = await aioredis.from_url(REDIS_URL, decode_responses=True)

    async def listen():
        ps = redis.pubsub()
        await ps.subscribe("risk:recalculate")
        async for msg in ps.listen():
            if msg["type"] != "message": continue
            try:
                d = json.loads(msg["data"])
                await scorer.score_identity(d["identity_id"], d["org_id"])
            except Exception as e: logger.warning(f"Risk trigger: {e}")

    async def periodic():
        while True:
            try:
                orgs = await pg.fetch("SELECT id FROM organizations WHERE is_active=true")
                for org in orgs:
                    await scorer.score_all_org(str(org["id"]))
            except Exception as e: logger.error(f"Periodic risk: {e}")
            await asyncio.sleep(6*3600)

    logger.info("Predictive Risk Scorer running")
    await asyncio.gather(listen(), periodic())


if __name__ == "__main__":
    asyncio.run(run_risk_scheduler())
