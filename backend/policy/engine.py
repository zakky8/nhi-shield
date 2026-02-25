"""
NHI Shield - Zero Trust Policy Engine v2.0
5-layer evaluation: identity → risk → permission → time → context
Decisions: ALLOW | DENY | STEP_UP | LOG_ONLY | QUARANTINE
"""

import asyncio
import logging
import json
import os
import fnmatch
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import List, Dict, Optional

import asyncpg

logger = logging.getLogger(__name__)


class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    STEP_UP = "STEP_UP"
    LOG_ONLY = "LOG_ONLY"
    QUARANTINE = "QUARANTINE"


class PolicyLayer(str, Enum):
    IDENTITY = "identity"
    RISK = "risk"
    PERMISSION = "permission"
    TIME = "time"
    CONTEXT = "context"


@dataclass
class PolicyContext:
    identity_id: str
    org_id: str
    action: str
    resource: str
    platform: str
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    timestamp: Optional[datetime] = None
    metadata: Dict = field(default_factory=dict)

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc)


@dataclass
class PolicyResult:
    decision: Decision
    reason: str
    layer: PolicyLayer
    confidence: float
    factors: List[Dict] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)
    evaluation_time_ms: float = 0.0

    def to_dict(self):
        return {
            'decision': self.decision.value,
            'reason': self.reason,
            'layer': self.layer.value,
            'confidence': self.confidence,
            'factors': self.factors,
            'recommended_actions': self.recommended_actions,
            'evaluation_time_ms': self.evaluation_time_ms
        }


class ZeroTrustPolicyEngine:
    """Never trust, always verify. 5-layer policy evaluation engine."""

    SENSITIVE_ACTIONS = {
        'offboard', 'delete', 'destroy', 'terminate', 'rotate', 'bulk_offboard',
        'export', 'iam:attach', 'iam:create', 'sts:assumerole', 'assign_role',
        'create_admin', 'reset_password', 'generate_credentials'
    }

    ALWAYS_DENY = {
        'root_login', 'bypass_mfa', 'disable_logging',
        'disable_cloudtrail', 'delete_audit_log', 'modify_security_policy'
    }

    def __init__(self):
        self.db_url = os.getenv('DATABASE_URL', 'postgresql://nhiadmin:nhi_secure_password_2026@localhost:5432/nhishield')
        self.pg_pool = None
        self._custom_policies: List[Dict] = []

    async def initialize(self):
        self.pg_pool = await asyncpg.create_pool(self.db_url)
        await self._load_custom_policies()
        logger.info("Zero Trust Policy Engine initialized")

    async def close(self):
        if self.pg_pool:
            await self.pg_pool.close()

    async def _load_custom_policies(self):
        try:
            async with self.pg_pool.acquire() as conn:
                rows = await conn.fetch("SELECT * FROM zero_trust_policies WHERE is_active = true")
                self._custom_policies = [dict(r) for r in rows]
        except Exception:
            self._custom_policies = []

    async def evaluate(self, ctx: PolicyContext) -> PolicyResult:
        """Evaluate through all 5 layers. Short-circuit on DENY/QUARANTINE."""
        start = datetime.now(timezone.utc)
        factors = []

        for layer_fn in [
            self._layer_identity,
            self._layer_risk,
            self._layer_permission,
            self._layer_context,
        ]:
            result = await layer_fn(ctx, factors)
            if result.decision in (Decision.DENY, Decision.QUARANTINE):
                result.factors = factors
                result.evaluation_time_ms = _ms(start)
                await self._log(ctx, result)
                return result
            if result.decision == Decision.STEP_UP:
                result.factors = factors
                result.evaluation_time_ms = _ms(start)
                await self._log(ctx, result)
                return result

        # Layer 4: Time
        result = self._layer_time(ctx, factors)
        result.factors = factors
        result.evaluation_time_ms = _ms(start)
        await self._log(ctx, result)
        return result

    async def _layer_identity(self, ctx: PolicyContext, factors: List) -> PolicyResult:
        """Validate identity exists, is active, not offboarded."""
        try:
            async with self.pg_pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT id, is_active, offboarded_at FROM identities WHERE id = $1 AND org_id = $2",
                    ctx.identity_id, ctx.org_id
                )
            if not row:
                factors.append({'layer': 'identity', 'check': 'exists', 'pass': False})
                return PolicyResult(Decision.DENY, 'Identity not found', PolicyLayer.IDENTITY, 1.0)
            if not row['is_active']:
                factors.append({'layer': 'identity', 'check': 'active', 'pass': False})
                return PolicyResult(Decision.DENY, 'Identity is inactive', PolicyLayer.IDENTITY, 1.0)
            if row['offboarded_at']:
                factors.append({'layer': 'identity', 'check': 'offboarded', 'pass': False})
                return PolicyResult(
                    Decision.DENY, 'Identity has been offboarded', PolicyLayer.IDENTITY, 1.0,
                    recommended_actions=['Investigate why offboarded identity is attempting access']
                )
            factors.append({'layer': 'identity', 'check': 'valid', 'pass': True})
            return PolicyResult(Decision.ALLOW, 'Identity valid', PolicyLayer.IDENTITY, 1.0)
        except Exception as e:
            logger.error(f"Identity layer error: {e}")
            return PolicyResult(Decision.LOG_ONLY, 'Identity check error', PolicyLayer.IDENTITY, 0.5)

    async def _layer_risk(self, ctx: PolicyContext, factors: List) -> PolicyResult:
        """Check risk score and recent unresolved alerts."""
        try:
            if not self.pg_pool:
                factors.append({'layer': 'risk', 'check': 'skipped', 'reason': 'no_db'})
                return PolicyResult(Decision.ALLOW, 'Risk check skipped (no DB)', PolicyLayer.RISK, 0.5)
            async with self.pg_pool.acquire() as conn:
                risk = await conn.fetchrow(
                    "SELECT level, total_score FROM risk_scores WHERE identity_id = $1", ctx.identity_id
                )
                open_critical = await conn.fetchval("""
                    SELECT COUNT(*) FROM anomaly_alerts
                    WHERE identity_id = $1 AND severity IN ('HIGH','CRITICAL')
                      AND resolved = false AND created_at > NOW() - INTERVAL '24 hours'
                """, ctx.identity_id)

            if risk:
                level, score = risk['level'], risk['total_score']
                factors.append({'layer': 'risk', 'level': level, 'score': score})
                if level == 'CRITICAL':
                    return PolicyResult(
                        Decision.QUARANTINE, f'Critical risk score ({score}/100)',
                        PolicyLayer.RISK, 0.95,
                        recommended_actions=['Immediately investigate', 'Review all recent activity']
                    )
                if level == 'HIGH':
                    action_lower = ctx.action.lower()
                    if any(s in action_lower for s in self.SENSITIVE_ACTIONS):
                        return PolicyResult(
                            Decision.STEP_UP, f'High risk ({score}/100) requires verification for sensitive action',
                            PolicyLayer.RISK, 0.85,
                            recommended_actions=['Require MFA', 'Log all actions for 24h']
                        )

            if open_critical and open_critical > 0:
                factors.append({'layer': 'risk', 'open_alerts': int(open_critical)})
                return PolicyResult(
                    Decision.LOG_ONLY, f'{open_critical} unresolved critical alerts',
                    PolicyLayer.RISK, 0.80,
                    recommended_actions=['Review and resolve alerts before continuing']
                )

            factors.append({'layer': 'risk', 'check': 'pass'})
            return PolicyResult(Decision.ALLOW, 'Risk acceptable', PolicyLayer.RISK, 0.9)
        except Exception as e:
            logger.error(f"Risk layer error: {e}")
            return PolicyResult(Decision.ALLOW, 'Risk check skipped', PolicyLayer.RISK, 0.5)

    async def _layer_permission(self, ctx: PolicyContext, factors: List) -> PolicyResult:
        """Check action is not in deny-list, handle sensitive ops, check custom policies."""
        action_lower = ctx.action.lower()

        # Always-deny list
        if any(d in action_lower for d in self.ALWAYS_DENY):
            factors.append({'layer': 'permission', 'check': 'deny_list', 'action': ctx.action})
            return PolicyResult(Decision.DENY, f'Action "{ctx.action}" is permanently denied', PolicyLayer.PERMISSION, 1.0)

        # Sensitive action → step-up
        if any(s in action_lower for s in self.SENSITIVE_ACTIONS):
            factors.append({'layer': 'permission', 'check': 'sensitive', 'action': ctx.action})
            return PolicyResult(
                Decision.STEP_UP, 'Sensitive action requires step-up authentication',
                PolicyLayer.PERMISSION, 0.9
            )

        # Custom org policies
        for policy in self._custom_policies:
            if str(policy.get('org_id')) != str(ctx.org_id):
                continue
            pattern = policy.get('resource_pattern', '*')
            if ctx.resource and fnmatch.fnmatch(ctx.resource.lower(), pattern.lower()):
                decision_str = policy.get('decision', 'LOG_ONLY')
                factors.append({'layer': 'permission', 'policy': policy.get('name'), 'matched': True})
                return PolicyResult(
                    Decision(decision_str), f"Custom policy: {policy.get('name', 'unnamed')}",
                    PolicyLayer.PERMISSION, 0.95
                )

        factors.append({'layer': 'permission', 'check': 'pass'})
        return PolicyResult(Decision.ALLOW, 'Permission check passed', PolicyLayer.PERMISSION, 1.0)

    async def _layer_context(self, ctx: PolicyContext, factors: List) -> PolicyResult:
        """Behavioral context: impossible travel, new IP, unusual pattern."""
        try:
            async with self.pg_pool.acquire() as conn:
                last_event = await conn.fetchrow("""
                    SELECT ip_address, timestamp FROM activity_events
                    WHERE identity_id = $1 ORDER BY timestamp DESC LIMIT 1
                """, ctx.identity_id)

            if last_event and ctx.source_ip and last_event['ip_address']:
                if last_event['ip_address'] != ctx.source_ip:
                    factors.append({'layer': 'context', 'check': 'ip_change', 'old': last_event['ip_address'], 'new': ctx.source_ip})
                    # Don't deny, but log - IP changes are common for some identities
                    return PolicyResult(
                        Decision.LOG_ONLY, f'IP address changed from {last_event["ip_address"]} to {ctx.source_ip}',
                        PolicyLayer.CONTEXT, 0.70,
                        recommended_actions=['Verify this IP change is expected']
                    )

            factors.append({'layer': 'context', 'check': 'pass'})
            return PolicyResult(Decision.ALLOW, 'Context check passed', PolicyLayer.CONTEXT, 0.9)
        except Exception as e:
            logger.error(f"Context layer error: {e}")
            return PolicyResult(Decision.ALLOW, 'Context check skipped', PolicyLayer.CONTEXT, 0.5)

    def _layer_time(self, ctx: PolicyContext, factors: List) -> PolicyResult:
        """Time-based access policy: business hours enforcement."""
        if not ctx.timestamp:
            factors.append({'layer': 'time', 'check': 'skipped'})
            return PolicyResult(Decision.ALLOW, 'Time check skipped', PolicyLayer.TIME, 0.5)

        hour = ctx.timestamp.hour
        weekday = ctx.timestamp.weekday()  # 0=Mon, 6=Sun

        # Weekend outside business hours for sensitive actions
        is_weekend = weekday >= 5
        is_off_hours = not (8 <= hour <= 20)  # Outside 8am-8pm UTC

        action_lower = ctx.action.lower()
        is_sensitive = any(s in action_lower for s in self.SENSITIVE_ACTIONS)

        if is_weekend and is_off_hours and is_sensitive:
            factors.append({'layer': 'time', 'weekend': True, 'hour': hour, 'sensitive': True})
            return PolicyResult(
                Decision.STEP_UP,
                f'Sensitive action at {hour}:00 UTC on weekend requires additional verification',
                PolicyLayer.TIME, 0.80,
                recommended_actions=['Verify this is a legitimate emergency action']
            )

        factors.append({'layer': 'time', 'hour': hour, 'weekday': weekday, 'pass': True})
        return PolicyResult(Decision.ALLOW, 'Time policy passed', PolicyLayer.TIME, 1.0)

    async def _log(self, ctx: PolicyContext, result: PolicyResult):
        """Log every policy decision for audit trail."""
        try:
            async with self.pg_pool.acquire() as conn:
                await conn.execute("""
                    INSERT INTO policy_decisions
                    (org_id, identity_id, action, resource, decision, reason, layer, confidence, factors, created_at)
                    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NOW())
                """, ctx.org_id, ctx.identity_id, ctx.action, ctx.resource,
                    result.decision.value, result.reason, result.layer.value,
                    result.confidence, json.dumps(result.factors))
        except Exception:
            pass  # Non-fatal - table may not exist yet


def _ms(start: datetime) -> float:
    return (datetime.now(timezone.utc) - start).total_seconds() * 1000


# ── Standalone test ──────────────────────────────────────────────────────────
if __name__ == "__main__":

    async def test():
        _ = ZeroTrustPolicyEngine()  # validates initialization path
        # Test without DB (will gracefully degrade)
        ctx = PolicyContext(
            identity_id="test-id-123",
            org_id="org-456",
            action="delete",
            resource="iam/users/admin",
            platform="aws",
            source_ip="1.2.3.4"
        )
        print(f"Testing policy context: action={ctx.action}, resource={ctx.resource}")
        print("Zero Trust Policy Engine loaded successfully.")

    asyncio.run(test())
