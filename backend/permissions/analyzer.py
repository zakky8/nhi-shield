"""
NHI Shield — Permission Analyzer v2.0
=======================================
Compares granted permissions vs. actually used permissions.
Generates least-privilege recommendations with risk-reduction estimates.

Output:
  - Over-permissioned identities list
  - Specific permissions to remove
  - Generated remediation scripts (AWS, GitHub, Slack)
  - Risk reduction % per recommendation
"""

import asyncio, json, logging, os, re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Optional

import asyncpg

logger = logging.getLogger(__name__)

DB_URL = os.getenv("DATABASE_URL", "postgresql://nhiadmin:nhi_secure_password_2026@localhost:5432/nhishield")

# AWS admin/dangerous permissions
AWS_DANGEROUS = {
    "AdministratorAccess", "PowerUserAccess", "IAMFullAccess",
    "AWSAccountManagementFullAccess", "AWSOrganizationsFullAccess",
    "*:*",
}

GITHUB_DANGEROUS_SCOPES = {"admin:org", "admin:repo_hook", "delete_repo", "admin:enterprise"}
SLACK_DANGEROUS_SCOPES  = {"admin", "admin.users:read", "admin.users:write",
                            "channels:history", "files:read"}


@dataclass
class PermissionGap:
    identity_id: str
    identity_name: str
    platform: str
    org_id: str
    granted_permissions: List[str]
    used_permissions: List[str]
    unused_permissions: List[str]
    dangerous_permissions: List[str]
    recommendation: str
    risk_reduction_pct: int
    remediation_script: str = ""


@dataclass
class AnalysisResult:
    org_id: str
    analyzed_at: datetime
    total_analyzed: int
    over_permissioned: int
    gaps: List[PermissionGap]
    total_risky_permissions: int
    summary: str


class PermissionAnalyzer:

    def __init__(self, pg: asyncpg.Pool):
        self.pg = pg

    async def analyze_org(self, org_id: str) -> AnalysisResult:
        identities = await self.pg.fetch("""
            SELECT i.id, i.name, i.platform, i.type, i.permissions,
                   i.metadata
            FROM identities i
            WHERE i.org_id=$1 AND i.is_active=true
        """, org_id)

        gaps = []
        for identity in identities:
            gap = await self._analyze_identity(identity, org_id)
            if gap and gap.unused_permissions:
                gaps.append(gap)

        gaps.sort(key=lambda g: len(g.unused_permissions) + len(g.dangerous_permissions), reverse=True)

        total_risky = sum(len(g.dangerous_permissions) for g in gaps)
        over = len(gaps)

        summary = (
            f"Analyzed {len(identities)} identities. "
            f"{over} over-permissioned ({over/max(len(identities),1)*100:.0f}%). "
            f"{total_risky} dangerous permissions found. "
            f"Implementing all recommendations reduces attack surface by ~"
            f"{min(80, total_risky*5)}%."
        )

        return AnalysisResult(
            org_id=org_id,
            analyzed_at=datetime.now(timezone.utc),
            total_analyzed=len(identities),
            over_permissioned=over,
            gaps=gaps,
            total_risky_permissions=total_risky,
            summary=summary,
        )

    async def analyze_identity(self, identity_id: str, org_id: str) -> Optional[PermissionGap]:
        row = await self.pg.fetchrow("""
            SELECT id, name, platform, type, permissions, metadata
            FROM identities WHERE id=$1 AND org_id=$2
        """, identity_id, org_id)
        if not row:
            return None
        return await self._analyze_identity(row, org_id)

    async def generate_remediation(self, gap: PermissionGap) -> str:
        """Generate platform-specific remediation script."""
        platform = gap.platform.lower()
        if platform == "aws":
            return self._aws_remediation(gap)
        elif platform == "github":
            return self._github_remediation(gap)
        elif platform == "slack":
            return self._slack_remediation(gap)
        else:
            return self._generic_remediation(gap)

    # ── Internal ─────────────────────────────────────────────────────────────

    async def _analyze_identity(self, row, org_id: str) -> Optional[PermissionGap]:
        name = row["name"]
        platform = row["platform"]
        permissions_raw = row["permissions"]

        if not permissions_raw:
            return None

        # Parse permissions (stored as JSON array or comma string)
        if isinstance(permissions_raw, list):
            granted = [str(p) for p in permissions_raw]
        elif isinstance(permissions_raw, str):
            try:
                granted = json.loads(permissions_raw)
            except Exception:
                granted = [p.strip() for p in permissions_raw.split(",") if p.strip()]
        else:
            granted = []

        if not granted:
            return None

        # Fetch actual usage from activity_events
        used = await self._get_used_permissions(str(row["id"]))

        # Find unused = granted but never seen in activity
        unused = [p for p in granted if not self._permission_used(p, used)]

        # Flag dangerous permissions
        dangerous = self._find_dangerous(granted, platform)

        if not unused and not dangerous:
            return None

        risk_reduction = min(90, len(unused)*5 + len(dangerous)*15)
        recommendation = self._build_recommendation(name, platform, granted, unused, dangerous)
        gap = PermissionGap(
            identity_id=str(row["id"]),
            identity_name=name,
            platform=platform,
            org_id=org_id,
            granted_permissions=granted,
            used_permissions=list(used),
            unused_permissions=unused,
            dangerous_permissions=dangerous,
            recommendation=recommendation,
            risk_reduction_pct=risk_reduction,
        )
        gap.remediation_script = await self.generate_remediation(gap)
        return gap

    async def _get_used_permissions(self, identity_id: str) -> set:
        """Extract implied permissions from activity_events actions."""
        try:
            rows = await self.pg.fetch("""
                SELECT DISTINCT action FROM activity_events
                WHERE identity_id=$1
                AND timestamp >= NOW()-INTERVAL '90 days'
                LIMIT 500
            """, identity_id)
            return {r["action"].lower() for r in rows}
        except Exception:
            return set()

    def _permission_used(self, permission: str, used_actions: set) -> bool:
        """Check if a permission was implied by any observed action."""
        # Admin / wildcard always considered "used" (can't verify)
        if "*" in permission or "admin" in permission.lower():
            return True
        # Normalize both sides for comparison (case-insensitive, colon→underscore)
        def _norm(s: str) -> str:
            return s.lower().replace(":", "_").replace("-", "_")
        perm_norm = _norm(permission)
        for action in used_actions:
            action_norm = _norm(str(action))
            if perm_norm == action_norm or perm_norm in action_norm or action_norm in perm_norm:
                return True
        return False

    def _find_dangerous(self, permissions: List[str], platform: str) -> List[str]:
        dangerous = []
        if platform.lower() == "aws":
            for p in permissions:
                if p in AWS_DANGEROUS or ":*" in p or p == "*":
                    dangerous.append(p)
        elif platform.lower() == "github":
            for p in permissions:
                if p.lower() in GITHUB_DANGEROUS_SCOPES:
                    dangerous.append(p)
        elif platform.lower() == "slack":
            for p in permissions:
                if p.lower() in SLACK_DANGEROUS_SCOPES:
                    dangerous.append(p)
        return dangerous

    def _build_recommendation(self, name, platform, granted, unused, dangerous) -> str:
        parts = []
        if dangerous:
            parts.append(f"URGENT: Remove dangerous permissions: {', '.join(dangerous)}")
        if unused:
            parts.append(f"Remove {len(unused)} unused permissions: {', '.join(unused[:5])}"
                         + (f" +{len(unused)-5} more" if len(unused)>5 else ""))
        parts.append(f"Replace with least-privilege policy granting only: "
                     f"{', '.join([p for p in granted if p not in unused][:5]) or 'read-only'}")
        return " | ".join(parts)

    def _aws_remediation(self, gap: PermissionGap) -> str:
        safe_name = re.sub(r'[^a-zA-Z0-9_]', '_', gap.identity_name)
        allowed = [p for p in gap.granted_permissions if p not in gap.unused_permissions]
        statements = []
        for perm in allowed[:10]:
            if ":" in perm:
                svc, action = perm.split(":", 1)
                statements.append(f'    {{"Effect":"Allow","Action":"{svc}:{action}","Resource":"*"}}')

        script = f"""#!/bin/bash
# NHI Shield — AWS Least-Privilege Remediation
# Identity: {gap.identity_name} | Risk Reduction: ~{gap.risk_reduction_pct}%
# Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}

IAM_USER="{gap.identity_name}"
POLICY_NAME="NHIShield-LeastPrivilege-{safe_name}"

# Step 1: Detach all existing managed policies
POLICIES=$(aws iam list-attached-user-policies --user-name $IAM_USER --query 'AttachedPolicies[*].PolicyArn' --output text)
for POLICY_ARN in $POLICIES; do
  echo "Detaching: $POLICY_ARN"
  aws iam detach-user-policy --user-name $IAM_USER --policy-arn $POLICY_ARN
done

# Step 2: Create least-privilege inline policy
cat > /tmp/nhi-policy.json << 'EOF'
{{
  "Version": "2012-10-17",
  "Statement": [
{chr(10).join(statements) if statements else '    {"Effect":"Allow","Action":"sts:GetCallerIdentity","Resource":"*"}'}
  ]
}}
EOF

# Step 3: Apply policy
aws iam put-user-policy --user-name $IAM_USER --policy-name $POLICY_NAME --policy-document file:///tmp/nhi-policy.json
echo "✅ Least-privilege policy applied for $IAM_USER"

# Step 4: Remove dangerous permissions explicitly
{"".join([f"# Removed: {p}{chr(10)}" for p in gap.dangerous_permissions])}
echo "Verification: aws iam get-user-policy --user-name $IAM_USER --policy-name $POLICY_NAME"
"""
        return script

    def _github_remediation(self, gap: PermissionGap) -> str:
        return f"""#!/bin/bash
# NHI Shield — GitHub Least-Privilege Remediation
# Identity: {gap.identity_name} | Risk Reduction: ~{gap.risk_reduction_pct}%

# Current dangerous scopes: {', '.join(gap.dangerous_permissions)}
# Unused scopes: {', '.join(gap.unused_permissions[:5])}

# Required actions:
# 1. Go to https://github.com/settings/tokens
# 2. Delete token: {gap.identity_name}
# 3. Create new fine-grained PAT with ONLY these permissions:
#    Allowed: {', '.join(p for p in gap.granted_permissions if p not in gap.unused_permissions)[:3] or 'contents:read'}

# Using GitHub CLI:
gh api --method DELETE /apps/installations/TOKEN_ID
# Then create replacement with minimal scopes
"""

    def _slack_remediation(self, gap: PermissionGap) -> str:
        return f"""#!/bin/bash
# NHI Shield — Slack Least-Privilege Remediation
# Identity: {gap.identity_name} | Risk Reduction: ~{gap.risk_reduction_pct}%

# Dangerous scopes found: {', '.join(gap.dangerous_permissions)}
# Unused scopes: {', '.join(gap.unused_permissions[:5])}

# Actions required:
# 1. Go to https://api.slack.com/apps
# 2. Select app: {gap.identity_name}
# 3. Navigate to: OAuth & Permissions
# 4. Remove these scopes: {', '.join(gap.dangerous_permissions + gap.unused_permissions[:3])}
# 5. Reinstall app to apply changes
# 6. Required scopes only: {', '.join(p for p in gap.granted_permissions if p not in gap.unused_permissions)[:3] or 'channels:read'}
"""

    def _generic_remediation(self, gap: PermissionGap) -> str:
        return f"""#!/bin/bash
# NHI Shield — Least-Privilege Remediation
# Identity: {gap.identity_name} ({gap.platform})
# Risk Reduction: ~{gap.risk_reduction_pct}%

# Remove these unused permissions:
{chr(10).join(f"# - {p}" for p in gap.unused_permissions[:10])}

# Remove these dangerous permissions:
{chr(10).join(f"# - {p}" for p in gap.dangerous_permissions)}

# Keep only:
{chr(10).join(f"# + {p}" for p in gap.granted_permissions if p not in gap.unused_permissions and p not in gap.dangerous_permissions)[:10] or "# + (review manually)"}
"""


async def run_permission_analyzer():
    """Run as standalone service — analyze all orgs every 24h."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    pg = await asyncpg.create_pool(DB_URL)
    analyzer = PermissionAnalyzer(pg)

    while True:
        try:
            orgs = await pg.fetch("SELECT id FROM organizations WHERE is_active=true")
            for org in orgs:
                result = await analyzer.analyze_org(str(org["id"]))
                logger.info(f"Permission analysis: {result.summary}")
                # Store results
                for gap in result.gaps:
                    await pg.execute("""
                        INSERT INTO permission_analysis
                        (identity_id, org_id, unused_permissions, dangerous_permissions,
                         recommendation, risk_reduction_pct, analyzed_at)
                        VALUES($1,$2,$3,$4,$5,$6,NOW())
                        ON CONFLICT (identity_id) DO UPDATE SET
                            unused_permissions=$3, dangerous_permissions=$4,
                            recommendation=$5, risk_reduction_pct=$6, analyzed_at=NOW()
                    """, gap.identity_id, gap.org_id,
                        json.dumps(gap.unused_permissions),
                        json.dumps(gap.dangerous_permissions),
                        gap.recommendation, gap.risk_reduction_pct)
        except Exception as e:
            logger.error(f"Permission analyzer error: {e}")
        await asyncio.sleep(24 * 3600)


if __name__ == "__main__":
    asyncio.run(run_permission_analyzer())
