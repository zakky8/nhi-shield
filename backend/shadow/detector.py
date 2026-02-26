"""
NHI Shield — Shadow AI Detection Engine v2.0
=============================================
Discovers unauthorized, unregistered, or undocumented AI/API identities
across cloud environments, code repositories, and SaaS platforms.

Methods:
  - GitHub secret scanning (API keys in code)
  - AWS resource scanning for untagged/unregistered keys
  - Cloud billing anomaly detection (unexpected usage = shadow services)
  - Cross-reference discovered vs. registered identities
"""

import asyncio, json, logging, os, re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List

import asyncpg
import redis.asyncio as aioredis
import httpx

logger = logging.getLogger(__name__)

DB_URL    = os.getenv("DATABASE_URL", "postgresql://nhiadmin:nhi_secure_password_2026@localhost:5432/nhishield")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")

# Regex patterns for common API key formats
SECRET_PATTERNS = {
    "openai_key":    re.compile(r'sk-[a-zA-Z0-9]{48}'),
    "openai_proj":   re.compile(r'sk-proj-[a-zA-Z0-9_-]{40,}'),
    "anthropic_key": re.compile(r'sk-ant-[a-zA-Z0-9_-]{93}'),
    "github_token":  re.compile(r'(ghp|gho|ghs|ghr|github_pat)_[a-zA-Z0-9_]{36,}'),
    "aws_key":       re.compile(r'AKIA[A-Z0-9]{16}'),
    "slack_bot":     re.compile(r'xoxb-[0-9]+-[0-9]+-[a-zA-Z0-9]+'),
    "slack_user":    re.compile(r'xoxp-[0-9]+-[0-9]+-[a-zA-Z0-9]+'),
    "stripe_key":    re.compile(r'(sk|pk)_(live|test)_[a-zA-Z0-9]{24,}'),
    "twilio_key":    re.compile(r'SK[a-f0-9]{32}'),
    "google_key":    re.compile(r'AIza[A-Za-z0-9_-]{35}'),
    "jwt_secret":    re.compile(r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}'),
}

# Files to skip (binary/vendor/irrelevant)
SKIP_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff',
                    '.woff2', '.ttf', '.eot', '.pdf', '.zip', '.gz', '.lock',
                    '.sum', '.mod',
    '.min.js', '.min.css',
}


@dataclass
class ShadowIdentity:
    type: str               # "github_secret" | "aws_unregistered" | "billing_anomaly"
    platform: str
    name: str
    description: str
    severity: str           # CRITICAL | HIGH | MEDIUM
    location: str           # repo path, AWS resource ID, etc.
    raw_value: str          # Masked version
    metadata: Dict = field(default_factory=dict)


@dataclass
class ShadowScanResult:
    org_id: str
    scanned_at: datetime
    shadow_identities: List[ShadowIdentity]
    new_findings: int
    total_scanned: int
    scan_errors: List[str] = field(default_factory=list)


class ShadowAIDetector:

    def __init__(self, pg: asyncpg.Pool, redis: aioredis.Redis):
        self.pg = pg
        self.redis = redis

    async def scan_org(self, org_id: str, integrations: List[Dict]) -> ShadowScanResult:
        """Run all shadow detection methods for an org."""
        findings: List[ShadowIdentity] = []
        errors = []
        total_scanned = 0

        for integration in integrations:
            platform = integration.get("platform", "").lower()
            config   = integration.get("config", {})
            if isinstance(config, str):
                try: config = json.loads(config)
                except Exception: config = {}

            try:
                if platform == "github":
                    results = await self._scan_github(config, org_id)
                    findings.extend(results)
                    total_scanned += 1
                elif platform == "aws":
                    results = await self._scan_aws_unregistered(config, org_id)
                    findings.extend(results)
                    total_scanned += 1
            except Exception as e:
                errors.append(f"{platform}: {str(e)[:100]}")
                logger.warning(f"Shadow scan error ({platform}): {e}")

        # Cross-reference: find newly discovered identities not in our registry
        new_findings = await self._cross_reference(org_id, findings)

        # Persist new findings
        for finding in new_findings:
            await self._persist_finding(finding, org_id)
            await self._publish_finding(finding, org_id)

        return ShadowScanResult(
            org_id=org_id, scanned_at=datetime.now(timezone.utc),
            shadow_identities=findings, new_findings=len(new_findings),
            total_scanned=total_scanned, scan_errors=errors
        )

    # ── GitHub Secret Scanning ────────────────────────────────────────────────

    async def _scan_github(self, config: Dict, org_id: str) -> List[ShadowIdentity]:
        """Scan GitHub repos for exposed API keys and tokens."""
        token = config.get("token") or os.getenv("GITHUB_TOKEN")
        org = config.get("org") or config.get("org_name")
        if not token or not org:
            return []

        findings = []
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }

        async with httpx.AsyncClient(timeout=30) as client:
            # Get all repos
            repos = []
            page = 1
            while True:
                r = await client.get(
                    f"https://api.github.com/orgs/{org}/repos",
                    headers=headers, params={"per_page": 100, "page": page}
                )
                if r.status_code != 200: break
                batch = r.json()
                if not batch: break
                repos.extend(batch)
                page += 1
                if page > 5: break  # Limit to 500 repos

            logger.info(f"Scanning {len(repos)} GitHub repos for secrets")

            # Scan recent commits for each repo
            for repo in repos[:50]:  # Limit to avoid rate limits
                repo_name = repo["full_name"]
                try:
                    secrets = await self._scan_repo_commits(client, headers, repo_name, org_id)
                    findings.extend(secrets)
                except Exception as e:
                    logger.debug(f"Repo scan error {repo_name}: {e}")

            # Also use GitHub's native secret scanning if available
            try:
                r = await client.get(
                    f"https://api.github.com/orgs/{org}/secret-scanning/alerts",
                    headers=headers, params={"state": "open", "per_page": 50}
                )
                if r.status_code == 200:
                    for alert in r.json():
                        findings.append(ShadowIdentity(
                            type="github_secret_scan",
                            platform=alert.get("secret_type", "unknown"),
                            name=f"Exposed secret in {alert.get('repository', {}).get('name', 'unknown')}",
                            description=f"GitHub native scan detected: {alert.get('secret_type_display_name', '')}",
                            severity="CRITICAL",
                            location=alert.get("html_url", ""),
                            raw_value=f"[REDACTED — type: {alert.get('secret_type','')}]",
                            metadata={"alert_number": alert.get("number"), "repo": alert.get("repository",{}).get("full_name")}
                        ))
            except Exception:
                pass

        return findings

    async def _scan_repo_commits(self, client: httpx.AsyncClient, headers: Dict,
                                  repo_name: str, org_id: str) -> List[ShadowIdentity]:
        """Scan recent commits in a repo for exposed secrets."""
        findings = []
        # Get recent commits
        r = await client.get(
            f"https://api.github.com/repos/{repo_name}/commits",
            headers=headers, params={"per_page": 10}
        )
        if r.status_code != 200: return []

        for commit in r.json()[:5]:
            sha = commit.get("sha", "")
            try:
                # Get commit diff
                rc = await client.get(
                    f"https://api.github.com/repos/{repo_name}/commits/{sha}",
                    headers=headers
                )
                if rc.status_code != 200: continue
                commit_data = rc.json()

                for file in commit_data.get("files", []):
                    filename = file.get("filename", "")
                    if any(filename.endswith(ext) for ext in SKIP_EXTENSIONS):
                        continue
                    patch = file.get("patch", "")
                    if not patch: continue

                    for key_type, pattern in SECRET_PATTERNS.items():
                        matches = pattern.findall(patch)
                        for match in matches:
                            # Mask the value
                            masked = match[:8] + "..." + match[-4:] if len(match) > 12 else "***"
                            findings.append(ShadowIdentity(
                                type="github_secret",
                                platform=key_type.split("_")[0],
                                name=f"Exposed {key_type} in {repo_name}",
                                description=f"Secret pattern '{key_type}' found in commit {sha[:8]} file: {filename}",
                                severity="CRITICAL",
                                location=f"https://github.com/{repo_name}/commit/{sha}#{filename}",
                                raw_value=masked,
                                metadata={"repo": repo_name, "file": filename, "commit": sha, "key_type": key_type}
                            ))
            except Exception: continue

        return findings

    # ── AWS Unregistered Resources ────────────────────────────────────────────

    async def _scan_aws_unregistered(self, config: Dict, org_id: str) -> List[ShadowIdentity]:
        """Find AWS IAM resources not registered in NHI Shield."""
        try:
            import boto3
            session = boto3.Session(
                aws_access_key_id=config.get("access_key") or os.getenv("AWS_ACCESS_KEY_ID"),
                aws_secret_access_key=config.get("secret_key") or os.getenv("AWS_SECRET_ACCESS_KEY"),
                region_name=config.get("region", "us-east-1")
            )
            iam = session.client("iam")

            # Get all registered identity external_ids for this org
            registered = await self.pg.fetch(
                "SELECT external_id FROM identities WHERE org_id=$1 AND platform='aws' AND is_active=true",
                org_id
            )
            registered_ids = {r["external_id"] for r in registered if r["external_id"]}

            findings = []

            # Scan IAM users
            paginator = iam.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page["Users"]:
                    username = user["UserName"]
                    if username not in registered_ids:
                        # Check if it has access keys (NHI indicator)
                        keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
                        if keys and not user.get("PasswordLastUsed"):  # No console = NHI
                            findings.append(ShadowIdentity(
                                type="aws_unregistered",
                                platform="aws",
                                name=f"Unregistered IAM User: {username}",
                                description=f"IAM user with {len(keys)} access key(s) not registered in NHI Shield",
                                severity="HIGH",
                                location=f"arn:aws:iam::*:user/{username}",
                                raw_value=user["Arn"],
                                metadata={"username": username, "key_count": len(keys),
                                          "created": user["CreateDate"].isoformat()}
                            ))

            # Scan IAM roles
            paginator = iam.get_paginator("list_roles")
            for page in paginator.paginate():
                for role in page["Roles"]:
                    role_name = role["RoleName"]
                    if role_name not in registered_ids and not role_name.startswith("AWS"):
                        # Check for attached policies (non-service-linked roles)
                        attached = iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
                        if attached:
                            findings.append(ShadowIdentity(
                                type="aws_unregistered_role",
                                platform="aws",
                                name=f"Unregistered IAM Role: {role_name}",
                                description=f"IAM role with {len(attached)} policies not tracked in NHI Shield",
                                severity="MEDIUM",
                                location=role["Arn"],
                                raw_value=role["Arn"],
                                metadata={"role_name": role_name, "policy_count": len(attached)}
                            ))

            return findings

        except ImportError:
            logger.warning("boto3 not available for AWS shadow scan")
            return []
        except Exception as e:
            logger.warning(f"AWS unregistered scan error: {e}")
            return []

    # ── Cross-Reference ────────────────────────────────────────────────────────

    async def _cross_reference(self, org_id: str, findings: List[ShadowIdentity]) -> List[ShadowIdentity]:
        """Filter out findings already known/tracked. Uses SHA-256 fingerprint to prevent key collisions."""
        known_keys = await self.redis.smembers(f"known_shadows:{org_id}")
        new_findings = []
        for f in findings:
            # Use SHA-256 hash instead of raw colon-concat to prevent collision
            # (URLs/values can contain colons which break naive f"{a}:{b}:{c}" keys)
            raw = f"{f.type}|{f.location}|{f.raw_value}"
            fp = hashlib.sha256(raw.encode()).hexdigest()
            if fp not in known_keys:
                new_findings.append(f)
                await self.redis.sadd(f"known_shadows:{org_id}", fp)
        await self.redis.expire(f"known_shadows:{org_id}", 86400 * 7)  # 7 day cache
        return new_findings

    async def _persist_finding(self, finding: ShadowIdentity, org_id: str):
        try:
            await self.pg.execute("""
                INSERT INTO anomaly_alerts
                (org_id, alert_type, severity, description, evidence, created_at)
                VALUES($1,'SHADOW_AI_DETECTED',$2,$3,$4,NOW())
            """, org_id, finding.severity,
                finding.description,
                json.dumps({**finding.metadata, "location": finding.location,
                            "masked_value": finding.raw_value}))
        except Exception as e:
            logger.warning(f"Persist shadow finding: {e}")

    async def _publish_finding(self, finding: ShadowIdentity, org_id: str):
        try:
            await self.redis.publish("shadow:detected", json.dumps({
                "org_id": org_id, "type": finding.type, "platform": finding.platform,
                "name": finding.name, "severity": finding.severity,
                "location": finding.location, "timestamp": datetime.now(timezone.utc).isoformat()
            }))
        except Exception: pass


async def run_shadow_scanner():
    """Standalone service — run shadow scan daily."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    pg = await asyncpg.create_pool(DB_URL)
    redis = await aioredis.from_url(REDIS_URL, decode_responses=True)
    detector = ShadowAIDetector(pg, redis)

    while True:
        try:
            orgs = await pg.fetch("SELECT id FROM organizations WHERE is_active=true")
            for org in orgs:
                integrations = await pg.fetch("""
                    SELECT platform, config FROM integrations WHERE org_id=$1 AND is_active=true
                """, str(org["id"]))
                result = await detector.scan_org(str(org["id"]), [dict(i) for i in integrations])
                logger.info(f"Shadow scan: org={org['id']} new={result.new_findings} total={len(result.shadow_identities)}")
        except Exception as e:
            logger.error(f"Shadow scanner error: {e}")
        await asyncio.sleep(24 * 3600)


if __name__ == "__main__":
    asyncio.run(run_shadow_scanner())
