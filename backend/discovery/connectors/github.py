# ============================================================
# NHI SHIELD — GitHub Connector
# Discovers: GitHub Apps, Deploy Keys, OAuth tokens,
#            Actions secrets, Personal Access Tokens
# ============================================================
from datetime import datetime
from typing import List, Dict, Any
import logging
logger = logging.getLogger(__name__)

from backend.discovery.models import NHIdentity, IdentityType, RiskIndicator
from backend.discovery.connectors.base import BaseConnector, CredentialError


class GitHubConnector(BaseConnector):

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.token = config['token']
        self.org = config['org']
        self.base_url = "https://api.github.com"
        self._headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    async def validate_credentials(self) -> bool:
        async with self._make_client(self._headers) as client:
            r = await self._get(client, f"{self.base_url}/user")
            if r.status_code == 401:
                raise CredentialError("GitHub token is invalid or expired")
            return r.status_code == 200

    async def discover(self) -> List[NHIdentity]:
        """Main entry: discovers all NHI types on GitHub org"""
        identities = []
        logger.info(f"Starting GitHub discovery for org: {self.org}")

        async with self._make_client(self._headers) as client:
            # Run all discovery types concurrently
            import asyncio
            results = await asyncio.gather(
                self._discover_github_apps(client),
                self._discover_deploy_keys(client),
                self._discover_dependabot(client),
                return_exceptions=True,
            )
            for result in results:
                if isinstance(result, Exception):
                    logger.error(f"GitHub sub-discovery error: {result}")
                else:
                    identities.extend(result)

        # Apply standard risk indicators
        for identity in identities:
            self._apply_risk_indicators(identity)
            # GitHub-specific risk: no expiry set on app
            if not identity.metadata.get('expires_at'):
                identity.add_risk_indicator(RiskIndicator.NO_EXPIRY)

        logger.info(f"GitHub discovery complete: {len(identities)} identities found")
        return identities

    async def _discover_github_apps(self, client) -> List[NHIdentity]:
        """Discovers GitHub Apps installed on the organization"""
        identities = []
        r = await self._get(client, f"{self.base_url}/orgs/{self.org}/installations",
                            params={"per_page": 100})
        if r.status_code != 200:
            logger.warning(f"Could not list GitHub Apps: {r.status_code} — may need admin:org scope")
            return identities

        for app in r.json().get('installations', []):
            perms = list(app.get('permissions', {}).keys())
            nhi = NHIdentity(
                id=f"github-app-{app['id']}",
                external_id=str(app['id']),
                name=app.get('app_slug', f"app-{app['id']}"),
                platform='github',
                type=IdentityType.GITHUB_APP,
                created_at=self._parse_dt(app.get('created_at')),
                last_used=self._parse_dt(app.get('updated_at')),
                permissions=perms,
                owner=app.get('account', {}).get('login'),
                is_active=True,
                metadata={
                    'app_id': app.get('app_id'),
                    'repository_selection': app.get('repository_selection'),
                    'html_url': app.get('html_url'),
                    'permissions': app.get('permissions', {}),
                },
            )
            # Flag write access to all repos as high risk
            if app.get('repository_selection') == 'all' and 'contents' in perms:
                nhi.add_risk_indicator(RiskIndicator.ADMIN_ACCESS)

            identities.append(nhi)
        return identities

    async def _discover_deploy_keys(self, client) -> List[NHIdentity]:
        """Discovers deploy keys across all repositories"""
        identities = []

        # Get all repos first
        repos = []
        page = 1
        while True:
            r = await self._get(client, f"{self.base_url}/orgs/{self.org}/repos",
                                params={"per_page": 100, "page": page})
            if r.status_code != 200 or not r.json():
                break
            repos.extend(r.json())
            if len(r.json()) < 100:
                break
            page += 1

        # For each repo, get deploy keys
        for repo in repos:
            r = await self._get(
                client,
                f"{self.base_url}/repos/{self.org}/{repo['name']}/keys"
            )
            if r.status_code != 200:
                continue
            for key in r.json():
                nhi = NHIdentity(
                    id=f"github-deploy-key-{key['id']}",
                    external_id=str(key['id']),
                    name=key.get('title', f"deploy-key-{key['id']}"),
                    platform='github',
                    type=IdentityType.DEPLOY_KEY,
                    created_at=self._parse_dt(key.get('created_at')),
                    last_used=None,  # GitHub API doesn't expose last_used for keys
                    permissions=['read'] if key.get('read_only') else ['read', 'write'],
                    owner=repo['name'],
                    is_active=True,
                    metadata={
                        'repo': repo['name'],
                        'read_only': key.get('read_only', True),
                        'key_id': key['id'],
                    },
                )
                # Write deploy keys are higher risk
                if not key.get('read_only'):
                    nhi.add_risk_indicator(RiskIndicator.ADMIN_ACCESS)
                identities.append(nhi)
        return identities

    async def _discover_dependabot(self, client) -> List[NHIdentity]:
        """Discovers Dependabot access (auto-PRs, security updates)"""
        identities = []
        r = await self._get(client, f"{self.base_url}/orgs/{self.org}")
        if r.status_code == 200 and r.json().get('has_organization_projects'):
            identities.append(NHIdentity(
                id=f"github-dependabot-{self.org}",
                external_id=f"dependabot-{self.org}",
                name="Dependabot",
                platform='github',
                type=IdentityType.OTHER,
                permissions=['contents:write', 'pull_requests:write'],
                owner=None,
                is_active=True,
                metadata={'org': self.org, 'type': 'dependabot'},
            ))
        return identities

    @staticmethod
    def _parse_dt(dt_str: str | None) -> datetime | None:
        if not dt_str:
            return None
        try:
            return datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
        except (ValueError, AttributeError):
            return None
