# ============================================================
# NHI SHIELD — OpenAI Connector
# ============================================================
from datetime import datetime
from typing import List, Dict, Any
import logging
logger = logging.getLogger(__name__)

from backend.discovery.models import NHIdentity, IdentityType, RiskIndicator
from backend.discovery.connectors.base import BaseConnector, CredentialError


class OpenAIConnector(BaseConnector):

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.admin_key = config['admin_key']
        self._headers = {
            "Authorization": f"Bearer {self.admin_key}",
            "Content-Type": "application/json",
        }

    async def validate_credentials(self) -> bool:
        async with self._make_client(self._headers) as client:
            r = await self._get(client, "https://api.openai.com/v1/models")
            if r.status_code == 401:
                raise CredentialError("OpenAI API key is invalid")
            return r.status_code == 200

    async def discover(self) -> List[NHIdentity]:
        identities = []
        logger.info("Starting OpenAI API key discovery")

        async with self._make_client(self._headers) as client:
            r = await self._get(client, "https://api.openai.com/v1/organization/api_keys",
                                params={"limit": 100})
            if r.status_code == 200:
                for key in r.json().get('data', []):
                    last_used_ts = key.get('last_used_at')
                    nhi = NHIdentity(
                        id=f"openai-key-{key['id']}",
                        external_id=key['id'],
                        name=key.get('name', f"key-{key['id'][:8]}"),
                        platform='openai',
                        type=IdentityType.API_KEY,
                        created_at=datetime.fromtimestamp(key['created_at']) if key.get('created_at') else None,
                        last_used=datetime.fromtimestamp(last_used_ts) if last_used_ts else None,
                        permissions=['api_access'],
                        owner=key.get('created_by', {}).get('name'),
                        is_active=key.get('status') == 'active',
                        metadata={
                            'key_id': key['id'],
                            'has_expiry': bool(key.get('expires_at')),
                            'expires_at': key.get('expires_at'),
                        },
                    )
                    if not key.get('expires_at'):
                        nhi.add_risk_indicator(RiskIndicator.NO_EXPIRY)
                    self._apply_risk_indicators(nhi)
                    identities.append(nhi)
            else:
                logger.warning(f"OpenAI API returned {r.status_code} — may need admin API access")

        logger.info(f"OpenAI discovery complete: {len(identities)} keys found")
        return identities


# ============================================================
# NHI SHIELD — Slack Connector
# ============================================================
class SlackConnector(BaseConnector):

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.token = config['token']
        self._headers = {"Authorization": f"Bearer {self.token}"}

    async def validate_credentials(self) -> bool:
        async with self._make_client(self._headers) as client:
            r = await self._get(client, "https://slack.com/api/auth.test")
            data = r.json()
            if not data.get('ok'):
                raise CredentialError(f"Slack token invalid: {data.get('error')}")
            return True

    async def discover(self) -> List[NHIdentity]:
        identities = []
        logger.info("Starting Slack app discovery")

        async with self._make_client(self._headers) as client:
            r = await self._get(client, "https://slack.com/api/apps.list",
                                params={"limit": 200})
            data = r.json()
            if not data.get('ok'):
                logger.warning(f"Could not list Slack apps: {data.get('error')}")
                return identities

            for app in data.get('apps', []):
                scopes = app.get('scopes', [])
                nhi = NHIdentity(
                    id=f"slack-app-{app['id']}",
                    external_id=app['id'],
                    name=app.get('name', f"app-{app['id']}"),
                    platform='slack',
                    type=IdentityType.SLACK_APP,
                    created_at=datetime.fromtimestamp(app['date_added']) if app.get('date_added') else None,
                    last_used=None,
                    permissions=scopes,
                    owner=app.get('installed_by', {}).get('name'),
                    is_active=True,
                    metadata={
                        'app_id': app['id'],
                        'workspace_id': app.get('workspace_id'),
                        'scopes': scopes,
                    },
                )
                # Flag admin scopes as critical
                admin_scopes = {'admin', 'admin:users', 'admin:channels', 'admin:conversations'}
                if admin_scopes.intersection(set(scopes)):
                    nhi.add_risk_indicator(RiskIndicator.ADMIN_ACCESS)

                self._apply_risk_indicators(nhi)
                identities.append(nhi)

        logger.info(f"Slack discovery complete: {len(identities)} apps found")
        return identities
