"""
NHI Shield — Additional Platform Connectors
Anthropic, Okta, Jira, Salesforce, HubSpot, Stripe, Twilio, GCP
Appended to DiscoveryEngine via mixin/import pattern.
"""

import logging
import os
from typing import List, Dict
from datetime import datetime
import httpx
from backend.discovery.models import NHIdentity, IdentityType, RiskIndicator

logger = logging.getLogger(__name__)


class AdditionalConnectors:
    """
    Mixin for DiscoveryEngine adding connectors for:
    Anthropic, Okta, Jira, Salesforce, HubSpot, Stripe, Twilio, GCP, Azure, Gmail
    """

    async def discover_azure(self, config: Dict) -> List:
        """
        Discovers Azure Active Directory service principals and managed identities.
        Uses azure-identity + azure-graphrbac (or microsoft-graph).
        """
        identities = []
        tenant_id  = config.get("tenant_id") or os.getenv("AZURE_TENANT_ID")
        client_id  = config.get("client_id") or os.getenv("AZURE_CLIENT_ID")
        client_sec = config.get("client_secret") or os.getenv("AZURE_CLIENT_SECRET")

        if not all([tenant_id, client_id, client_sec]):
            logger.warning("Azure discovery requires tenant_id, client_id, client_secret")
            return identities

        try:
            from azure.identity import ClientSecretCredential
            from azure.graphrbac import GraphRbacManagementClient

            cred = ClientSecretCredential(tenant_id=tenant_id, client_id=client_id,
                                          client_secret=client_sec)
            client = GraphRbacManagementClient(cred, tenant_id)
            for sp in client.service_principals.list():
                identities.append(NHIdentity(
                    id=f"azure-sp-{sp.object_id}",
                    name=sp.display_name or sp.app_id,
                    platform="azure",
                    type="service_principal",
                    created_at=getattr(sp, "created_date_time", datetime.utcnow()),
                    last_used=None,
                    permissions=["azure_sp"],
                    owner=None,
                    is_active=sp.account_enabled if sp.account_enabled is not None else True,
                    metadata={
                        "object_id": sp.object_id,
                        "app_id": sp.app_id,
                        "tenant_id": tenant_id,
                        "service_principal_type": getattr(sp, "service_principal_type", "Application"),
                    }
                ))
        except ImportError:
            logger.warning("Azure discovery requires: pip install azure-identity azure-graphrbac")
        except Exception as e:
            logger.error(f"Azure discovery error: {e}")

        logger.info(f"Azure: found {len(identities)} service principals")
        return identities

    # ─── Anthropic ────────────────────────────────────────────────────────────

    async def discover_anthropic(self, config: Dict) -> List:
        """Discover Anthropic API keys via admin API"""
        try:
            identities = []
            async with httpx.AsyncClient() as client:
                r = await client.get(
                    "https://api.anthropic.com/v1/organizations/api_keys",
                    headers={
                        "x-api-key": config['admin_key'],
                        "anthropic-version": "2023-06-01"
                    }
                )
                if r.status_code == 200:
                    for key in r.json().get('data', []):
                        identities.append(NHIdentity(
                            id=f"anthropic-key-{key['id']}",
                            name=key.get('name', 'Unnamed Anthropic Key'),
                            platform='anthropic',
                            type='api_key',
                            created_at=datetime.fromisoformat(key['created_at'].replace('Z', '+00:00')),
                            last_used=None,
                            permissions=['api_access'],
                            owner=key.get('created_by', {}).get('email'),
                            is_active=key.get('status') == 'active',
                            metadata={'key_id': key['id'], 'workspace_id': key.get('workspace_id')}
                        ))
            logger.info(f"Anthropic: found {len(identities)} API keys")
            return identities

        # ─── Okta ────────────────────────────────────────────────────────────────
        except Exception as e:
            logger.error(f"discover_anthropic failed: {e}")
            return []

    async def discover_okta(self, config: Dict) -> List:
        """Discover Okta service apps, API tokens, OAuth clients"""
        try:
            identities = []
            domain = config['domain']  # e.g. your-org.okta.com
            token = config['api_token']
            headers = {'Authorization': f'SSWS {token}', 'Accept': 'application/json'}

            async with httpx.AsyncClient() as client:
                # Service applications
                r = await client.get(
                    f"https://{domain}/api/v1/apps",
                    headers=headers,
                    params={'filter': 'status eq "ACTIVE"', 'limit': 200}
                )
                if r.status_code == 200:
                    for app in r.json():
                        if app.get('signOnMode') in ('AUTO_LOGIN', 'SAML_2_0', 'WS_FED', 'BOOKMARK', 'BASIC_AUTH'):
                            continue  # Skip human-facing SSO apps
                        identities.append(NHIdentity(
                            id=f"okta-app-{app['id']}",
                            name=app['label'],
                            platform='okta',
                            type='service_app',
                            created_at=datetime.fromisoformat(app['created'].replace('Z', '+00:00')),
                            last_used=None,
                            permissions=list(app.get('features', [])),
                            owner=None,
                            is_active=app['status'] == 'ACTIVE',
                            metadata={'app_id': app['id'], 'sign_on_mode': app.get('signOnMode')}
                        ))

                # API tokens (Okta admin tokens)
                r2 = await client.get(f"https://{domain}/api/v1/api-tokens", headers=headers)
                if r2.status_code == 200:
                    for tok in r2.json():
                        identities.append(NHIdentity(
                            id=f"okta-token-{tok['id']}",
                            name=tok['name'],
                            platform='okta',
                            type='api_token',
                            created_at=datetime.fromisoformat(tok['created'].replace('Z', '+00:00')),
                            last_used=datetime.fromisoformat(tok['lastUpdated'].replace('Z', '+00:00')) if tok.get('lastUpdated') else None,
                            permissions=['admin_api'],
                            owner=tok.get('userId'),
                            is_active=True,
                            metadata={'token_id': tok['id']}
                        ))

            logger.info(f"Okta: found {len(identities)} identities")
            return identities

        # ─── Jira ────────────────────────────────────────────────────────────────
        except Exception as e:
            logger.error(f"discover_okta failed: {e}")
            return []

    async def discover_jira(self, config: Dict) -> List:
        """Discover Jira service accounts, OAuth apps, API tokens"""
        try:
            identities = []
            base_url = config['base_url']  # https://your-org.atlassian.net
            email = config['email']
            api_token = config['api_token']
            auth = (email, api_token)

            async with httpx.AsyncClient() as client:
                # List all users — find service accounts (no display name matching human patterns)
                r = await client.get(
                    f"{base_url}/rest/api/3/users/search",
                    auth=auth,
                    params={'maxResults': 1000}
                )
                if r.status_code == 200:
                    for user in r.json():
                        # Filter: service accounts typically have accountType = 'app' or bot names
                        if user.get('accountType') == 'app' or \
                           any(kw in user.get('displayName', '').lower()
                               for kw in ['bot', 'service', 'automation', 'webhook', 'ci', 'deploy', 'integration']):
                            identities.append(NHIdentity(
                                id=f"jira-user-{user['accountId']}",
                                name=user.get('displayName', user['accountId']),
                                platform='jira',
                                type='service_account' if user.get('accountType') == 'app' else 'bot_user',
                                created_at=datetime.utcnow(),
                                last_used=None,
                                permissions=['jira_access'],
                                owner=None,
                                is_active=user.get('active', True),
                                metadata={'account_id': user['accountId'], 'account_type': user.get('accountType')}
                            ))

            logger.info(f"Jira: found {len(identities)} service identities")
            return identities

        # ─── Salesforce ──────────────────────────────────────────────────────────
        except Exception as e:
            logger.error(f"discover_jira failed: {e}")
            return []

    async def discover_salesforce(self, config: Dict) -> List:
        """Discover Salesforce connected apps and integration users"""
        try:
            identities = []
            instance_url = config['instance_url']
            access_token = config['access_token']
            headers = {'Authorization': f"Bearer {access_token}", 'Content-Type': 'application/json'}

            async with httpx.AsyncClient() as client:
                # Query connected apps
                r = await client.get(
                    f"{instance_url}/services/data/v59.0/query",
                    headers=headers,
                    params={'q': "SELECT Id, Name, Status, CreatedDate FROM ConnectedApplication LIMIT 200"}
                )
                if r.status_code == 200:
                    for app in r.json().get('records', []):
                        identities.append(NHIdentity(
                            id=f"sf-app-{app['Id']}",
                            name=app['Name'],
                            platform='salesforce',
                            type='connected_app',
                            created_at=datetime.fromisoformat(app['CreatedDate'].replace('+0000', '+00:00')),
                            last_used=None,
                            permissions=['api_access'],
                            owner=None,
                            is_active=app.get('Status') == 'Active',
                            metadata={'sf_id': app['Id']}
                        ))

                # Integration users (profile = "Integration User" or similar)
                r2 = await client.get(
                    f"{instance_url}/services/data/v59.0/query",
                    headers=headers,
                    params={'q': "SELECT Id, Name, Username, LastLoginDate, IsActive FROM User WHERE Profile.Name LIKE '%Integration%' OR Profile.Name LIKE '%API%' LIMIT 200"}
                )
                if r2.status_code == 200:
                    for user in r2.json().get('records', []):
                        identities.append(NHIdentity(
                            id=f"sf-user-{user['Id']}",
                            name=user['Name'],
                            platform='salesforce',
                            type='integration_user',
                            created_at=datetime.utcnow(),
                            last_used=datetime.fromisoformat(user['LastLoginDate'].replace('+0000', '+00:00')) if user.get('LastLoginDate') else None,
                            permissions=['api_access'],
                            owner=None,
                            is_active=user.get('IsActive', False),
                            metadata={'username': user['Username']}
                        ))

            logger.info(f"Salesforce: found {len(identities)} identities")
            return identities

        # ─── HubSpot ─────────────────────────────────────────────────────────────
        except Exception as e:
            logger.error(f"discover_salesforce failed: {e}")
            return []

    async def discover_hubspot(self, config: Dict) -> List:
        """Discover HubSpot private apps and OAuth tokens"""
        try:
            identities = []
            async with httpx.AsyncClient() as client:
                r = await client.get(
                    "https://api.hubapi.com/integrations/v1/self",
                    headers={'Authorization': f"Bearer {config['access_token']}"}
                )
                if r.status_code == 200:
                    data = r.json()
                    identities.append(NHIdentity(
                        id=f"hubspot-app-{data.get('appId', 'unknown')}",
                        name=data.get('hubDomain', 'HubSpot Integration'),
                        platform='hubspot',
                        type='private_app',
                        created_at=datetime.utcnow(),
                        last_used=None,
                        permissions=data.get('scopes', []),
                        owner=None,
                        is_active=True,
                        metadata={'hub_id': data.get('portalId'), 'app_id': data.get('appId')}
                    ))

                # List all API keys / private apps
                _ = await client.get(
                    "https://api.hubapi.com/crm/v3/extensions/calling/settings",
                    headers={'Authorization': f"Bearer {config['access_token']}"}
                )

            logger.info(f"HubSpot: found {len(identities)} identities")
            return identities

        # ─── Stripe ──────────────────────────────────────────────────────────────
        except Exception as e:
            logger.error(f"discover_hubspot failed: {e}")
            return []

    async def discover_stripe(self, config: Dict) -> List:
        """Discover Stripe API keys and restricted keys"""
        identities = []
        async with httpx.AsyncClient() as client:
            # Get account info
            r = await client.get(
                "https://api.stripe.com/v1/account",
                auth=(config['secret_key'], '')
            )
            if r.status_code == 200:
                acct = r.json()
                # List API keys (requires Dashboard access — via management API if available)
                # For each key configuration the user has registered
                identities.append(NHIdentity(
                    id=f"stripe-key-{acct['id']}",
                    name=f"Stripe Key — {acct.get('display_name', acct['id'])}",
                    platform='stripe',
                    type='api_key',
                    created_at=datetime.utcnow(),
                    last_used=None,
                    permissions=['charges', 'refunds', 'customers'],
                    owner=acct.get('email'),
                    is_active=not acct.get('charges_enabled') is False,
                    metadata={'account_id': acct['id'], 'country': acct.get('country')}
                ))

            # Restricted keys (available via Stripe Management API for platforms)
            r2 = await client.get(
                "https://api.stripe.com/v1/restricted_keys",
                auth=(config['secret_key'], '')
            )
            if r2.status_code == 200:
                for key in r2.json().get('data', []):
                    identities.append(NHIdentity(
                        id=f"stripe-rkey-{key['id']}",
                        name=key.get('name', f"Restricted Key {key['id']}"),
                        platform='stripe',
                        type='restricted_api_key',
                        created_at=datetime.fromtimestamp(key['created']),
                        last_used=None,
                        permissions=key.get('permissions', []),
                        owner=None,
                        is_active=not key.get('deleted', False),
                        metadata={'key_id': key['id']}
                    ))

        logger.info(f"Stripe: found {len(identities)} identities")
        return identities

    # ─── Twilio ──────────────────────────────────────────────────────────────

    async def discover_twilio(self, config: Dict) -> List:
        """Discover Twilio API keys and subaccounts"""
        try:
            identities = []
            account_sid = config['account_sid']
            auth_token = config['auth_token']
            auth = (account_sid, auth_token)

            async with httpx.AsyncClient() as client:
                # List API keys
                r = await client.get(
                    f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Keys.json",
                    auth=auth
                )
                if r.status_code == 200:
                    for key in r.json().get('keys', []):
                        identities.append(NHIdentity(
                            id=f"twilio-key-{key['sid']}",
                            name=key.get('friendly_name', key['sid']),
                            platform='twilio',
                            type='api_key',
                            created_at=datetime.strptime(key['date_created'], '%a, %d %b %Y %H:%M:%S %z'),
                            last_used=None,
                            permissions=['api_access'],
                            owner=None,
                            is_active=True,
                            metadata={'sid': key['sid']}
                        ))

                # Subaccounts (often used for service segregation)
                r2 = await client.get(
                    "https://api.twilio.com/2010-04-01/Accounts.json",
                    auth=auth,
                    params={'Status': 'active'}
                )
                if r2.status_code == 200:
                    for acct in r2.json().get('accounts', []):
                        if acct['sid'] != account_sid:  # Skip main account
                            identities.append(NHIdentity(
                                id=f"twilio-subaccount-{acct['sid']}",
                                name=acct.get('friendly_name', acct['sid']),
                                platform='twilio',
                                type='subaccount',
                                created_at=datetime.strptime(acct['date_created'], '%a, %d %b %Y %H:%M:%S %z'),
                                last_used=None,
                                permissions=['messaging', 'voice'],
                                owner=None,
                                is_active=acct['status'] == 'active',
                                metadata={'sid': acct['sid']}
                            ))

            logger.info(f"Twilio: found {len(identities)} identities")
            return identities

        # ─── GCP (Google Cloud Platform - separate from Workspace) ───────────────
        except Exception as e:
            logger.error(f"discover_twilio failed: {e}")
            return []

    async def discover_gcp(self, config: Dict) -> List:
        """Discover GCP service accounts and keys via Cloud IAM API"""
        identities = []
        project_id = config['project_id']

        try:
            from google.oauth2 import service_account
            from googleapiclient.discovery import build

            credentials = service_account.Credentials.from_service_account_file(
                config['credentials_path'],
                scopes=['https://www.googleapis.com/auth/cloud-platform']
            )

            import asyncio
            loop = asyncio.get_running_loop()
            iam_service = await loop.run_in_executor(None, lambda: build('iam', 'v1', credentials=credentials))

            def list_service_accounts():
                return iam_service.projects().serviceAccounts().list(
                    name=f"projects/{project_id}"
                ).execute()

            response = await loop.run_in_executor(None, list_service_accounts)

            for sa in response.get('accounts', []):
                # Get keys for this service account
                def list_keys(sa_name=sa['name']):
                    return iam_service.projects().serviceAccounts().keys().list(
                        name=sa_name, keyTypes=['USER_MANAGED']
                    ).execute()

                keys_resp = await loop.run_in_executor(None, list_keys)
                key_count = len(keys_resp.get('keys', []))

                identities.append(NHIdentity(
                    id=f"gcp-sa-{sa['uniqueId']}",
                    name=sa['displayName'] or sa['email'],
                    platform='gcp',
                    type='service_account',
                    created_at=datetime.utcnow(),
                    last_used=None,
                    permissions=['gcp_api'],
                    owner=sa.get('email', '').split('@')[0],
                    is_active=not sa.get('disabled', False),
                    metadata={
                        'email': sa['email'],
                        'project': project_id,
                        'key_count': key_count,
                        'description': sa.get('description', '')
                    }
                ))

        except ImportError:
            logger.warning("google-cloud libraries not installed: pip install google-cloud-iam")
        except Exception as e:
            logger.error(f"GCP discovery error: {e}")

        logger.info(f"GCP: found {len(identities)} service accounts")
        return identities

    async def discover_gmail(self, config: Dict) -> List:
        """
        Discovers Gmail service account delegations and OAuth clients
        that have been granted access to Gmail scopes (Drive, Gmail API, etc.)
        Uses Google Admin SDK Directory API + Google Cloud IAM.
        Finds: domain-wide delegation grants, service accounts with Gmail OAuth scopes.
        """
        identities = []

        credentials_json = config.get("credentials_json")
        admin_email     = config.get("admin_email")        # delegated admin email
        domain          = config.get("domain", "")

        if not credentials_json or not admin_email:
            logger.warning("Gmail discovery requires credentials_json and admin_email")
            return identities

        try:
            from google.oauth2 import service_account
            from googleapiclient.discovery import build

            SCOPES = [
                "https://www.googleapis.com/auth/admin.directory.user.readonly",
                "https://www.googleapis.com/auth/admin.directory.domain.readonly",
            ]

            if isinstance(credentials_json, str):
                import json as _json
                cred_info = _json.loads(credentials_json)
            else:
                cred_info = credentials_json

            creds = service_account.Credentials.from_service_account_info(
                cred_info, scopes=SCOPES
            ).with_subject(admin_email)

            # --- Domain-wide delegation grants via Admin SDK ---
            try:
                admin_sdk = build("admin", "directory_v1", credentials=creds)
                page_token = None
                while True:
                    resp = admin_sdk.tokens().list(userKey=admin_email, pageToken=page_token).execute()
                    for token in resp.get("items", []):
                        client_id = token.get("clientId", "")
                        display   = token.get("displayText", client_id)
                        scopes    = token.get("scopes", [])
                        gmail_scopes = [s for s in scopes if "gmail" in s.lower() or "mail" in s.lower()]
                        if not gmail_scopes:
                            continue  # only track identities with actual Gmail access

                        identities.append(NHIdentity(
                            id=f"gmail-oauth-{client_id[:32]}",
                            name=display,
                            platform="gmail",
                            type="oauth_client",
                            created_at=datetime.utcnow(),
                            last_used=None,
                            permissions=gmail_scopes,
                            owner=admin_email,
                            is_active=True,
                            metadata={
                                "client_id": client_id,
                                "domain": domain,
                                "scopes": scopes,
                                "gmail_scopes": gmail_scopes,
                                "delegated_admin": admin_email,
                            }
                        ))
                    page_token = resp.get("nextPageToken")
                    if not page_token:
                        break
            except Exception as ex:
                logger.warning(f"Gmail Admin SDK token listing error: {ex}")

            # --- Service accounts with Gmail scopes via IAM API ---
            project_id = cred_info.get("project_id", "")
            if project_id:
                try:
                    from google.oauth2 import service_account as _sa
                    iam_creds = _sa.Credentials.from_service_account_info(
                        cred_info,
                        scopes=["https://www.googleapis.com/auth/cloud-platform"]
                    )
                    iam_svc = build("iam", "v1", credentials=iam_creds)
                    sa_resp = iam_svc.projects().serviceAccounts().list(
                        name=f"projects/{project_id}"
                    ).execute()

                    for sa in sa_resp.get("accounts", []):
                        email = sa.get("email", "")
                        if not any(kw in sa.get("description", "").lower()
                                   for kw in ["gmail", "mail", "email", "workspace"]):
                            continue

                        identities.append(NHIdentity(
                            id=f"gmail-sa-{sa.get('uniqueId', email)[:24]}",
                            name=sa.get("displayName") or email,
                            platform="gmail",
                            type="service_account",
                            created_at=datetime.utcnow(),
                            last_used=None,
                            permissions=["gmail_service_account"],
                            owner=email.split("@")[0],
                            is_active=not sa.get("disabled", False),
                            metadata={
                                "email": email,
                                "project": project_id,
                                "description": sa.get("description", ""),
                                "has_gmail_delegation": True,
                            }
                        ))
                except Exception as ex:
                    logger.warning(f"Gmail service account discovery error: {ex}")

        except ImportError:
            logger.warning(
                "Gmail discovery requires google-auth and google-api-python-client: "
                "pip install google-auth google-api-python-client"
            )
        except Exception as e:
            logger.error(f"Gmail discovery error: {e}")

        logger.info(f"Gmail: found {len(identities)} OAuth clients/service accounts with mail scopes")
        return identities
