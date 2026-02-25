"""
NHI Shield - Discovery Engine
Discovers Non-Human Identities across all connected platforms
"""

import asyncio
import logging
import os
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import json

import httpx
from neo4j import AsyncGraphDatabase
import asyncpg
try:
    import boto3
    from botocore.exceptions import ClientError
    _BOTO3_AVAILABLE = True
except ImportError:
    boto3 = None
    ClientError = Exception
    _BOTO3_AVAILABLE = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Import additional connectors mixin
try:
    import sys as _sys, os as _os
    _sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
    from integrations.additional_connectors import AdditionalConnectors as _AddConn
    _HAS_EXTRA = True
except ImportError:
    class _AddConn:
        pass
    _HAS_EXTRA = False


class IdentityType(str, Enum):
    API_KEY = "api_key"
    SERVICE_ACCOUNT = "service_account"
    IAM_ROLE = "iam_role"
    OAUTH_TOKEN = "oauth_token"
    BOT_TOKEN = "bot_token"
    GITHUB_APP = "github_app"
    DEPLOY_KEY = "deploy_key"
    SLACK_APP = "slack_app"
    AZURE_SP = "azure_service_principal"
    GCP_SA = "gcp_service_account"


@dataclass
class NHIdentity:
    """Represents a discovered Non-Human Identity"""
    id: str
    name: str
    platform: str
    type: IdentityType
    created_at: Optional[datetime]
    last_used: Optional[datetime]
    permissions: List[str]
    owner: Optional[str]
    is_active: bool
    metadata: Dict[str, Any]
    org_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'name': self.name,
            'platform': self.platform,
            'type': self.type.value if isinstance(self.type, IdentityType) else self.type,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_used': self.last_used.isoformat() if self.last_used else None,
            'permissions': self.permissions,
            'owner': self.owner,
            'is_active': self.is_active,
            'metadata': self.metadata,
            'org_id': self.org_id
        }


class DiscoveryEngine(_AddConn):
    """Main discovery engine that scans all connected platforms"""
    
    def __init__(self):
        self.neo4j_uri = os.getenv('NEO4J_URI', 'bolt://localhost:7687')
        self.neo4j_password = os.getenv('NEO4J_PASSWORD', 'neo4j')
        self.db_url = os.getenv('DATABASE_URL', 'postgresql://nhiadmin:nhi_secure_password_2026@localhost:5432/nhishield')
        self.driver = None
        self.pg_pool = None
        
    async def initialize(self):
        """Initialize database connections"""
        self.driver = AsyncGraphDatabase.driver(
            self.neo4j_uri,
            auth=("neo4j", self.neo4j_password)
        )
        self.pg_pool = await asyncpg.create_pool(self.db_url)
        logger.info("Discovery Engine initialized")
        
    async def close(self):
        """Close database connections"""
        if self.driver:
            await self.driver.close()
        if self.pg_pool:
            await self.pg_pool.close()
            
    async def get_integrations(self, org_id: Optional[str] = None) -> List[Dict]:
        """Get all active integrations from database"""
        async with self.pg_pool.acquire() as conn:
            if org_id:
                rows = await conn.fetch(
                    "SELECT * FROM integrations WHERE org_id = $1 AND is_active = true",
                    org_id
                )
            else:
                rows = await conn.fetch(
                    "SELECT * FROM integrations WHERE is_active = true"
                )
            return [dict(row) for row in rows]
    
    async def discover_all(self, org_id: Optional[str] = None) -> List[NHIdentity]:
        """Discovers all NHIs across all connected platforms"""
        integrations = await self.get_integrations(org_id)
        
        if not integrations:
            logger.warning("No active integrations found")
            return []
        
        tasks = []
        for integration in integrations:
            platform = integration['platform']
            config = json.loads(integration['config']) if isinstance(integration['config'], str) else integration['config']
            config['org_id'] = str(integration['org_id'])
            
            if platform == 'github':
                tasks.append(self.discover_github(config))
            elif platform == 'aws':
                tasks.append(self.discover_aws(config))
            elif platform == 'openai':
                tasks.append(self.discover_openai(config))
            elif platform == 'slack':
                tasks.append(self.discover_slack(config))
            elif platform == 'google':
                tasks.append(self.discover_google(config))
            elif platform == 'azure':
                tasks.append(self.discover_azure(config))
            elif platform == 'gitlab':
                tasks.append(self.discover_gitlab(config))
            elif platform == 'anthropic':
                tasks.append(self.discover_anthropic(config))
            elif platform == 'okta':
                tasks.append(self.discover_okta(config))
            elif platform == 'jira':
                tasks.append(self.discover_jira(config))
            elif platform == 'salesforce':
                tasks.append(self.discover_salesforce(config))
            elif platform == 'hubspot':
                tasks.append(self.discover_hubspot(config))
            elif platform == 'stripe':
                tasks.append(self.discover_stripe(config))
            elif platform == 'twilio':
                tasks.append(self.discover_twilio(config))
            elif platform == 'gcp':
                tasks.append(self.discover_gcp(config))
            else:
                logger.warning(f"Unknown platform: {platform}")
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        all_identities = []
        
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Discovery error: {result}")
            else:
                all_identities.extend(result)
        
        # Store discovered identities
        await self.store_identities(all_identities)
        
        logger.info(f"Discovered {len(all_identities)} identities across {len(integrations)} integrations")
        return all_identities
    
    async def discover_github(self, config: Dict) -> List[NHIdentity]:
        """Discovers GitHub Apps, OAuth tokens, deploy keys, Actions secrets"""
        identities = []
        token = config.get('token') or os.getenv('GITHUB_TOKEN')
        org = config.get('org') or os.getenv('GITHUB_ORG')
        org_id = config.get('org_id')
        
        if not token or not org:
            logger.warning("GitHub token or org not configured")
            return identities
        
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }
        
        async with httpx.AsyncClient() as client:
            # Discover GitHub Apps installed in the organization
            try:
                r = await client.get(
                    f"https://api.github.com/orgs/{org}/installations",
                    headers=headers
                )
                if r.status_code == 200:
                    data = r.json()
                    for app in data.get('installations', []):
                        identity = NHIdentity(
                            id=f"github-app-{app['id']}",
                            name=app.get('app_slug', f"app-{app['id']}"),
                            platform='github',
                            type=IdentityType.GITHUB_APP,
                            created_at=datetime.fromisoformat(
                                app['created_at'].replace('Z', '+00:00')
                            ) if app.get('created_at') else None,
                            last_used=None,
                            permissions=list(app.get('permissions', {}).keys()),
                            owner=app.get('account', {}).get('login'),
                            is_active=app.get('suspended_at') is None,
                            metadata={
                                "app_id": app.get('app_id'),
                                "repository_selection": app.get('repository_selection'),
                                "events": app.get('events', []),
                                "repositories_url": app.get('repositories_url')
                            },
                            org_id=org_id
                        )
                        identities.append(identity)
                        logger.debug(f"Discovered GitHub App: {identity.name}")
            except Exception as e:
                logger.error(f"Error discovering GitHub apps: {e}")
            
            # Discover organization repositories and their deploy keys
            try:
                page = 1
                while True:
                    r = await client.get(
                        f"https://api.github.com/orgs/{org}/repos",
                        headers=headers,
                        params={"per_page": 100, "page": page}
                    )
                    if r.status_code != 200:
                        break
                    
                    repos = r.json()
                    if not repos:
                        break
                    
                    for repo in repos:
                        repo_name = repo['name']
                        
                        # Get deploy keys
                        keys_r = await client.get(
                            f"https://api.github.com/repos/{org}/{repo_name}/keys",
                            headers=headers
                        )
                        if keys_r.status_code == 200:
                            for key in keys_r.json():
                                identity = NHIdentity(
                                    id=f"github-deploy-key-{key['id']}",
                                    name=key.get('title', f"key-{key['id']}"),
                                    platform='github',
                                    type=IdentityType.DEPLOY_KEY,
                                    created_at=datetime.fromisoformat(
                                        key['created_at'].replace('Z', '+00:00')
                                    ) if key.get('created_at') else None,
                                    last_used=None,
                                    permissions=['read'] if key.get('read_only') else ['read', 'write'],
                                    owner=repo_name,
                                    is_active=True,
                                    metadata={
                                        "repo": repo_name,
                                        "read_only": key.get('read_only', True),
                                        "key_id": key['id']
                                    },
                                    org_id=org_id
                                )
                        identities.append(identity)
                        
                        # Get repository secrets (metadata only, not values)
                        secrets_r = await client.get(
                            f"https://api.github.com/repos/{org}/{repo_name}/actions/secrets",
                            headers=headers
                        )
                        if secrets_r.status_code == 200:
                            for secret in secrets_r.json().get('secrets', []):
                                identity = NHIdentity(
                                    id=f"github-secret-{repo_name}-{secret['name']}",
                                    name=secret['name'],
                                    platform='github',
                                    type=IdentityType.API_KEY,
                                    created_at=datetime.fromisoformat(
                                        secret['created_at'].replace('Z', '+00:00')
                                    ) if secret.get('created_at') else None,
                                    last_used=datetime.fromisoformat(
                                        secret['updated_at'].replace('Z', '+00:00')
                                    ) if secret.get('updated_at') else None,
                                    permissions=['actions:read'],
                                    owner=repo_name,
                                    is_active=True,
                                    metadata={
                                        "repo": repo_name,
                                        "secret_type": "actions",
                                        "visibility": secret.get('visibility')
                                    },
                                    org_id=org_id
                                )
                                identities.append(identity)
                    
                    page += 1
                    if len(repos) < 100:
                        break
            except Exception as e:
                logger.error(f"Error discovering GitHub repos: {e}")
        
        logger.info(f"Discovered {len(identities)} GitHub identities")
        return identities
    
    async def discover_aws(self, config: Dict) -> List[NHIdentity]:
        """Discovers AWS IAM users, roles, and service accounts"""
        identities = []
        org_id = config.get('org_id')
        
        try:
            # Create boto3 session
            session = boto3.Session(
                aws_access_key_id=config.get('access_key') or os.getenv('AWS_ACCESS_KEY_ID'),
                aws_secret_access_key=config.get('secret_key') or os.getenv('AWS_SECRET_ACCESS_KEY'),
                region_name=config.get('region', 'us-east-1')
            )
            
            iam = session.client('iam')
            
            # Discover IAM Users (service accounts have no console login)
            paginator = iam.get_paginator('list_users')
            for page in paginator.paginate():
                for user in page['Users']:
                    username = user['UserName']
                    
                    # Check if it's a service account (no console login)
                    try:
                        iam.get_login_profile(UserName=username)
                        is_human = True
                    except ClientError as e:
                        if e.response['Error']['Code'] == 'NoSuchEntity':
                            is_human = False
                        else:
                            raise
                    
                    if not is_human:
                        # Get attached policies
                        attached = iam.list_attached_user_policies(UserName=username)
                        permissions = [p['PolicyName'] for p in attached['AttachedPolicies']]
                        
                        # Get inline policies
                        inline = iam.list_user_policies(UserName=username)
                        permissions.extend(inline['PolicyNames'])
                        
                        # Get groups and their policies
                        groups = iam.list_groups_for_user(UserName=username)
                        for group in groups['Groups']:
                            group_attached = iam.list_attached_group_policies(GroupName=group['GroupName'])
                            permissions.extend([p['PolicyName'] for p in group_attached['AttachedPolicies']])
                        
                        # Get last activity from access keys
                        last_used = None
                        try:
                            keys = iam.list_access_keys(UserName=username)['AccessKeyMetadata']
                            for key in keys:
                                key_last_used = iam.get_access_key_last_used(
                                    AccessKeyId=key['AccessKeyId']
                                )['AccessKeyLastUsed']
                                if 'LastUsedDate' in key_last_used:
                                    key_date = key_last_used['LastUsedDate']
                                    if last_used is None or key_date > last_used:
                                        last_used = key_date
                        except Exception:
                            pass
                        
                        # Get tags for owner info
                        tags_response = iam.get_user(UserName=username)
                        tags = {tag['Key']: tag['Value'] for tag in tags_response['User'].get('Tags', [])}
                        owner = tags.get('Owner') or tags.get('owner') or tags.get('Team')
                        
                        identity = NHIdentity(
                            id=f"aws-user-{user['UserId']}",
                            name=username,
                            platform='aws',
                            type=IdentityType.SERVICE_ACCOUNT,
                            created_at=user['CreateDate'].replace(tzinfo=timezone.utc) if user.get('CreateDate') else None,
                            last_used=last_used.replace(tzinfo=timezone.utc) if last_used else None,
                            permissions=permissions,
                            owner=owner,
                            is_active=True,
                            metadata={
                                "arn": user['Arn'],
                                "path": user.get('Path', '/'),
                                "tags": tags,
                                "access_key_count": len(keys) if 'keys' in dir() else 0
                            },
                            org_id=org_id
                        )
                        identities.append(identity)
            
            # Discover IAM Roles
            paginator = iam.get_paginator('list_roles')
            for page in paginator.paginate():
                for role in page['Roles']:
                    rolename = role['RoleName']
                    
                    # Skip AWS service roles
                    if role.get('Path', '').startswith('/aws-service-role/'):
                        continue
                    
                    attached = iam.list_attached_role_policies(RoleName=rolename)
                    permissions = [p['PolicyName'] for p in attached['AttachedPolicies']]
                    
                    # Get trust policy (who can assume this role)
                    trust_policy = role.get('AssumeRolePolicyDocument', {})
                    trusted_entities = []
                    for statement in trust_policy.get('Statement', []):
                        principal = statement.get('Principal', {})
                        if 'Service' in principal:
                            trusted_entities.append(f"service:{principal['Service']}")
                        if 'AWS' in principal:
                            trusted_entities.append(f"arn:{principal['AWS']}")
                    
                    # Get last used info
                    last_used = None
                    try:
                        role_last_used = iam.get_role(RoleName=rolename)['Role'].get('RoleLastUsed', {})
                        if 'LastUsedDate' in role_last_used:
                            last_used = role_last_used['LastUsedDate']
                    except Exception:
                        pass
                    
                    identity = NHIdentity(
                        id=f"aws-role-{role['RoleId']}",
                        name=rolename,
                        platform='aws',
                        type=IdentityType.IAM_ROLE,
                        created_at=role['CreateDate'].replace(tzinfo=timezone.utc) if role.get('CreateDate') else None,
                        last_used=last_used.replace(tzinfo=timezone.utc) if last_used else None,
                        permissions=permissions,
                        owner=None,
                        is_active=True,
                        metadata={
                            "arn": role['Arn'],
                            "path": role.get('Path', '/'),
                            "trusted_entities": trusted_entities,
                            "max_session_duration": role.get('MaxSessionDuration', 3600)
                        },
                        org_id=org_id
                    )
                    identities.append(identity)
            
            logger.info(f"Discovered {len(identities)} AWS identities")
            
        except Exception as e:
            logger.error(f"Error discovering AWS identities: {e}")
        
        return identities
    
    async def discover_openai(self, config: Dict) -> List[NHIdentity]:
        """Discovers OpenAI API keys and projects"""
        identities = []
        admin_key = config.get('admin_key') or os.getenv('OPENAI_ADMIN_KEY')
        org_id = config.get('org_id')
        
        if not admin_key:
            logger.warning("OpenAI admin key not configured")
            return identities
        
        headers = {
            "Authorization": f"Bearer {admin_key}",
            "Content-Type": "application/json"
        }
        
        async with httpx.AsyncClient() as client:
            # Discover API keys
            try:
                r = await client.get(
                    "https://api.openai.com/v1/organization/api_keys",
                    headers=headers
                )
                if r.status_code == 200:
                    data = r.json()
                    for key in data.get('data', []):
                        created_at = None
                        last_used = None
                        
                        if key.get('created_at'):
                            created_at = datetime.fromtimestamp(key['created_at'], tz=timezone.utc)
                        if key.get('last_used_at'):
                            last_used = datetime.fromtimestamp(key['last_used_at'], tz=timezone.utc)
                        
                        identity = NHIdentity(
                            id=f"openai-key-{key['id']}",
                            name=key.get('name', f"key-{key['id']}"),
                            platform='openai',
                            type=IdentityType.API_KEY,
                            created_at=created_at,
                            last_used=last_used,
                            permissions=['api_access'],
                            owner=key.get('created_by', {}).get('name') if key.get('created_by') else None,
                            is_active=key.get('status') == 'active',
                            metadata={
                                "key_id": key['id'],
                                "status": key.get('status'),
                                "last_used_org": key.get('last_used_org')
                            },
                            org_id=org_id
                        )
                        identities.append(identity)
                        logger.debug(f"Discovered OpenAI key: {identity.name}")
            except Exception as e:
                logger.error(f"Error discovering OpenAI keys: {e}")
            
            # Discover projects
            try:
                r = await client.get(
                    "https://api.openai.com/v1/organization/projects",
                    headers=headers
                )
                if r.status_code == 200:
                    for project in r.json().get('data', []):
                        identity = NHIdentity(
                            id=f"openai-project-{project['id']}",
                            name=project.get('name', f"project-{project['id']}"),
                            platform='openai',
                            type=IdentityType.SERVICE_ACCOUNT,
                            created_at=datetime.fromtimestamp(project['created_at'], tz=timezone.utc) if project.get('created_at') else None,
                            last_used=None,
                            permissions=['project_access'],
                            owner=project.get('owner'),
                            is_active=project.get('status') == 'active',
                            metadata={
                                "project_id": project['id'],
                                "status": project.get('status'),
                                "settings": project.get('settings', {})
                            },
                            org_id=org_id
                        )
                        identities.append(identity)
            except Exception as e:
                logger.error(f"Error discovering OpenAI projects: {e}")
        
        logger.info(f"Discovered {len(identities)} OpenAI identities")
        return identities
    
    async def discover_slack(self, config: Dict) -> List[NHIdentity]:
        """Discovers Slack bots and installed apps"""
        identities = []
        token = config.get('token') or os.getenv('SLACK_TOKEN')
        org_id = config.get('org_id')
        
        if not token:
            logger.warning("Slack token not configured")
            return identities
        
        headers = {"Authorization": f"Bearer {token}"}
        
        async with httpx.AsyncClient() as client:
            # Discover installed apps
            try:
                r = await client.get(
                    "https://slack.com/api/apps.list",
                    headers=headers
                )
                if r.status_code == 200:
                    data = r.json()
                    if data.get('ok'):
                        for app in data.get('apps', []):
                            identity = NHIdentity(
                                id=f"slack-app-{app['id']}",
                                name=app.get('name', f"app-{app['id']}"),
                                platform='slack',
                                type=IdentityType.SLACK_APP,
                                created_at=datetime.fromtimestamp(app.get('date_added', 0), tz=timezone.utc) if app.get('date_added') else None,
                                last_used=None,
                                permissions=app.get('scopes', []),
                                owner=app.get('installed_by', {}).get('name') if app.get('installed_by') else None,
                                is_active=not app.get('disabled', False),
                                metadata={
                                    "app_id": app['id'],
                                    "app_type": app.get('app_type'),
                                    "description": app.get('description'),
                                    "help_url": app.get('help_url'),
                                    "privacy_policy": app.get('privacy_policy'),
                                    "terms_of_service": app.get('terms_of_service')
                                },
                                org_id=org_id
                            )
                            identities.append(identity)
                            logger.debug(f"Discovered Slack app: {identity.name}")
            except Exception as e:
                logger.error(f"Error discovering Slack apps: {e}")
            
            # Discover bot users
            try:
                r = await client.get(
                    "https://slack.com/api/users.list",
                    headers=headers,
                    params={"limit": 200}
                )
                if r.status_code == 200:
                    data = r.json()
                    if data.get('ok'):
                        for user in data.get('members', []):
                            if user.get('is_bot') and not user.get('deleted'):
                                identity = NHIdentity(
                                    id=f"slack-bot-{user['id']}",
                                    name=user.get('name', f"bot-{user['id']}"),
                                    platform='slack',
                                    type=IdentityType.BOT_TOKEN,
                                    created_at=None,  # Slack doesn't expose this
                                    last_used=None,
                                    permissions=['bot'],
                                    owner=user.get('real_name'),
                                    is_active=not user.get('deleted', False),
                                    metadata={
                                        "user_id": user['id'],
                                        "team_id": user.get('team_id'),
                                        "is_app_user": user.get('is_app_user', False)
                                    },
                                    org_id=org_id
                                )
                                identities.append(identity)
            except Exception as e:
                logger.error(f"Error discovering Slack bots: {e}")
        
        logger.info(f"Discovered {len(identities)} Slack identities")
        return identities
    
    async def discover_google(self, config: Dict) -> List[NHIdentity]:
        """Discovers Google Cloud service accounts"""
        identities = []
        org_id = config.get('org_id')
        
        try:
            from google.oauth2 import service_account
            from googleapiclient.discovery import build
            
            credentials_path = config.get('credentials_path') or os.getenv('GOOGLE_CREDENTIALS_PATH')
            project_id = config.get('project_id')
            
            if not credentials_path:
                logger.warning("Google credentials path not configured")
                return identities
            
            credentials = service_account.Credentials.from_service_account_file(
                credentials_path,
                scopes=['https://www.googleapis.com/auth/cloud-platform']
            )
            
            service = build('iam', 'v1', credentials=credentials)
            
            # List service accounts
            if not project_id:
                # Try to get from credentials
                project_id = credentials.project_id
            
            request = service.projects().serviceAccounts().list(
                name=f"projects/{project_id}"
            )
            
            while request:
                response = request.execute()
                for account in response.get('accounts', []):
                    email = account['email']
                    
                    # Get IAM policies for this service account
                    iam_request = service.projects().serviceAccounts().getIamPolicy(
                        resource=account['name']
                    )
                    try:
                        iam_policy = iam_request.execute()
                        bindings = iam_policy.get('bindings', [])
                        permissions = [b['role'] for b in bindings]
                    except Exception:
                        permissions = []
                    
                    # Parse creation date
                    created_at = None
                    if 'createTime' in account:
                        created_at = datetime.fromisoformat(
                            account['createTime'].replace('Z', '+00:00')
                        )
                    
                    identity = NHIdentity(
                        id=f"gcp-sa-{email}",
                        name=email,
                        platform='google',
                        type=IdentityType.GCP_SA,
                        created_at=created_at,
                        last_used=None,  # Would need additional API calls
                        permissions=permissions,
                        owner=account.get('displayName'),
                        is_active=True,
                        metadata={
                            "unique_id": account.get('uniqueId'),
                            "project_id": project_id,
                            "oauth2_client_id": account.get('oauth2ClientId'),
                            "disabled": account.get('disabled', False)
                        },
                        org_id=org_id
                    )
                    identities.append(identity)
                
                request = service.projects().serviceAccounts().list_next(request, response)
            
            logger.info(f"Discovered {len(identities)} Google Cloud identities")
            
        except ImportError:
            logger.warning("Google Cloud libraries not installed. Run: pip install google-auth google-api-python-client")
        except Exception as e:
            logger.error(f"Error discovering Google identities: {e}")
        
        return identities
    
    async def discover_azure(self, config: Dict) -> List[NHIdentity]:
        """Discovers Azure service principals"""
        identities = []
        org_id = config.get('org_id')
        
        try:
            from azure.identity import ClientSecretCredential
            from azure.graphrbac import GraphRbacManagementClient
            
            tenant_id = config.get('tenant_id') or os.getenv('AZURE_TENANT_ID')
            client_id = config.get('client_id') or os.getenv('AZURE_CLIENT_ID')
            client_secret = config.get('client_secret') or os.getenv('AZURE_CLIENT_SECRET')
            
            if not all([tenant_id, client_id, client_secret]):
                logger.warning("Azure credentials not fully configured")
                return identities
            
            credentials = ClientSecretCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret
            )
            
            graph_client = GraphRbacManagementClient(credentials, tenant_id)
            
            # List service principals
            for sp in graph_client.service_principals.list():
                identity = NHIdentity(
                    id=f"azure-sp-{sp.object_id}",
                    name=sp.display_name or f"sp-{sp.object_id}",
                    platform='azure',
                    type=IdentityType.AZURE_SP,
                    created_at=sp.creation_timestamp.replace(tzinfo=timezone.utc) if sp.creation_timestamp else None,
                    last_used=None,
                    permissions=[],  # Would need additional API calls
                    owner=None,
                    is_active=sp.account_enabled if sp.account_enabled is not None else True,
                    metadata={
                        "object_id": sp.object_id,
                        "app_id": sp.app_id,
                        "service_principal_type": sp.service_principal_type,
                        "tags": sp.tags
                    },
                    org_id=org_id
                )
                identities.append(identity)
            
            logger.info(f"Discovered {len(identities)} Azure identities")
            
        except ImportError:
            logger.warning("Azure libraries not installed. Run: pip install azure-identity azure-graphrbac")
        except Exception as e:
            logger.error(f"Error discovering Azure identities: {e}")
        
        return identities
    
    async def discover_gitlab(self, config: Dict) -> List[NHIdentity]:
        """Discovers GitLab access tokens and service accounts"""
        identities = []
        token = config.get('token') or os.getenv('GITLAB_TOKEN')
        org_id = config.get('org_id')
        base_url = config.get('base_url', 'https://gitlab.com')
        
        if not token:
            logger.warning("GitLab token not configured")
            return identities
        
        headers = {"PRIVATE-TOKEN": token}
        
        async with httpx.AsyncClient() as client:
            # Discover group access tokens
            try:
                group_id = config.get('group_id')
                if group_id:
                    r = await client.get(
                        f"{base_url}/api/v4/groups/{group_id}/access_tokens",
                        headers=headers
                    )
                    if r.status_code == 200:
                        for token_info in r.json():
                            identity = NHIdentity(
                                id=f"gitlab-token-{token_info['id']}",
                                name=token_info.get('name', f"token-{token_info['id']}"),
                                platform='gitlab',
                                type=IdentityType.OAUTH_TOKEN,
                                created_at=datetime.fromisoformat(
                                    token_info['created_at'].replace('Z', '+00:00')
                                ) if token_info.get('created_at') else None,
                                last_used=datetime.fromisoformat(
                                    token_info['last_used_at'].replace('Z', '+00:00')
                                ) if token_info.get('last_used_at') else None,
                                permissions=token_info.get('scopes', []),
                                owner=token_info.get('username'),
                                is_active=token_info.get('active', True),
                                metadata={
                                    "token_id": token_info['id'],
                                    "access_level": token_info.get('access_level'),
                                    "expires_at": token_info.get('expires_at')
                                },
                                org_id=org_id
                            )
                            identities.append(identity)
            except Exception as e:
                logger.error(f"Error discovering GitLab tokens: {e}")
        
        logger.info(f"Discovered {len(identities)} GitLab identities")
        return identities
    
    async def store_identities(self, identities: List[NHIdentity]):
        """Store discovered identities in PostgreSQL and Neo4j"""
        if not identities:
            return
        
        # Store in PostgreSQL
        async with self.pg_pool.acquire() as conn:
            for identity in identities:
                try:
                    await conn.execute("""
                        INSERT INTO identities 
                        (id, org_id, name, platform, type, permissions, owner, 
                         is_active, created_at, last_used, metadata, discovered_at)
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW())
                        ON CONFLICT (id) DO UPDATE SET
                            name = EXCLUDED.name,
                            permissions = EXCLUDED.permissions,
                            owner = EXCLUDED.owner,
                            is_active = EXCLUDED.is_active,
                            last_used = EXCLUDED.last_used,
                            metadata = EXCLUDED.metadata,
                            updated_at = NOW(),
                            last_synced_at = NOW()
                    """,
                        identity.id,
                        identity.org_id,
                        identity.name,
                        identity.platform,
                        identity.type.value if isinstance(identity.type, IdentityType) else identity.type,
                        identity.permissions,
                        identity.owner,
                        identity.is_active,
                        identity.created_at,
                        identity.last_used,
                        json.dumps(identity.metadata)
                    )
                except Exception as e:
                    logger.error(f"Error storing identity {identity.id}: {e}")
        
        # Store in Neo4j graph
        async with self.driver.session() as session:
            for identity in identities:
                try:
                    await session.run("""
                        MERGE (n:NHIdentity {id: $id})
                        SET n.name = $name,
                            n.platform = $platform,
                            n.type = $type,
                            n.created_at = $created_at,
                            n.last_used = $last_used,
                            n.is_active = $is_active,
                            n.permissions = $permissions,
                            n.owner = $owner,
                            n.risk_level = 'LOW',
                            n.updated_at = datetime()
                        WITH n
                        MERGE (p:Platform {name: $platform})
                        SET p.type = $platform_type
                        MERGE (n)-[:BELONGS_TO]->(p)
                    """,
                        id=identity.id,
                        name=identity.name,
                        platform=identity.platform,
                        type=identity.type.value if isinstance(identity.type, IdentityType) else identity.type,
                        created_at=identity.created_at.isoformat() if identity.created_at else None,
                        last_used=identity.last_used.isoformat() if identity.last_used else None,
                        is_active=identity.is_active,
                        permissions=identity.permissions,
                        owner=identity.owner,
                        platform_type=identity.platform
                    )
                except Exception as e:
                    logger.error(f"Error storing identity in Neo4j {identity.id}: {e}")
        
        logger.info(f"Stored {len(identities)} identities in databases")


async def main():
    """Main entry point for discovery engine"""
    engine = DiscoveryEngine()
    await engine.initialize()
    
    try:
        # Discover all identities
        identities = await engine.discover_all()
        logger.info(f"Discovery complete. Found {len(identities)} total identities")
        
        # Print summary by platform
        by_platform = {}
        for identity in identities:
            platform = identity.platform
            by_platform[platform] = by_platform.get(platform, 0) + 1
        
        logger.info("Discovery summary by platform:")
        for platform, count in sorted(by_platform.items()):
            logger.info(f"  {platform}: {count}")
            
    finally:
        await engine.close()


if __name__ == "__main__":
    asyncio.run(main())
