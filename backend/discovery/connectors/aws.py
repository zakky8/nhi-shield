# ============================================================
# NHI SHIELD — AWS Connector
# Discovers: IAM Service Accounts, IAM Roles, Lambda Execution
#            Roles, EC2 Instance Profiles, ECS Task Roles
# ============================================================
from datetime import datetime
from typing import List, Dict, Any
import logging
logger = logging.getLogger(__name__)

from backend.discovery.models import NHIdentity, IdentityType, RiskIndicator
from backend.discovery.connectors.base import BaseConnector, CredentialError


class AWSConnector(BaseConnector):

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.access_key = config['access_key']
        self.secret_key = config['secret_key']
        self.region = config.get('region', 'us-east-1')
        self._iam = None

    def _get_iam(self):
        if not self._iam:
            import boto3
            self._iam = boto3.client(
                'iam',
                aws_access_key_id=self.access_key,
                aws_secret_access_key=self.secret_key,
                region_name=self.region,
            )
        return self._iam

    async def validate_credentials(self) -> bool:
        import boto3
        try:
            sts = boto3.client(
                'sts',
                aws_access_key_id=self.access_key,
                aws_secret_access_key=self.secret_key,
                region_name=self.region,
            )
            sts.get_caller_identity()
            return True
        except Exception as e:
            if 'InvalidClientTokenId' in str(e) or 'AuthFailure' in str(e):
                raise CredentialError(f"AWS credentials invalid: {e}")
            raise

    async def discover(self) -> List[NHIdentity]:
        """Discovers all NHIs in AWS account"""
        import asyncio
        identities = []
        logger.info("Starting AWS IAM discovery")

        # Run in thread pool since boto3 is synchronous
        loop = asyncio.get_running_loop()
        results = await asyncio.gather(
            loop.run_in_executor(None, self._discover_service_accounts),
            loop.run_in_executor(None, self._discover_iam_roles),
            loop.run_in_executor(None, self._discover_lambda_roles),
            return_exceptions=True,
        )

        for result in results:
            if isinstance(result, Exception):
                logger.error(f"AWS sub-discovery error: {result}")
            else:
                identities.extend(result)

        # Apply standard risk indicators
        for identity in identities:
            self._apply_risk_indicators(identity)
            self._apply_aws_specific_risks(identity)

        logger.info(f"AWS discovery complete: {len(identities)} identities found")
        return identities

    def _discover_service_accounts(self) -> List[NHIdentity]:
        """IAM Users without console access = service accounts"""
        identities = []
        iam = self._get_iam()
        paginator = iam.get_paginator('list_users')

        for page in paginator.paginate():
            for user in page['Users']:
                # Skip users with console login (they're human)
                try:
                    iam.get_login_profile(UserName=user['UserName'])
                    continue  # Has console — it's a human user
                except iam.exceptions.NoSuchEntityException:
                    pass  # No console login — this is a service account

                permissions = self._get_user_permissions(user['UserName'])
                last_used = self._get_user_last_used(user['UserName'])
                key_age_days = self._get_key_age(user['UserName'])

                nhi = NHIdentity(
                    id=f"aws-user-{user['UserId']}",
                    external_id=user['UserId'],
                    name=user['UserName'],
                    platform='aws',
                    type=IdentityType.SERVICE_ACCOUNT,
                    created_at=user['CreateDate'].replace(tzinfo=None) if user.get('CreateDate') else None,
                    last_used=last_used,
                    permissions=permissions,
                    owner=None,
                    is_active=True,
                    metadata={
                        'arn': user['Arn'],
                        'user_id': user['UserId'],
                        'key_age_days': key_age_days,
                        'path': user.get('Path', '/'),
                    },
                )
                if key_age_days and key_age_days > 90:
                    nhi.add_risk_indicator(RiskIndicator.NO_ROTATION_90D)
                identities.append(nhi)

        return identities

    def _discover_iam_roles(self) -> List[NHIdentity]:
        """IAM Roles used by services"""
        identities = []
        iam = self._get_iam()
        paginator = iam.get_paginator('list_roles')

        for page in paginator.paginate():
            for role in page['Roles']:
                # Skip AWS service-linked roles (managed by AWS, not us)
                if '/aws-service-role/' in role.get('Path', ''):
                    continue

                permissions = self._get_role_permissions(role['RoleName'])
                nhi = NHIdentity(
                    id=f"aws-role-{role['RoleId']}",
                    external_id=role['RoleId'],
                    name=role['RoleName'],
                    platform='aws',
                    type=IdentityType.IAM_ROLE,
                    created_at=role['CreateDate'].replace(tzinfo=None) if role.get('CreateDate') else None,
                    last_used=None,
                    permissions=permissions,
                    owner=None,
                    is_active=True,
                    metadata={
                        'arn': role['Arn'],
                        'role_id': role['RoleId'],
                        'trust_policy': str(role.get('AssumeRolePolicyDocument', {})),
                        'description': role.get('Description', ''),
                    },
                )
                identities.append(nhi)
        return identities

    def _discover_lambda_roles(self) -> List[NHIdentity]:
        """Lambda function execution roles"""
        identities = []
        try:
            import boto3
            lambda_client = boto3.client(
                'lambda',
                aws_access_key_id=self.access_key,
                aws_secret_access_key=self.secret_key,
                region_name=self.region,
            )
            paginator = lambda_client.get_paginator('list_functions')
            for page in paginator.paginate():
                for fn in page['Functions']:
                    role_arn = fn.get('Role', '')
                    nhi = NHIdentity(
                        id=f"aws-lambda-role-{fn['FunctionName']}",
                        external_id=fn['FunctionArn'],
                        name=f"lambda-role:{fn['FunctionName']}",
                        platform='aws',
                        type=IdentityType.LAMBDA_ROLE,
                        created_at=None,
                        last_used=None,
                        permissions=['lambda_execution'],
                        owner=None,
                        is_active=True,
                        metadata={
                            'function_name': fn['FunctionName'],
                            'function_arn': fn['FunctionArn'],
                            'role_arn': role_arn,
                            'runtime': fn.get('Runtime', 'unknown'),
                        },
                    )
                    identities.append(nhi)
        except Exception as e:
            logger.warning(f"Could not discover Lambda roles: {e}")
        return identities

    def _get_user_permissions(self, username: str) -> List[str]:
        iam = self._get_iam()
        try:
            attached = iam.list_attached_user_policies(UserName=username)
            return [p['PolicyName'] for p in attached['AttachedPolicies']]
        except Exception:
            return []

    def _get_role_permissions(self, role_name: str) -> List[str]:
        iam = self._get_iam()
        try:
            attached = iam.list_attached_role_policies(RoleName=role_name)
            return [p['PolicyName'] for p in attached['AttachedPolicies']]
        except Exception:
            return []

    def _get_user_last_used(self, username: str) -> datetime | None:
        iam = self._get_iam()
        try:
            keys = iam.list_access_keys(UserName=username)['AccessKeyMetadata']
            for key in keys:
                result = iam.get_access_key_last_used(AccessKeyId=key['AccessKeyId'])
                if 'LastUsedDate' in result.get('AccessKeyLastUsed', {}):
                    return result['AccessKeyLastUsed']['LastUsedDate'].replace(tzinfo=None)
        except Exception:
            pass
        return None

    def _get_key_age(self, username: str) -> int | None:
        iam = self._get_iam()
        try:
            keys = iam.list_access_keys(UserName=username)['AccessKeyMetadata']
            if keys:
                create_date = keys[0]['CreateDate'].replace(tzinfo=None)
                return (datetime.utcnow() - create_date).days
        except Exception:
            pass
        return None

    @staticmethod
    def _apply_aws_specific_risks(identity: NHIdentity):
        perms = ' '.join(identity.permissions)
        if 'AdministratorAccess' in perms:
            identity.add_risk_indicator(RiskIndicator.ADMIN_ACCESS)
        key_age = identity.metadata.get('key_age_days', 0)
        if key_age and key_age > 90:
            identity.add_risk_indicator(RiskIndicator.NO_ROTATION_90D)
