# ============================================================
# NHI SHIELD — Discovery Engine Data Models
# ============================================================
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any, Optional
from enum import Enum


class IdentityType(str, Enum):
    API_KEY = "api_key"
    SERVICE_ACCOUNT = "service_account"
    OAUTH_TOKEN = "oauth_token"
    BOT_TOKEN = "bot_token"
    BOT = "bot_token"  # alias for BOT_TOKEN
    DEPLOY_KEY = "deploy_key"
    GITHUB_APP = "github_app"
    SLACK_APP = "slack_app"
    IAM_ROLE = "iam_role"
    LAMBDA_ROLE = "lambda_role"
    MACHINE_ACCOUNT = "machine_account"
    WEBHOOK = "webhook"
    OTHER = "other"


class RiskIndicator(str, Enum):
    ADMIN_ACCESS = "admin_access"
    WILDCARD_PERMISSION = "wildcard_permission"
    NO_EXPIRY = "no_expiry"
    NO_ROTATION_90D = "no_rotation_90d"
    DORMANT_90D = "dormant_90d"
    DORMANT_180D = "dormant_180d"
    NO_OWNER = "no_owner"
    INTERNET_ACCESSIBLE = "internet_accessible"
    SHADOW_AI = "shadow_ai"  # Unapproved AI tool
    HIGH_PRIVILEGE_CHAIN = "high_privilege_chain"  # Created by high-priv identity


@dataclass
class NHIdentity:
    """Represents a discovered Non-Human Identity"""
    id: str                                    # Unique ID on the source platform
    name: str
    platform: str                              # github, aws, openai, slack, etc.
    type: IdentityType
    created_at: Optional[datetime] = None
    last_used: Optional[datetime] = None
    permissions: List[str] = field(default_factory=list)
    owner: Optional[str] = None               # Email/username of responsible human
    is_active: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)
    risk_indicators: List[RiskIndicator] = field(default_factory=list)
    external_id: Optional[str] = None         # ID on source platform for dedup

    def add_risk_indicator(self, indicator: RiskIndicator):
        if indicator not in self.risk_indicators:
            self.risk_indicators.append(indicator)

    def has_admin_access(self) -> bool:
        admin_keywords = ['admin', 'administrator', 'root', 'superuser', 'AdministratorAccess', '*']
        return any(kw.lower() in p.lower() for p in self.permissions for kw in admin_keywords)

    def is_dormant(self, days: int = 90) -> bool:
        if not self.last_used:
            return True
        delta = datetime.utcnow() - self.last_used.replace(tzinfo=None)
        return delta.days >= days


@dataclass
class DiscoveryResult:
    """Summary of a single platform discovery run"""
    platform: str
    identities_found: int
    new_identities: int = 0
    removed_identities: int = 0
    errors: List[str] = field(default_factory=list)
    duration_seconds: float = 0.0
    timestamp: datetime = field(default_factory=datetime.utcnow)
    success: bool = True
