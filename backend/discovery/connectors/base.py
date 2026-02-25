# ============================================================
# NHI SHIELD — Base Connector
# Abstract class all platform connectors inherit from
# ============================================================
import asyncio
from abc import ABC, abstractmethod
from typing import List, Dict, Any
import logging
logger = logging.getLogger(__name__)
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
import httpx

from backend.discovery.models import NHIdentity


class ConnectorError(Exception):
    """Raised when a connector fails to communicate with a platform"""
    pass


class CredentialError(ConnectorError):
    """Raised when credentials are invalid or expired"""
    pass


class BaseConnector(ABC):
    """
    Abstract base class for all platform discovery connectors.
    Provides: retry logic, timeout handling, rate limiting, logging.
    """

    TIMEOUT_SECONDS = 30
    MAX_RETRIES = 3

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.platform = self.__class__.__name__.replace('Connector', '').lower()

    @abstractmethod
    async def discover(self) -> List[NHIdentity]:
        """
        Discover all NHIs on this platform.
        Must be implemented by each connector.
        Returns list of NHIdentity objects.
        """
        ...

    @abstractmethod
    async def validate_credentials(self) -> bool:
        """
        Test if the provided credentials are valid.
        Should make a lightweight API call and return True/False.
        """
        ...

    def _apply_risk_indicators(self, identity: NHIdentity) -> NHIdentity:
        """
        Auto-apply standard risk indicators based on identity properties.
        Called after each discovery to standardize risk flagging.
        """
        from backend.discovery.models import RiskIndicator

        if identity.has_admin_access():
            identity.add_risk_indicator(RiskIndicator.ADMIN_ACCESS)

        if '*' in ' '.join(identity.permissions):
            identity.add_risk_indicator(RiskIndicator.WILDCARD_PERMISSION)

        if not identity.owner:
            identity.add_risk_indicator(RiskIndicator.NO_OWNER)

        if identity.is_dormant(90):
            identity.add_risk_indicator(RiskIndicator.DORMANT_90D)

        if identity.is_dormant(180):
            identity.add_risk_indicator(RiskIndicator.DORMANT_180D)

        return identity

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=30),
        retry=retry_if_exception_type((httpx.TimeoutException, httpx.ConnectError)),
        before_sleep=lambda rs: logger.warning(
            f"Retrying request (attempt {rs.attempt_number})..."
        )
    )
    async def _get(self, client: httpx.AsyncClient, url: str, **kwargs) -> httpx.Response:
        """Make a GET request with automatic retry on transient failures"""
        logger.debug(f"GET {url}")
        response = await client.get(url, timeout=self.TIMEOUT_SECONDS, **kwargs)
        return response

    def _make_client(self, headers: Dict[str, str]) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            headers=headers,
            timeout=httpx.Timeout(self.TIMEOUT_SECONDS),
            follow_redirects=True,
        )
