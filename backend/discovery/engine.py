# ============================================================
# NHI SHIELD — Discovery Engine  (FIXED v2.1)
# Fixes: psycopg2→asyncpg, double instantiation, tobytes() bug,
#        connector import paths
# ============================================================
import asyncio
import json
import time
from typing import Dict, List
import logging
logger = logging.getLogger(__name__)

import asyncpg
from neo4j import AsyncGraphDatabase

from backend.discovery.models import NHIdentity, DiscoveryResult
from backend.discovery.connectors.github import GitHubConnector
from backend.discovery.connectors.aws import AWSConnector
from backend.discovery.connectors.openai_slack import OpenAIConnector, SlackConnector


CONNECTOR_MAP = {
    'github':  GitHubConnector,
    'aws':     AWSConnector,
    'openai':  OpenAIConnector,
    'slack':   SlackConnector,
}


class DiscoveryEngine:

    def __init__(self, database_url: str, neo4j_uri: str, neo4j_password: str):
        self.database_url  = database_url
        self.neo4j_uri     = neo4j_uri
        self.neo4j_password = neo4j_password
        self._pg_pool: asyncpg.Pool | None = None

    async def _get_pool(self) -> asyncpg.Pool:
        """Lazy-initialise async connection pool (thread-safe)."""
        if self._pg_pool is None:
            self._pg_pool = await asyncpg.create_pool(self.database_url, min_size=2, max_size=10)
        return self._pg_pool

    def _get_neo4j_driver(self):
        return AsyncGraphDatabase.driver(
            self.neo4j_uri,
            auth=("neo4j", self.neo4j_password)
        )

    # ── Credential Parsing ────────────────────────────────────────────────────

    @staticmethod
    def _parse_credentials(raw) -> Dict:
        """
        Safely parse credentials stored as JSON string, bytes, memoryview, or dict.
        FIX: original code called .tobytes() unconditionally which crashes on str.
        """
        if isinstance(raw, dict):
            return raw
        if isinstance(raw, memoryview):
            raw = raw.tobytes()
        if isinstance(raw, (bytes, bytearray)):
            raw = raw.decode('utf-8')
        if isinstance(raw, str):
            return json.loads(raw)
        raise ValueError(f"Cannot parse credentials of type {type(raw)}")

    # ── Discovery ─────────────────────────────────────────────────────────────

    async def run_full_discovery(self, org_id: str) -> List[DiscoveryResult]:
        """Run discovery for ALL connected integrations for an org."""
        pool = await self._get_pool()
        rows = await pool.fetch(
            "SELECT platform, credentials FROM integrations WHERE org_id=$1 AND is_active=true",
            org_id
        )

        if not rows:
            logger.info(f"No active integrations for org {org_id}")
            return []

        logger.info(f"Running full discovery for {len(rows)} integrations")

        tasks = [
            self._run_platform_discovery(org_id, r['platform'], self._parse_credentials(r['credentials']))
            for r in rows
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        output = []
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Platform discovery failed: {result}")
            else:
                output.append(result)
        return output

    async def _run_platform_discovery(
        self, org_id: str, platform: str, credentials: Dict
    ) -> DiscoveryResult:
        """Run discovery for a single platform and store results."""
        start = time.time()
        result = DiscoveryResult(platform=platform, identities_found=0)

        try:
            connector_class = CONNECTOR_MAP.get(platform)
            if not connector_class:
                raise ValueError(f"No connector for platform: {platform}")

            # FIX: single instance - validate then discover (was creating two separate instances)
            connector = connector_class(credentials)
            await connector.validate_credentials()
            identities = await connector.discover()

            result.identities_found = len(identities)
            await self._store_identities(org_id, platform, identities)
            await self._update_sync_timestamp(org_id, platform, len(identities))

            logger.info(f"[{platform}] Discovery complete: {len(identities)} identities")

        except Exception as e:
            result.success = False
            result.errors.append(str(e))
            logger.error(f"[{platform}] Discovery failed: {e}")

        result.duration_seconds = time.time() - start
        return result

    # ── Storage ───────────────────────────────────────────────────────────────

    async def _store_identities(self, org_id: str, platform: str, identities: List[NHIdentity]):
        """Upsert discovered identities into PostgreSQL and Neo4j."""
        if not identities:
            return

        pool = await self._get_pool()
        async with pool.acquire() as conn:
            async with conn.transaction():
                for identity in identities:
                    await conn.execute("""
                        INSERT INTO identities
                            (org_id, name, platform, type, permissions, owner, is_active,
                             created_at, last_used, metadata, external_id)
                        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
                        ON CONFLICT (org_id, platform, external_id) DO UPDATE SET
                            name        = EXCLUDED.name,
                            permissions = EXCLUDED.permissions,
                            owner       = EXCLUDED.owner,
                            last_used   = EXCLUDED.last_used,
                            is_active   = EXCLUDED.is_active,
                            metadata    = EXCLUDED.metadata,
                            updated_at  = NOW()
                    """,
                        org_id, identity.name, identity.platform,
                        identity.type.value,
                        json.dumps(identity.permissions),
                        identity.owner,
                        identity.is_active,
                        identity.created_at,
                        identity.last_used,
                        json.dumps(identity.metadata),
                        identity.external_id or identity.id,
                    )

        # Also sync into Neo4j for graph relationships
        await self._store_in_neo4j(org_id, identities)

    async def _store_in_neo4j(self, org_id: str, identities: List[NHIdentity]):
        """Store NHI nodes and relationships in Neo4j."""
        driver = self._get_neo4j_driver()
        try:
            async with driver.session() as session:
                for identity in identities:
                    await session.run("""
                        MERGE (n:NHIdentity {id: $external_id, org_id: $org_id})
                        SET n.name          = $name,
                            n.platform      = $platform,
                            n.type          = $type,
                            n.is_active     = $is_active,
                            n.risk_indicators = $risk_indicators,
                            n.updated_at    = datetime()
                        MERGE (p:Platform {name: $platform})
                        MERGE (n)-[:BELONGS_TO]->(p)
                        MERGE (org:Organization {id: $org_id})
                        MERGE (n)-[:MEMBER_OF]->(org)
                    """, {
                        'external_id':     identity.external_id or identity.id,
                        'org_id':          org_id,
                        'name':            identity.name,
                        'platform':        identity.platform,
                        'type':            identity.type.value,
                        'is_active':       identity.is_active,
                        'risk_indicators': [r.value for r in identity.risk_indicators],
                    })
        finally:
            await driver.close()

    async def _update_sync_timestamp(self, org_id: str, platform: str, count: int):
        pool = await self._get_pool()
        await pool.execute(
            "UPDATE integrations SET last_sync=NOW(), last_sync_count=$1 WHERE org_id=$2 AND platform=$3",
            count, org_id, platform
        )

    async def close(self):
        if self._pg_pool:
            await self._pg_pool.close()
