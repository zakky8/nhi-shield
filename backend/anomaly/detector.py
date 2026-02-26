"""
NHI Shield — Advanced ML Anomaly Detection Engine v3.0
=======================================================
Detection layers:
  1. Rule-based: time, sensitive resource, impossible travel
  2. Volume spike: PostgreSQL time-series
  3. Isolation Forest: unsupervised anomaly scoring
  4. Behavioral embedding: Qdrant cosine similarity drift
  5. Chain attack: creation lineage traversal

All detections feed PostgreSQL anomaly_alerts and Redis pub/sub.
"""

import asyncio, json, logging, os, hashlib
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional

import numpy as np
import asyncpg
import redis.asyncio as aioredis
from qdrant_client import AsyncQdrantClient
from qdrant_client.models import Distance, VectorParams, PointStruct
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib

logger = logging.getLogger(__name__)

DB_URL     = os.getenv("DATABASE_URL", "postgresql://nhiadmin:nhi_secure_password_2026@localhost:5432/nhishield")
REDIS_URL  = os.getenv("REDIS_URL", "redis://localhost:6379")
QDRANT_URL = os.getenv("QDRANT_URL", "http://localhost:6333")
QDRANT_KEY = os.getenv("QDRANT_API_KEY", "qdrant_secure_2026")
INFLUX_URL    = os.getenv("INFLUXDB_URL", "http://localhost:8086")
INFLUX_TOKEN  = os.getenv("INFLUX_TOKEN", "influx_token_secure_2026")
INFLUX_ORG    = os.getenv("INFLUX_ORG", "nhishield")
INFLUX_BUCKET = os.getenv("INFLUX_BUCKET", "activity")
COLLECTION = "identity_behavior"
MODEL_PATH = "/tmp/nhi_if.pkl"
VECTOR_DIM = 128
BUSINESS_HOURS = (6, 23)

# Lazy InfluxDB client — only used if influxdb-client is installed
try:
    from influxdb_client import InfluxDBClient as _InfluxClient, Point as _InfluxPoint
    from influxdb_client.client.write_api import ASYNCHRONOUS as _ASYNC
    _INFLUX_AVAILABLE = True
except ImportError:
    _INFLUX_AVAILABLE = False

SENSITIVE_PATTERNS = [
    "prod","secret","password","database","backup","admin","root",
    "financial","pii",".env","terraform.tfstate","credentials",
    "private_key","ssh","token","api_key","iam"
]


@dataclass
class ActivityEvent:
    identity_id: str
    org_id: str
    action: str
    resource: str
    timestamp: datetime
    ip_address: Optional[str] = None
    success: bool = True
    metadata: Dict = field(default_factory=dict)


@dataclass
class AnomalyAlert:
    identity_id: str
    org_id: str
    alert_type: str
    severity: str
    description: str
    evidence: Dict = field(default_factory=dict)
    ml_score: float = 0.0


class FeatureExtractor:
    ACTION_TYPES  = ["read","write","delete","create","update","list","execute","access","deploy","scan"]
    RESOURCE_PREFX = ["iam","s3","ec2","rds","lambda","github","slack","openai","admin","api"]

    def extract(self, events: List[Dict]) -> np.ndarray:
        vec = np.zeros(VECTOR_DIM)
        if not events:
            return vec
        total = len(events)
        hours    = [e.get("hour", 12) for e in events]
        days     = [e.get("dow", 0)   for e in events]
        actions  = [str(e.get("action","")).lower()   for e in events]
        resources= [str(e.get("resource","")).lower() for e in events]
        ips      = [e.get("ip","") for e in events]
        failures = sum(1 for e in events if not e.get("success", True))
        weekends = sum(1 for d in days if d >= 5)

        for h in hours:
            if 0 <= h < 24: vec[h] += 1
        vec[0:24] /= (total + 1e-9)

        for d in days:
            if 0 <= d < 7: vec[24+d] += 1
        vec[24:31] /= (total + 1e-9)

        for i, at in enumerate(self.ACTION_TYPES):
            vec[31+i] = sum(1 for a in actions if at in a) / (total+1e-9)

        for i, rp in enumerate(self.RESOURCE_PREFX):
            vec[41+i] = sum(1 for r in resources if r.startswith(rp)) / (total+1e-9)

        vec[51] = failures / (total+1e-9)
        vec[52] = min(total/24.0, 1.0)
        vec[53] = min(len(set(ips))/10.0, 1.0)
        vec[54] = min(len(set(resources))/50.0, 1.0)
        vec[55] = weekends / (total+1e-9)
        return vec


class IFModel:
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self._trained = False

    def train(self, vectors: List[np.ndarray]):
        if len(vectors) < 10: return
        X = self.scaler.fit_transform(np.stack(vectors))
        self.model = IsolationForest(n_estimators=200, contamination=0.05, random_state=42, n_jobs=-1)
        self.model.fit(X)
        self._trained = True
        joblib.dump((self.model, self.scaler), MODEL_PATH)
        logger.info(f"IF trained on {len(vectors)} samples")

    def score(self, v: np.ndarray) -> float:
        """
        Returns anomaly score in [0,1] where 1.0 = most anomalous.
        Uses decision_function() calibrated to the trained threshold:
          decision_function < 0 = outlier, > 0 = inlier.
        Formula: score = 0.5 - decision_function/0.6  clamped to [0,1]
        """
        if not self._trained: self._try_load()
        if not self._trained: return 0.5   # untrained = neutral
        try:
            X = self.scaler.transform(v.reshape(1, -1))
            df = float(self.model.decision_function(X)[0])
            return float(max(0.0, min(1.0, 0.5 - df / 0.6)))
        except Exception: return 0.5
    def _try_load(self):
        if os.path.exists(MODEL_PATH):
            try:
                self.model, self.scaler = joblib.load(MODEL_PATH)
                self._trained = True
            except Exception: pass


class AnomalyDetector:

    def __init__(self):
        self.pg = None
        self.redis = None
        self.qdrant = None
        self.extractor = FeatureExtractor()
        self.if_model = IFModel()
        self._influx_write = None   # InfluxDB write API, set in initialize()

    async def initialize(self):
        self.pg     = await asyncpg.create_pool(DB_URL, min_size=2, max_size=10)
        self.redis  = await aioredis.from_url(REDIS_URL, decode_responses=True)
        self.qdrant = AsyncQdrantClient(url=QDRANT_URL, api_key=QDRANT_KEY)
        await self._ensure_collection()
        self.if_model._try_load()
        # Initialize InfluxDB write API if library is available
        if _INFLUX_AVAILABLE:
            try:
                _influx = _InfluxClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
                self._influx_write = _influx.write_api(write_options=_ASYNC)
                logger.info("InfluxDB time-series connected")
            except Exception as ex:
                logger.warning(f"InfluxDB unavailable (non-fatal): {ex}")
        logger.info("AnomalyDetector ready")

    async def close(self):
        if self.pg:    await self.pg.close()
        if self.redis: await self.redis.aclose()

    async def _ensure_collection(self):
        try:
            await self.qdrant.get_collection(COLLECTION)
        except Exception:
            await self.qdrant.create_collection(
                collection_name=COLLECTION,
                vectors_config=VectorParams(size=VECTOR_DIM, distance=Distance.COSINE)
            )

    # ── Public API ───────────────────────────────────────────────────────────

    async def analyze(self, event: ActivityEvent) -> List[AnomalyAlert]:
        alerts = []
        alerts += self._rule_unusual_time(event)
        alerts += self._rule_sensitive_resource(event)
        alerts += await self._rule_impossible_travel(event)
        alerts += await self._rule_volume_spike(event)
        alerts += await self._ml_behavioral_drift(event)
        alerts += await self._detect_chain_attack(event)

        final = []
        for a in alerts:
            if not await self._is_dup(a):
                await self._save(a)
                await self._publish(a)
                final.append(a)

        if final:
            await self.redis.publish("risk:recalculate",
                json.dumps({"identity_id": event.identity_id, "org_id": event.org_id}))

        # ── InfluxDB: write activity event as time-series point ───────────────
        # Enables rich time-series dashboards in Grafana (activity/hour, error rates, etc.)
        if self._influx_write and _INFLUX_AVAILABLE:
            try:
                loop = asyncio.get_running_loop()
                point = (
                    _InfluxPoint("activity_event")
                    .tag("identity_id", event.identity_id)
                    .tag("org_id", event.org_id)
                    .tag("action", event.action)
                    .tag("platform", event.metadata.get("platform", "unknown"))
                    .field("success", int(event.success))
                    .field("alert_count", len(final))
                    .field("has_alert", int(bool(final)))
                    .time(event.timestamp)
                )
                await loop.run_in_executor(
                    None,
                    lambda: self._influx_write.write(bucket=INFLUX_BUCKET, org=INFLUX_ORG, record=point)
                )
            except Exception as ex:
                logger.debug(f"InfluxDB write skipped: {ex}")

        return final

    async def train_baselines(self, org_id: str):
        rows = await self.pg.fetch(
            "SELECT id FROM identities WHERE org_id=$1 AND is_active=true", org_id)
        vectors = []
        for row in rows:
            evts = await self._fetch_events(row["id"], days=30)
            if len(evts) >= 10:
                v = self.extractor.extract(evts)
                vectors.append(v)
                await self._upsert_baseline(row["id"], org_id, v)
        if len(vectors) >= 10:
            self.if_model.train(vectors)
        logger.info(f"Trained {len(vectors)} baselines for org {org_id}")

    # ── Rules ────────────────────────────────────────────────────────────────

    def _rule_unusual_time(self, e: ActivityEvent) -> List[AnomalyAlert]:
        h = e.timestamp.hour
        if BUSINESS_HOURS[0] <= h <= BUSINESS_HOURS[1]: return []
        sev = "HIGH" if h < 4 or h > 22 else "MEDIUM"
        return [AnomalyAlert(e.identity_id, e.org_id, "UNUSUAL_TIME", sev,
            f"Activity at {h:02d}:00 UTC (outside business hours)",
            {"hour": h, "action": e.action})]

    def _rule_sensitive_resource(self, e: ActivityEvent) -> List[AnomalyAlert]:
        matched = [p for p in SENSITIVE_PATTERNS if p in e.resource.lower()]
        if not matched: return []
        h = e.timestamp.hour
        off = not (BUSINESS_HOURS[0] <= h <= BUSINESS_HOURS[1])
        sev = "CRITICAL" if off else "HIGH"
        return [AnomalyAlert(e.identity_id, e.org_id, "SENSITIVE_RESOURCE_ACCESS", sev,
            f"Access to sensitive resource '{e.resource}'",
            {"resource": e.resource, "patterns": matched, "off_hours": off})]

    async def _rule_impossible_travel(self, e: ActivityEvent) -> List[AnomalyAlert]:
        if not e.ip_address: return []
        try:
            key = f"ip:{e.identity_id}"
            last = await self.redis.get(key)
            await self.redis.setex(key, 600,
                json.dumps({"ip": e.ip_address, "ts": e.timestamp.isoformat()}))
            if last:
                prev = json.loads(last)
                if prev["ip"] != e.ip_address:
                    delta = abs((e.timestamp - datetime.fromisoformat(prev["ts"])).total_seconds())
                    if delta < 600:
                        return [AnomalyAlert(e.identity_id, e.org_id, "IMPOSSIBLE_TRAVEL", "CRITICAL",
                            f"IP changed {prev['ip']}→{e.ip_address} in {delta:.0f}s",
                            {"old_ip": prev["ip"], "new_ip": e.ip_address, "delta_s": delta})]
        except Exception as ex:
            logger.warning(f"Impossible travel error: {ex}")
        return []

    async def _rule_volume_spike(self, e: ActivityEvent) -> List[AnomalyAlert]:
        try:
            h_start = e.timestamp.replace(minute=0, second=0, microsecond=0)
            current = await self.pg.fetchval(
                "SELECT COUNT(*) FROM activity_events WHERE identity_id=$1 AND timestamp>=$2",
                e.identity_id, h_start) or 0
            avg = await self.pg.fetchval("""
                SELECT COALESCE(AVG(cnt),0) FROM (
                  SELECT COUNT(*) AS cnt FROM activity_events
                  WHERE identity_id=$1 AND timestamp >= NOW()-INTERVAL '7 days' AND timestamp<$2
                  GROUP BY date_trunc('hour',timestamp)
                ) sub""", e.identity_id, h_start) or 0
            if avg == 0: return []          # No baseline at all — skip
            if current < 5: return []       # Absolute minimum to avoid false positives
            ratio = current / float(avg)
            if ratio >= 50: sev, lbl = "CRITICAL", f"{ratio:.0f}x"
            elif ratio >= 10: sev, lbl = "HIGH", f"{ratio:.0f}x"
            elif ratio >= 3: sev, lbl = "MEDIUM", f"{ratio:.1f}x"
            else: return []
            return [AnomalyAlert(e.identity_id, e.org_id, "VOLUME_SPIKE", sev,
                f"Volume {lbl} above 7-day avg ({current} vs {avg:.1f}/hr)",
                {"current": current, "avg": float(avg), "ratio": ratio})]
        except Exception as ex:
            logger.warning(f"Volume spike error: {ex}")
            return []

    # ── ML ───────────────────────────────────────────────────────────────────

    async def _ml_behavioral_drift(self, e: ActivityEvent) -> List[AnomalyAlert]:
        try:
            evts = await self._fetch_events(e.identity_id, days=1)
            if len(evts) < 5: return []
            cur_v = self.extractor.extract(evts)
            if_score = self.if_model.score(cur_v)

            baseline = await self._load_baseline(e.identity_id)
            cos_sim = 1.0
            if baseline is not None:
                dot = np.dot(cur_v, baseline)
                nrm = np.linalg.norm(cur_v) * np.linalg.norm(baseline)
                cos_sim = float(dot / (nrm + 1e-9)) if nrm > 0 else 1.0

            # Update baseline with EMA
            updated = 0.9*baseline + 0.1*cur_v if baseline is not None else cur_v
            await self._upsert_baseline(e.identity_id, e.org_id, updated)

            if if_score >= 0.8 or cos_sim < 0.3:
                sev, msg = "CRITICAL", "Severe behavioral anomaly"
            elif if_score >= 0.6 or cos_sim < 0.5:
                sev, msg = "HIGH", "High behavioral anomaly"
            elif if_score >= 0.4 or cos_sim < 0.7:
                sev, msg = "MEDIUM", "Moderate behavioral deviation"
            else: return []

            return [AnomalyAlert(e.identity_id, e.org_id, "BEHAVIORAL_DRIFT", sev,
                f"{msg} (IF:{if_score:.2f} cos:{cos_sim:.2f})",
                {"if_score": if_score, "cosine": cos_sim}, ml_score=if_score)]
        except Exception as ex:
            logger.warning(f"ML drift error: {ex}")
            return []

    async def _detect_chain_attack(self, e: ActivityEvent) -> List[AnomalyAlert]:
        try:
            chain = await self.pg.fetch("""
                WITH RECURSIVE chain AS (
                    SELECT id, name, created_by_identity, 0 AS depth
                    FROM identities WHERE id=$1
                    UNION ALL
                    SELECT i.id, i.name, i.created_by_identity, c.depth+1
                    FROM identities i JOIN chain c ON i.id=c.created_by_identity
                    WHERE c.depth < 10
                )
                SELECT * FROM chain ORDER BY depth DESC
            """, e.identity_id)
            depth = len(chain) - 1
            if depth >= 3:
                names = [r["name"] for r in reversed(chain)]
                return [AnomalyAlert(e.identity_id, e.org_id, "CHAIN_ATTACK",
                    "CRITICAL" if depth >= 5 else "HIGH",
                    f"Identity {depth} levels deep in creation chain: {' → '.join(names[:5])}",
                    {"depth": depth, "chain": names})]
        except Exception: pass
        return []

    # ── Helpers ──────────────────────────────────────────────────────────────

    async def _fetch_events(self, identity_id: str, days: int) -> List[Dict]:
        try:
            rows = await self.pg.fetch("""
                SELECT action, resource, ip_address as ip, success,
                       EXTRACT(HOUR FROM timestamp)::int as hour,
                       EXTRACT(DOW FROM timestamp)::int as dow
                FROM activity_events WHERE identity_id=$1
                AND timestamp >= NOW()-INTERVAL '1 day'*$2
                ORDER BY timestamp DESC LIMIT 5000
            """, identity_id, days)
            return [dict(r) for r in rows]
        except Exception: return []

    async def _load_baseline(self, identity_id: str):
        try:
            res = await self.qdrant.retrieve(COLLECTION, ids=[_hash(identity_id)], with_vectors=True)
            if res: return np.array(res[0].vector)
        except Exception: pass
        return None

    async def _upsert_baseline(self, identity_id: str, org_id: str, v: np.ndarray):
        try:
            await self.qdrant.upsert(COLLECTION, points=[PointStruct(
                id=_hash(identity_id), vector=v.tolist(),
                payload={"identity_id": identity_id, "org_id": org_id,
                         "updated_at": datetime.now(timezone.utc).isoformat()})])
        except Exception as ex: logger.warning(f"Qdrant upsert: {ex}")

    async def _is_dup(self, a: AnomalyAlert) -> bool:
        key = f"alert_dedup:{a.identity_id}:{a.alert_type}"
        if await self.redis.get(key): return True
        await self.redis.setex(key, 3600, "1")
        return False

    async def _save(self, a: AnomalyAlert):
        try:
            await self.pg.execute("""
                INSERT INTO anomaly_alerts
                (org_id,identity_id,alert_type,severity,description,evidence,ml_score,created_at)
                VALUES($1,$2,$3,$4,$5,$6,$7,NOW())
            """, a.org_id, a.identity_id, a.alert_type, a.severity,
                a.description, json.dumps(a.evidence), a.ml_score)
        except Exception as ex: logger.error(f"Save alert: {ex}")

    async def _publish(self, a: AnomalyAlert):
        try:
            payload = json.dumps(asdict(a))
            await self.redis.publish("alerts:new", payload)
            if a.severity == "CRITICAL":
                await self.redis.publish("alerts:critical", payload)
        except Exception: pass


def _hash(s: str) -> int:
    return int(hashlib.md5(s.encode()).hexdigest(), 16) % (2**63)


async def run_detector():
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    detector = AnomalyDetector()
    await detector.initialize()
    redis_conn = await aioredis.from_url(REDIS_URL, decode_responses=True)
    pg = await asyncpg.create_pool(DB_URL)

    async def handle_events():
        pubsub = redis_conn.pubsub()
        await pubsub.subscribe("activity:new")
        async for msg in pubsub.listen():
            if msg["type"] != "message": continue
            try:
                d = json.loads(msg["data"])
                evt = ActivityEvent(
                    identity_id=d["identity_id"], org_id=d["org_id"],
                    action=d.get("action",""), resource=d.get("resource",""),
                    timestamp=datetime.fromisoformat(d.get("timestamp", datetime.now(timezone.utc).isoformat())),
                    ip_address=d.get("ip_address"), success=d.get("success", True))
                alerts = await detector.analyze(evt)
                if alerts: logger.info(f"{len(alerts)} alerts for {evt.identity_id}")
            except Exception as ex: logger.error(f"Event error: {ex}")

    async def nightly_train():
        while True:
            now = datetime.now(timezone.utc)
            nxt = now.replace(hour=2,minute=0,second=0,microsecond=0)
            if nxt <= now: nxt += timedelta(days=1)
            await asyncio.sleep((nxt-now).total_seconds())
            try:
                orgs = await pg.fetch("SELECT id FROM organizations WHERE is_active=true")
                for org in orgs:
                    await detector.train_baselines(str(org["id"]))
            except Exception as ex: logger.error(f"Nightly train: {ex}")

    logger.info("Anomaly Detector running — listening for events")
    await asyncio.gather(handle_events(), nightly_train())


if __name__ == "__main__":
    asyncio.run(run_detector())
