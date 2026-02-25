/**
 * NHI Shield — Prometheus Metrics
 * Exposes /metrics endpoint for Prometheus scraping
 * Covers: API latency, identity counts, alert counts, DB pool, WebSocket connections
 */

const client = require('prom-client');

// Enable default Node.js metrics (CPU, memory, event loop, GC)
const register = new client.Registry();
client.collectDefaultMetrics({ register, prefix: 'nhi_shield_nodejs_' });

// ─── Custom Metrics ───────────────────────────────────────────────────────────

// HTTP request counter + histogram
const httpRequestsTotal = new client.Counter({
  name: 'nhi_shield_http_requests_total',
  help: 'Total HTTP requests',
  labelNames: ['method', 'route', 'status_code'],
  registers: [register],
});

const httpRequestDuration = new client.Histogram({
  name: 'nhi_shield_http_request_duration_seconds',
  help: 'HTTP request duration in seconds',
  labelNames: ['method', 'route', 'status_code'],
  buckets: [0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10],
  registers: [register],
});

// Identity metrics
const identitiesTotal = new client.Gauge({
  name: 'nhi_shield_identities_total',
  help: 'Total non-human identities discovered',
  labelNames: ['org_id', 'platform', 'risk_level'],
  registers: [register],
});

const identitiesActive = new client.Gauge({
  name: 'nhi_shield_identities_active',
  help: 'Active non-human identities',
  labelNames: ['org_id', 'platform'],
  registers: [register],
});

// Alert metrics
const alertsOpen = new client.Gauge({
  name: 'nhi_shield_alerts_open',
  help: 'Open anomaly alerts',
  labelNames: ['org_id', 'severity'],
  registers: [register],
});

const alertsTotal = new client.Counter({
  name: 'nhi_shield_alerts_created_total',
  help: 'Total alerts created',
  labelNames: ['org_id', 'severity', 'alert_type'],
  registers: [register],
});

// Policy decisions
const policyDecisions = new client.Counter({
  name: 'nhi_shield_policy_decisions_total',
  help: 'Zero Trust policy decisions',
  labelNames: ['decision', 'layer'],
  registers: [register],
});

// Discovery metrics
const discoveryRuns = new client.Counter({
  name: 'nhi_shield_discovery_runs_total',
  help: 'Total discovery runs',
  labelNames: ['platform', 'status'],
  registers: [register],
});

const discoveryDuration = new client.Histogram({
  name: 'nhi_shield_discovery_duration_seconds',
  help: 'Discovery run duration in seconds',
  labelNames: ['platform'],
  buckets: [1, 5, 10, 30, 60, 120, 300],
  registers: [register],
});

// Secret rotation metrics
const rotationsTotal = new client.Counter({
  name: 'nhi_shield_rotations_total',
  help: 'Total secret rotations',
  labelNames: ['platform', 'status'],
  registers: [register],
});

// WebSocket connections
const wsConnections = new client.Gauge({
  name: 'nhi_shield_websocket_connections',
  help: 'Active WebSocket connections',
  registers: [register],
});

// Database pool metrics
const dbPoolSize = new client.Gauge({
  name: 'nhi_shield_db_pool_total',
  help: 'PostgreSQL connection pool size',
  registers: [register],
});

const dbPoolIdle = new client.Gauge({
  name: 'nhi_shield_db_pool_idle',
  help: 'PostgreSQL idle connections',
  registers: [register],
});

// Webhook delivery metrics
const webhookDeliveries = new client.Counter({
  name: 'nhi_shield_webhook_deliveries_total',
  help: 'Webhook delivery attempts',
  labelNames: ['status'],
  registers: [register],
});

// Authentication metrics
const authAttempts = new client.Counter({
  name: 'nhi_shield_auth_attempts_total',
  help: 'Authentication attempts',
  labelNames: ['method', 'status'],
  registers: [register],
});

// ─── Middleware ───────────────────────────────────────────────────────────────

function metricsMiddleware(req, res, next) {
  const start = Date.now();
  res.on('finish', () => {
    const duration = (Date.now() - start) / 1000;
    // Normalize route (replace UUIDs + IDs with placeholders)
    const route = req.route?.path || req.path.replace(/[0-9a-f-]{8,}/gi, ':id');
    httpRequestsTotal.inc({ method: req.method, route, status_code: res.statusCode });
    httpRequestDuration.observe({ method: req.method, route, status_code: res.statusCode }, duration);
  });
  next();
}

// ─── Refresh Metrics from DB ─────────────────────────────────────────────────

async function refreshMetrics(pg) {
  try {
    // Identity gauges per platform + risk level
    const idents = await pg.query(`
      SELECT i.org_id, i.platform, rs.level as risk_level,
             COUNT(*) as total, COUNT(*) FILTER (WHERE i.is_active) as active
      FROM identities i LEFT JOIN risk_scores rs ON i.id = rs.identity_id
      GROUP BY i.org_id, i.platform, rs.level
    `);
    identitiesTotal.reset();
    identitiesActive.reset();
    idents.rows.forEach(r => {
      identitiesTotal.set({ org_id: r.org_id, platform: r.platform, risk_level: r.risk_level || 'UNKNOWN' }, parseInt(r.total));
      identitiesActive.set({ org_id: r.org_id, platform: r.platform }, parseInt(r.active));
    });

    // Alert gauges
    const alerts = await pg.query(`
      SELECT a.org_id, a.severity, COUNT(*) as cnt
      FROM anomaly_alerts a WHERE a.resolved = false GROUP BY a.org_id, a.severity
    `);
    alertsOpen.reset();
    alerts.rows.forEach(r => alertsOpen.set({ org_id: r.org_id, severity: r.severity }, parseInt(r.cnt)));

    // DB pool stats
    dbPoolSize.set(pg.totalCount || 0);
    dbPoolIdle.set(pg.idleCount || 0);
  } catch (e) {
    // Non-fatal
  }
}

module.exports = {
  register,
  metricsMiddleware,
  refreshMetrics,
  // Expose metrics for use in server
  httpRequestsTotal,
  alertsTotal,
  policyDecisions,
  discoveryRuns,
  discoveryDuration,
  rotationsTotal,
  wsConnections,
  webhookDeliveries,
  authAttempts,
};
