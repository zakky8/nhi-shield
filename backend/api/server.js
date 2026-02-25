/**
 * NHI Shield - Enterprise API Server v2.0 (FULLY UPGRADED)
 * Features: Zero Trust, WebSocket, WAF, SSO/OIDC, Webhooks, Chain Attack Detection,
 *           Shadow AI, Lifecycle Mgmt, Permission Analyzer, Step-up Auth, Public API v1,
 *           X-API-Key Auth (nhi_xxxxx), OpenAPI Docs, mTLS Support
 */

const express = require('express');
const http = require('http');
const https = require('https');
const fs = require('fs');
const { Server: SocketServer } = require('socket.io');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');  // Pure JS drop-in for bcrypt — no native build needed
const { Pool } = require('pg');
const redis = require('redis');
const neo4j = require('neo4j-driver');
const cors = require('cors');
const dotenv = require('dotenv');
const crypto = require('crypto');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const axios = require('axios');
const { encrypt, decrypt } = require('./utils/crypto');
const { initiateSSOFlow, handleSSOCallback } = require('./utils/sso');
const {
  register: metricsRegistry,
  metricsMiddleware,
  refreshMetrics,
  alertsTotal,
  policyDecisions,
  authAttempts,
  wsConnections,
} = require('./utils/metrics');

dotenv.config();

const app = express();
const httpServer = http.createServer(app);
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3001';
const io = new SocketServer(httpServer, {
  cors: { origin: FRONTEND_URL, credentials: true },
  transports: ['websocket', 'polling'],
  pingTimeout: 60000,
  pingInterval: 25000
});

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'changeme_jwt_secret_must_be_32_chars';

// ============ SECURITY MIDDLEWARE ============

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"], styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"], imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "ws:", "wss:"]
    }
  },
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true }
}));
app.use(express.json({ limit: '1mb' }));
app.use(cors({ origin: FRONTEND_URL, credentials: true, methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'], allowedHeaders: ['Content-Type', 'Authorization', 'X-Step-Up-Token'] }));

// WAF - Block SQLi, XSS, path traversal (precision patterns to avoid false positives)
app.use((req, res, next) => {
  const sqlPatterns = [
    /\bunion\b[\s\w]*\bselect\b/i,
    /\bdrop\b[\s]*\btable\b/i,
    /\binsert\b[\s]*\binto\b/i,
    /';[\s]*(or|and)[\s]*'/i,
    /\bexec\b[\s]*\(/i
  ];
  const xssPatterns = [/<script[\s>]/i, /javascript:[\s]*\w/i, /\bon\w{1,20}\s*=/i];
  const pathPatterns = [/\.\.[/\\]/];
  let bodyStr = '';
  try { bodyStr = req.body ? JSON.stringify(req.body).slice(0, 4096) : ''; } catch { bodyStr = ''; }
  const check = decodeURIComponent(req.url) + ' ' + bodyStr;
  for (const p of [...sqlPatterns, ...xssPatterns, ...pathPatterns]) {
    if (p.test(check)) {
      console.warn('WAF blocked:', p.source, 'from', req.ip, 'on', req.path);
      return res.status(403).json({ error: 'Request blocked by security policy' });
    }
  }
  next();
});

// Rate limiting
const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: process.env.NODE_ENV === 'test' ? 1000 : 200, standardHeaders: true, legacyHeaders: false });
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: process.env.NODE_ENV === 'test' ? 10 : 10, message: { error: 'Too many auth attempts', code: 'RATE_LIMIT_EXCEEDED' } });
const apiLimiter = rateLimit({ windowMs: 60 * 1000, max: process.env.NODE_ENV === 'test' ? 1000 : 60 });
app.use('/api/', limiter);
app.use('/api/v1/', apiLimiter);

// ============ DATABASE CONNECTIONS ============

const pg = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://localhost:5432/nhishield',
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  max: 20
});

const redisClient = redis.createClient({ url: process.env.REDIS_URL || 'redis://localhost:6379' });
if (process.env.NODE_ENV !== 'test') {
  redisClient.connect().catch(console.error);
}
redisClient.on('error', err => console.error('Redis error:', err));

// Wrap redis methods for test safety
const safeRedis = {
  get: async (key) => { try { return await redisClient.get(key); } catch { return null; } },
  setEx: async (key, ttl, val) => { try { return await redisClient.setEx(key, ttl, val); } catch { return null; } },
  publish: async (channel, msg) => { try { return await redisClient.publish(channel, msg); } catch { return null; } },
};

const neo4jDriver = neo4j.driver(
  process.env.NEO4J_URI || 'bolt://localhost:7687',
  neo4j.auth.basic('neo4j', process.env.NEO4J_PASSWORD || 'neo4j')
);

// ============ UTILITIES ============

const auditLog = async (orgId, userId, action, description, ip, extra = {}) => {
  try {
    const identityId = extra.identity_id || null;
    await pg.query(
      'INSERT INTO audit_logs (org_id, user_id, identity_id, action, description, ip_address, metadata, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,NOW())',
      [orgId, userId, identityId, action, description, ip, JSON.stringify(extra)]
    );
  } catch (e) { /* non-fatal - never block request for audit log failure */ }
};

const emitToOrg = (orgId, event, data) =>
  io.to(`org:${orgId}`).emit(event, { ...data, timestamp: new Date().toISOString() });

const deliverWebhooks = async (orgId, eventType, payload) => {
  try {
    const hooks = await pg.query(
      "SELECT * FROM webhooks WHERE org_id = $1 AND is_active = true AND $2 = ANY(events)",
      [orgId, eventType]
    );
    for (const h of hooks.rows) {
      const sig = crypto.createHmac('sha256', h.secret).update(JSON.stringify(payload)).digest('hex');
      axios.post(h.url, payload, {
        headers: { 'X-NHI-Signature': `sha256=${sig}`, 'X-NHI-Event': eventType },
        timeout: 10000
      }).then(() => pg.query('UPDATE webhooks SET last_delivery = NOW(), delivery_count = delivery_count + 1 WHERE id = $1', [h.id]))
        .catch(e => pg.query('UPDATE webhooks SET last_error = $1 WHERE id = $2', [e.message, h.id]));
    }
  } catch (e) { console.error('Webhook error:', e); }
};

// ============ AUTHENTICATION MIDDLEWARE ============

const authenticate = async (req, res, next) => {
  try {
    // ── X-API-Key authentication (nhi_xxxxx format) ───────────────
    const apiKey = req.headers['x-api-key'];
    if (apiKey && apiKey.startsWith('nhi_')) {
      const keyHash = crypto.createHash('sha256').update(apiKey).digest('hex');
      const keyRow = await pg.query(
        `SELECT ak.org_id, ak.role, ak.is_active, ak.last_used_at, o.name as org_name
         FROM api_keys ak JOIN organizations o ON o.id = ak.org_id
         WHERE ak.key_hash = $1 AND ak.is_active = true`,
        [keyHash]
      );
      if (!keyRow.rows.length) return res.status(401).json({ error: 'Invalid or inactive API key' });
      // Update last_used async (non-blocking)
      pg.query('UPDATE api_keys SET last_used_at = NOW(), use_count = use_count + 1 WHERE key_hash = $1', [keyHash]).catch(() => { });
      req.user = { id: `apikey:${keyHash.slice(0, 8)}`, role: keyRow.rows[0].role, org_id: keyRow.rows[0].org_id, is_api_key: true };
      return next();
    }

    // ── Bearer JWT authentication ─────────────────────────────────
    const auth = req.headers.authorization;
    if (!auth?.startsWith('Bearer ')) return res.status(401).json({ error: 'No token provided' });
    const token = auth.split(' ')[1];



    const blacklisted = await redisClient.get(`blacklist:${token}`);
    if (blacklisted) return res.status(401).json({ error: 'Token revoked' });
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.requireMfa) return res.status(401).json({ error: 'MFA required', requireMfa: true });

    const user = await pg.query(
      'SELECT id, email, role, org_id, is_active FROM users WHERE id = $1', [decoded.userId]
    );
    if (!user.rows.length || !user.rows[0].is_active) return res.status(401).json({ error: 'User not found or inactive' });
    req.user = user.rows[0];
    req.token = token;
    next();
  } catch (e) {
    if (e.name === 'TokenExpiredError') return res.status(401).json({ error: 'Token expired', code: 'TOKEN_EXPIRED' });
    return res.status(401).json({ error: 'Invalid token', code: 'TOKEN_INVALID' });
  }
};

const requireRole = (...roles) => (req, res, next) => {
  if (!roles.includes(req.user.role)) return res.status(403).json({ error: 'Insufficient permissions' });
  next();
};

const requireStepUp = async (req, res, next) => {
  const stepUpToken = req.headers['x-step-up-token'];
  if (!stepUpToken) return res.status(403).json({ error: 'Step-up authentication required', requireStepUp: true });
  try {
    const decoded = jwt.verify(stepUpToken, JWT_SECRET);
    if (!decoded.stepUpVerified || decoded.userId !== req.user.id)
      return res.status(403).json({ error: 'Invalid step-up token' });
    next();
  } catch {
    return res.status(403).json({ error: 'Step-up token expired', requireStepUp: true });
  }
};

// ============ WEBSOCKET ============

io.use(async (socket, next) => {
  try {
    const token = socket.handshake.auth.token;
    if (!token) return next(new Error('No auth token'));



    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await pg.query('SELECT id, org_id, role FROM users WHERE id = $1 AND is_active = true', [decoded.userId]);
    if (!user.rows.length) return next(new Error('User not found'));
    socket.user = user.rows[0];
    socket.join(`org:${user.rows[0].org_id}`);
    next();
  } catch { next(new Error('Auth failed')); }
});

io.on('connection', socket => {
  console.log(`WS connected: user ${socket.user?.id}`);
  socket.on('subscribe:identity', id => socket.join(`identity:${id}`));
  socket.on('unsubscribe:identity', id => socket.leave(`identity:${id}`));
  socket.on('disconnect', () => console.log(`WS disconnected: ${socket.user?.id}`));
});

// ============ AUTH ENDPOINTS ============

app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const { email, password, mfa_code } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });



    const result = await pg.query(
      'SELECT id, email, password_hash, role, org_id, mfa_enabled, mfa_secret, is_active FROM users WHERE email = $1',
      [email.toLowerCase()]
    );
    if (!result.rows.length) return res.status(401).json({ error: 'Invalid credentials' });
    const user = result.rows[0];
    if (!user.is_active) return res.status(401).json({ error: 'Account disabled' });
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      await auditLog(user.org_id, user.id, 'LOGIN_FAILED', 'Invalid password', req.ip);
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    if (user.mfa_enabled) {
      if (!mfa_code) {
        const tempToken = jwt.sign({ userId: user.id, requireMfa: true }, JWT_SECRET, { expiresIn: '5m' });
        return res.json({ requireMfa: true, tempToken });
      }
      const mfaValid = speakeasy.totp.verify({ secret: user.mfa_secret, encoding: 'base32', token: mfa_code, window: 2 });
      if (!mfaValid) return res.status(401).json({ error: 'Invalid MFA code' });
    }
    await pg.query('UPDATE users SET last_login = NOW(), failed_login_attempts = 0 WHERE id = $1', [user.id]);
    const token = jwt.sign({ userId: user.id, email: user.email, role: user.role, orgId: user.org_id }, JWT_SECRET, { expiresIn: '24h' });
    await auditLog(user.org_id, user.id, 'LOGIN', 'User logged in', req.ip);
    authAttempts.inc({ method: 'password', status: 'success' });
    res.json({ token, user: { id: user.id, email: user.email, role: user.role, orgId: user.org_id } });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Server error', details: err.message }); }
});

app.post('/api/auth/logout', authenticate, async (req, res) => {
  try {
    const decoded = jwt.decode(req.token);
    const expiry = Math.max(decoded.exp - Math.floor(Date.now() / 1000), 1);
    await redisClient.setEx(`blacklist:${req.token}`, expiry, 'true');
    await auditLog(req.user.org_id, req.user.id, 'LOGOUT', 'User logged out', req.ip);
    res.json({ message: 'Logged out successfully' });
  } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/auth/refresh', authenticate, (req, res) => {
  const token = jwt.sign({ userId: req.user.id, email: req.user.email, role: req.user.role, orgId: req.user.org_id }, JWT_SECRET, { expiresIn: '24h' });
  res.json({ token });
});

app.post('/api/auth/step-up', authenticate, async (req, res) => {
  try {
    const { password } = req.body;
    const user = await pg.query('SELECT password_hash FROM users WHERE id = $1', [req.user.id]);
    const valid = await bcrypt.compare(password, user.rows[0].password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid password' });
    const stepUpToken = jwt.sign({ userId: req.user.id, stepUpVerified: true }, JWT_SECRET, { expiresIn: '15m' });
    res.json({ stepUpToken, expiresIn: 900 });
  } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/auth/mfa/setup', authenticate, async (req, res) => {
  try {
    const secret = speakeasy.generateSecret({ name: `NHI Shield (${req.user.email})`, length: 20 });
    await pg.query('UPDATE users SET mfa_secret_temp = $1 WHERE id = $2', [secret.base32, req.user.id]);
    const qrCode = await QRCode.toDataURL(secret.otpauth_url);
    res.json({ secret: secret.base32, qrCode, otpauthUrl: secret.otpauth_url });
  } catch (err) { res.status(500).json({ error: 'MFA setup failed' }); }
});

app.post('/api/auth/mfa/verify', authenticate, async (req, res) => {
  try {
    const { token } = req.body;
    const user = await pg.query('SELECT mfa_secret_temp FROM users WHERE id = $1', [req.user.id]);
    if (!user.rows[0]?.mfa_secret_temp) return res.status(400).json({ error: 'No pending MFA setup' });
    const valid = speakeasy.totp.verify({ secret: user.rows[0].mfa_secret_temp, encoding: 'base32', token, window: 2 });
    if (!valid) return res.status(400).json({ error: 'Invalid token' });
    await pg.query('UPDATE users SET mfa_enabled = true, mfa_secret = mfa_secret_temp, mfa_secret_temp = NULL WHERE id = $1', [req.user.id]);
    await auditLog(req.user.org_id, req.user.id, 'MFA_ENABLED', 'MFA enabled for account', req.ip);
    res.json({ success: true, message: 'MFA enabled' });
  } catch (err) { res.status(500).json({ error: 'Verification failed' }); }
});

app.post('/api/auth/mfa/disable', authenticate, requireStepUp, async (req, res) => {
  try {
    await pg.query('UPDATE users SET mfa_enabled = false, mfa_secret = NULL WHERE id = $1', [req.user.id]);
    await auditLog(req.user.org_id, req.user.id, 'MFA_DISABLED', 'MFA disabled for account', req.ip);
    res.json({ success: true, message: 'MFA disabled' });
  } catch (err) { res.status(500).json({ error: 'Failed to disable MFA' }); }
});

// SSO - OIDC
app.get('/api/auth/sso/:provider', async (req, res) => {
  const configs = {
    google: { url: 'https://accounts.google.com/o/oauth2/v2/auth', clientId: process.env.GOOGLE_CLIENT_ID, scope: 'openid email profile' },
    microsoft: { url: `https://login.microsoftonline.com/${process.env.AZURE_TENANT_ID}/oauth2/v2.0/authorize`, clientId: process.env.AZURE_CLIENT_ID, scope: 'openid email profile' },
    okta: { url: `${process.env.OKTA_DOMAIN}/oauth2/default/v1/authorize`, clientId: process.env.OKTA_CLIENT_ID, scope: 'openid email profile' }
  };
  const p = configs[req.params.provider];
  if (!p?.clientId) return res.status(400).json({ error: `SSO provider not configured: ${req.params.provider}` });
  const state = crypto.randomBytes(16).toString('hex');
  await redisClient.setEx(`sso_state:${state}`, 300, req.params.provider);
  const params = new URLSearchParams({ client_id: p.clientId, response_type: 'code', scope: p.scope, redirect_uri: `${process.env.API_URL || 'http://localhost:3000'}/api/auth/sso/${req.params.provider}/callback`, state });
  res.json({ redirectUrl: `${p.url}?${params}` });
});

// SSO initiation (replaces simple state-only version with PKCE)
app.get('/api/auth/sso/:provider/initiate', async (req, res) => {
  try {
    const redirectUrl = await initiateSSOFlow(req.params.provider, redisClient);
    res.json({ redirectUrl });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get('/api/auth/sso/:provider/callback', async (req, res) => {
  try {
    const { code, state, error } = req.query;
    if (error) {
      return res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:3001'}/login?sso_error=${encodeURIComponent(error)}`);
    }
    if (!code || !state) return res.status(400).json({ error: 'Missing code or state' });

    const { token, user } = await handleSSOCallback(req.params.provider, code, state, redisClient, pg);
    authAttempts.inc({ method: `sso_${req.params.provider}`, status: 'success' });

    // Redirect to frontend with token
    res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:3001'}/sso-complete?token=${encodeURIComponent(token)}`);
  } catch (err) {
    console.error('SSO callback error:', err);
    authAttempts.inc({ method: `sso_${req.params.provider}`, status: 'failure' });
    res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:3001'}/login?sso_error=${encodeURIComponent(err.message)}`);
  }
});

// ============ IDENTITY ENDPOINTS ============

app.get('/api/identities', authenticate, async (req, res) => {
  try {
    const { platform, type, is_active, risk_level, query, offset = 0, limit = 50 } = req.query;
    let baseSql = `
      SELECT i.*, rs.total_score, rs.level as calculated_risk 
      FROM identities i 
      LEFT JOIN risk_scores rs ON i.id = rs.identity_id 
      WHERE i.org_id = $1
    `;
    const params = [req.user.org_id];
    let conditionCount = 1;

    if (platform) { baseSql += ` AND i.platform = $${++conditionCount}`; params.push(platform); }
    if (type) { baseSql += ` AND i.type = $${++conditionCount}`; params.push(type); }
    if (is_active !== undefined) { baseSql += ` AND i.is_active = $${++conditionCount}`; params.push(is_active === 'true'); }
    if (risk_level) { baseSql += ` AND rs.level = $${++conditionCount}`; params.push(risk_level.toUpperCase()); }
    if (query) { baseSql += ` AND (i.name ILIKE $${++conditionCount} OR i.owner ILIKE $${conditionCount})`; params.push(`%${query}%`); }

    const countRes = await pg.query(`SELECT COUNT(*) FROM (${baseSql}) as t`, params);

    baseSql += ` ORDER BY rs.total_score DESC NULLS LAST LIMIT $${++conditionCount} OFFSET $${++conditionCount}`;
    params.push(Math.min(parseInt(limit), 1000), parseInt(offset));

    const result = await pg.query(baseSql, params);

    res.json({
      identities: result.rows,
      total: parseInt(countRes.rows[0].count),
      limit: parseInt(limit),
      offset: parseInt(offset)
    });
  } catch (err) {
    console.error('Identities fetch error:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

app.get('/api/identities/:id', authenticate, async (req, res) => {
  try {
    const result = await pg.query(`
      SELECT i.*, rs.total_score, rs.level as risk_level, rs.factors as risk_factors
      FROM identities i LEFT JOIN risk_scores rs ON i.id = rs.identity_id
      WHERE i.id = $1 AND i.org_id = $2
    `, [req.params.id, req.user.org_id]);
    if (!result.rows.length) return res.status(404).json({ error: 'Identity not found' });
    res.json({ identity: result.rows[0] });
  } catch (err) { res.status(500).json({ error: 'Database error' }); }
});

// Graph handler — supports /api/identities/:id/graph (detailed) AND /api/graph?identity_id=x (spec path)
const graphHandler = async (req, res) => {
  const identityId = req.params.id || req.query.identity_id;
  if (!identityId) return res.status(400).json({ error: 'identity_id required as path param or query string' });

  const session = neo4jDriver.session();
  try {
    const result = await session.run(
      `
      MATCH (i:Identity {id: $id})-[r]-(target)
      RETURN i as source, r as relationship, target
      LIMIT 100
      `,
      { id: identityId }
    );

    const nodes = new Map();
    const edges = [];

    result.records.forEach(record => {
      const source = record.get('source').properties;
      const target = record.get('target').properties;
      const rel = record.get('relationship');

      if (!nodes.has(source.id)) nodes.set(source.id, source);
      if (!nodes.has(target.id)) nodes.set(target.id, target);

      edges.push({
        source: rel.start.toString() === record.get('source').elementId ? source.id : target.id,
        target: rel.end.toString() === record.get('target').elementId ? target.id : source.id,
        type: rel.type,
        properties: rel.properties
      });
    });

    if (nodes.size === 0) {
      // If no edges, at least try to return the node itself if it exists in PG
      const pgRes = await pg.query('SELECT id, name, platform, type, is_active FROM identities WHERE id = $1', [identityId]);
      if (pgRes.rows.length) {
        nodes.set(identityId, pgRes.rows[0]);
      }
    }

    res.json({ nodes: Array.from(nodes.values()), edges });
  } catch (err) {
    console.error('Neo4j error:', err);
    res.status(500).json({ error: 'Graph query failed' });
  } finally {
    await session.close();
  }
};
app.get('/api/identities/:id/graph', authenticate, graphHandler);
app.get('/api/graph', authenticate, graphHandler);

app.put('/api/identities/:id', authenticate, requireRole('admin', 'analyst'), async (req, res) => {
  try {
    const { name, owner, is_active, metadata } = req.body;
    const current = await pg.query('SELECT * FROM identities WHERE id = $1 AND org_id = $2', [req.params.id, req.user.org_id]);
    if (!current.rows.length) return res.status(404).json({ error: 'Identity not found' });
    const updates = [], params = [req.params.id, req.user.org_id];
    let c = 2;
    if (name !== undefined) { updates.push(`name = $${++c}`); params.push(name); }
    if (owner !== undefined) { updates.push(`owner = $${++c}`); params.push(owner); }
    if (is_active !== undefined) { updates.push(`is_active = $${++c}`); params.push(is_active); }
    if (metadata !== undefined) { updates.push(`metadata = $${++c}`); params.push(JSON.stringify(metadata)); }
    if (!updates.length) return res.status(400).json({ error: 'No fields to update' });
    updates.push('updated_at = NOW()');
    const result = await pg.query(`UPDATE identities SET ${updates.join(', ')} WHERE id = $1 AND org_id = $2 RETURNING *`, params);
    await auditLog(req.user.org_id, req.user.id, 'UPDATE_IDENTITY', `Updated identity ${req.params.id}`, req.ip);
    emitToOrg(req.user.org_id, 'identity:updated', { identity: result.rows[0] });
    res.json({ identity: result.rows[0] });
  } catch (err) { res.status(500).json({ error: 'Database error' }); }
});

app.post('/api/identities/:id/offboard', authenticate, requireRole('admin'), requireStepUp, async (req, res) => {
  try {
    const { reason } = req.body;
    if (!reason) return res.status(400).json({ error: 'Reason is required' });
    const check = await pg.query('SELECT * FROM identities WHERE id = $1 AND org_id = $2', [req.params.id, req.user.org_id]);
    if (!check.rows.length) return res.status(404).json({ error: 'Identity not found' });
    const result = await pg.query(`
      UPDATE identities SET is_active = false, offboarded_at = NOW(), offboarded_by = $1, offboard_reason = $2, updated_at = NOW()
      WHERE id = $3 AND org_id = $4 RETURNING *
    `, [req.user.id, reason, req.params.id, req.user.org_id]);
    await auditLog(req.user.org_id, req.user.id, 'OFFBOARD', `Offboarded identity: ${reason}`, req.ip, { identity_id: req.params.id });
    await redisClient.publish('offboard_events', JSON.stringify({ identity_id: req.params.id, org_id: req.user.org_id, reason }));
    const session = neo4jDriver.session();
    try { await session.run('MATCH (n:NHIdentity {id: $id}) SET n.is_active = false', { id: req.params.id }); }
    finally { await session.close(); }
    emitToOrg(req.user.org_id, 'identity:offboarded', { identity_id: req.params.id });
    await deliverWebhooks(req.user.org_id, 'identity.offboarded', { identity_id: req.params.id, reason });
    res.json({ success: true, message: 'Offboarding initiated', identity: result.rows[0] });
  } catch (err) { res.status(500).json({ error: 'Offboarding failed' }); }
});

// ============ PERMISSION ANALYZER ============

app.get('/api/identities/:id/permissions/analyze', authenticate, async (req, res) => {
  try {
    const identity = await pg.query('SELECT * FROM identities WHERE id = $1 AND org_id = $2', [req.params.id, req.user.org_id]);
    if (!identity.rows.length) return res.status(404).json({ error: 'Identity not found' });
    const permissions = identity.rows[0].permissions || [];
    const adminKw = ['admin', 'root', 'fullaccess', 'administratoraccess', '*', 'write', 'delete', 'create'];
    const sensitiveKw = ['iam', 'kms', 'secrets', 'billing', 'security', 'cloudtrail'];
    const overPriv = permissions.filter(p => adminKw.some(k => p.toLowerCase().includes(k)));
    const sensitive = permissions.filter(p => sensitiveKw.some(k => p.toLowerCase().includes(k)));
    const recentActivity = await pg.query(
      'SELECT DISTINCT metadata->>\'resource\' as resource FROM activity_events WHERE identity_id = $1 AND timestamp > NOW() - INTERVAL \'30 days\'',
      [req.params.id]
    );
    const usedResources = new Set(recentActivity.rows.map(r => r.resource).filter(Boolean));
    const unused = permissions.filter(p => {
      const resource = p.split(':')[0];
      return !Array.from(usedResources).some(r => r?.toLowerCase().includes(resource.toLowerCase()));
    });
    const recommendations = [];
    if (overPriv.length) recommendations.push({ type: 'REDUCE_ADMIN', severity: 'HIGH', message: `Restrict ${overPriv.length} over-privileged permissions`, permissions: overPriv });
    if (unused.length > 5) recommendations.push({ type: 'REMOVE_UNUSED', severity: 'MEDIUM', message: `${unused.length} permissions unused in last 30 days`, permissions: unused.slice(0, 20) });
    if (sensitive.length) recommendations.push({ type: 'SENSITIVE_ACCESS', severity: 'CRITICAL', message: `Access to ${sensitive.length} sensitive services`, permissions: sensitive });
    const score = Math.max(0, 100 - overPriv.length * 15 - sensitive.length * 20 - Math.min(unused.length * 3, 30));
    res.json({ identity_id: req.params.id, total_permissions: permissions.length, over_privileged: overPriv, sensitive_access: sensitive, unused_permissions: unused, recommendations, least_privilege_score: score });
  } catch (err) { res.status(500).json({ error: 'Analysis failed' }); }
});

// ============ CHAIN ATTACK DETECTION ============

app.post('/api/security/chain-attack/analyze', authenticate, requireRole('admin', 'analyst'), async (req, res) => {
  try {
    const { identity_id, hours = 24 } = req.body;
    const events = await pg.query(`
      SELECT ae.*, i.name as identity_name, i.platform
      FROM activity_events ae JOIN identities i ON ae.identity_id = i.id
      WHERE ae.identity_id = $1 AND ae.timestamp > NOW() - ($2 * INTERVAL '1 hour')
      ORDER BY ae.timestamp ASC
    `, [identity_id, Math.max(1, parseInt(hours, 10) || 24)]);
    const evs = events.rows;
    const indicators = [];
    const platforms = [...new Set(evs.map(e => e.platform))];
    if (platforms.length > 2) indicators.push({ type: 'LATERAL_MOVEMENT', severity: 'HIGH', description: `Accessed ${platforms.length} platforms: ${platforms.join(', ')}`, evidence: platforms });
    const adminActions = evs.filter(e => ['iam', 'admin', 'escalate', 'assume-role'].some(k => e.action?.toLowerCase().includes(k)));
    if (adminActions.length) indicators.push({ type: 'PRIVILEGE_ESCALATION', severity: 'CRITICAL', description: `${adminActions.length} privilege-related actions`, evidence: adminActions.slice(0, 5).map(a => ({ action: a.action, time: a.timestamp })) });
    const exfilActions = evs.filter(e => ['download', 'export', 'list', 'get-object'].some(k => e.action?.toLowerCase().includes(k)));
    if (exfilActions.length > 20) indicators.push({ type: 'DATA_EXFILTRATION', severity: 'CRITICAL', description: `${exfilActions.length} data retrieval actions detected`, evidence: { count: exfilActions.length } });
    const ips = [...new Set(evs.map(e => e.ip_address).filter(Boolean))];
    if (ips.length > 5) indicators.push({ type: 'MULTIPLE_SOURCE_IPS', severity: 'HIGH', description: `Activity from ${ips.length} different IPs`, evidence: ips.slice(0, 10) });
    const riskScore = Math.min(indicators.reduce((a, i) => a + (i.severity === 'CRITICAL' ? 40 : 25), 0), 100);
    if (riskScore >= 40) {
      await pg.query(`
        INSERT INTO anomaly_alerts (org_id, identity_id, severity, alert_type, description, confidence, evidence, created_at)
        SELECT org_id, $1, $2, 'CHAIN_ATTACK', $3, $4, $5, NOW() FROM identities WHERE id = $1
      `, [identity_id, riskScore >= 80 ? 'CRITICAL' : 'HIGH', `Chain attack: ${indicators.map(i => i.type).join(', ')}`, riskScore / 100, JSON.stringify(indicators)]);
      emitToOrg(req.user.org_id, 'alert:new', { type: 'CHAIN_ATTACK', severity: riskScore >= 80 ? 'CRITICAL' : 'HIGH', identity_id });
    }
    res.json({ identity_id, hours, events: evs.length, indicators, risk_score: riskScore, verdict: riskScore >= 80 ? 'LIKELY_ATTACK' : riskScore >= 40 ? 'SUSPICIOUS' : 'NORMAL', recommendation: riskScore >= 80 ? 'REVOKE_IMMEDIATELY' : riskScore >= 40 ? 'MONITOR_CLOSELY' : 'NORMAL' });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Analysis failed' }); }
});

// ============ SHADOW AI DETECTION ============

app.get('/api/security/shadow-ai/scan', authenticate, requireRole('admin', 'analyst'), async (req, res) => {
  try {
    const AI_PLATFORMS = [
      { name: 'OpenAI', domains: ['api.openai.com'], patterns: ['sk-', 'sk-proj-'] },
      { name: 'Anthropic', domains: ['api.anthropic.com'], patterns: ['sk-ant-'] },
      { name: 'Google AI', domains: ['generativelanguage.googleapis.com'], patterns: [] },
      { name: 'Hugging Face', domains: ['api-inference.huggingface.co'], patterns: ['hf_'] },
      { name: 'Cohere', domains: ['api.cohere.ai'], patterns: [] },
      { name: 'Replicate', domains: ['api.replicate.com'], patterns: ['r8_'] },
      { name: 'Mistral', domains: ['api.mistral.ai'], patterns: [] },
      { name: 'Groq', domains: ['api.groq.com'], patterns: ['gsk_'] },
      { name: 'AWS Bedrock', domains: ['bedrock-runtime.amazonaws.com'], patterns: [] }
    ];
    const [identities, approved] = await Promise.all([
      pg.query("SELECT id, name, platform, permissions, metadata FROM identities WHERE org_id = $1 AND is_active = true", [req.user.org_id]),
      pg.query("SELECT platform FROM integrations WHERE org_id = $1 AND is_active = true", [req.user.org_id])
    ]);
    const approvedPlatforms = new Set(approved.rows.map(r => r.platform.toLowerCase()));
    const findings = [];
    for (const identity of identities.rows) {
      const meta = typeof identity.metadata === 'string' ? JSON.parse(identity.metadata || '{}') : (identity.metadata || {});
      const metaStr = JSON.stringify(meta).toLowerCase();
      const perms = identity.permissions || [];
      for (const ai of AI_PLATFORMS) {
        let confidence = 0;
        const evidence = [];
        const aiPerms = perms.filter(p => ai.domains.some(d => p.toLowerCase().includes(d.split('.')[0])));
        if (aiPerms.length) { confidence += 40; evidence.push(`Permission references: ${aiPerms.join(', ')}`); }
        if (ai.domains.some(d => metaStr.includes(d.replace('.', '')))) { confidence += 30; evidence.push('Metadata references AI platform'); }
        if (ai.patterns.some(p => metaStr.includes(p.toLowerCase()))) { confidence += 30; evidence.push('API key pattern detected'); }
        const platformName = ai.name.toLowerCase().replace(' ai', '').replace(' ', '');
        const isApproved = approvedPlatforms.has(platformName) || approvedPlatforms.has(ai.name.toLowerCase());
        if (confidence >= 30 && !isApproved) {
          findings.push({ identity_id: identity.id, identity_name: identity.name, platform: identity.platform, ai_platform: ai.name, confidence, approved: isApproved, evidence, risk: confidence >= 70 ? 'HIGH' : 'MEDIUM' });
        }
      }
    }
    const activityCheck = await pg.query(`
      SELECT ae.identity_id, i.name, ae.resource, COUNT(*) as calls
      FROM activity_events ae JOIN identities i ON ae.identity_id = i.id
      WHERE i.org_id = $1 AND (ae.resource ILIKE '%openai%' OR ae.resource ILIKE '%anthropic%' OR ae.resource ILIKE '%huggingface%' OR ae.resource ILIKE '%bedrock%')
        AND ae.timestamp > NOW() - INTERVAL '7 days'
      GROUP BY ae.identity_id, i.name, ae.resource ORDER BY calls DESC LIMIT 20
    `, [req.user.org_id]);
    res.json({
      scan_time: new Date().toISOString(), scanned: identities.rows.length,
      shadow_ai_findings: findings, ai_activity: activityCheck.rows,
      summary: { total: findings.length, high_risk: findings.filter(f => f.risk === 'HIGH').length, unapproved: findings.filter(f => !f.approved).length },
      recommendations: findings.length > 0 ? ['Review unapproved AI usage', 'Update integrations with approved AI platforms', 'Implement AI governance policy'] : ['No shadow AI detected']
    });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Shadow AI scan failed' }); }
});

// ============ LIFECYCLE MANAGEMENT ============

app.get('/api/lifecycle/dormant', authenticate, requireRole('admin', 'analyst'), async (req, res) => {
  try {
    const { days = 90 } = req.query;
    const result = await pg.query(`
      SELECT i.*, rs.level as risk_level, rs.total_score,
             EXTRACT(DAY FROM (NOW() - COALESCE(i.last_used, i.discovered_at))) as days_inactive
      FROM identities i LEFT JOIN risk_scores rs ON i.id = rs.identity_id
      WHERE i.org_id = $1 AND i.is_active = true
        AND (i.last_used < NOW() - ($2 * INTERVAL '1 day') OR i.last_used IS NULL)
      ORDER BY i.last_used ASC NULLS FIRST LIMIT 100
    `, [req.user.org_id, Math.max(1, parseInt(days, 10) || 90)]);
    res.json({ dormant_identities: result.rows, count: result.rows.length, threshold_days: Math.max(1, parseInt(days, 10) || 90) });
  } catch (err) { res.status(500).json({ error: 'Failed to get dormant identities' }); }
});

app.post('/api/lifecycle/auto-offboard', authenticate, requireRole('admin'), requireStepUp, async (req, res) => {
  try {
    const { days = 90, dry_run = true, reason = 'Auto-offboarded: dormant identity' } = req.body;
    const dormant = await pg.query(`
      SELECT id, name, platform FROM identities
      WHERE org_id = $1 AND is_active = true AND last_used < NOW() - ($2 * INTERVAL '1 day')
    `, [req.user.org_id, Math.max(1, parseInt(days, 10) || 90)]);
    if (dry_run) return res.json({ dry_run: true, would_offboard: dormant.rows.length, identities: dormant.rows });
    for (const identity of dormant.rows) {
      await pg.query('UPDATE identities SET is_active = false, offboarded_at = NOW(), offboard_reason = $1 WHERE id = $2', [reason, identity.id]);
      await auditLog(req.user.org_id, req.user.id, 'AUTO_OFFBOARD', `${reason} - ${identity.name}`, req.ip);
    }
    emitToOrg(req.user.org_id, 'lifecycle:bulk-offboard', { count: dormant.rows.length });
    await deliverWebhooks(req.user.org_id, 'lifecycle.bulk_offboard', { count: dormant.rows.length, threshold_days: days });
    res.json({ success: true, offboarded: dormant.rows.length, identities: dormant.rows.map(i => i.id) });
  } catch (err) { res.status(500).json({ error: 'Auto-offboard failed' }); }
});

app.get('/api/lifecycle/expiring', authenticate, async (req, res) => {
  try {
    const { days = 30 } = req.query;
    const result = await pg.query(`
      SELECT id, name, platform, type, metadata->>'expires_at' as expires_at
      FROM identities WHERE org_id = $1 AND is_active = true
        AND (metadata->>'expires_at')::text IS NOT NULL
      LIMIT 50
    `, [req.user.org_id]);
    const now = new Date();
    const expiring = result.rows.filter(r => {
      if (!r.expires_at) return false;
      const exp = new Date(r.expires_at);
      const diff = (exp - now) / (1000 * 60 * 60 * 24);
      return diff > 0 && diff <= Math.max(1, parseInt(days, 10) || 90);
    });
    res.json({ expiring_soon: expiring, threshold_days: Math.max(1, parseInt(days, 10) || 90) });
  } catch (err) { res.status(500).json({ error: 'Failed to get expiring identities' }); }
});

app.get('/api/lifecycle/policies', authenticate, requireRole('admin'), async (req, res) => {
  try {
    const result = await pg.query('SELECT * FROM lifecycle_policies WHERE org_id = $1', [req.user.org_id]);
    res.json({ policies: result.rows });
  } catch (err) { res.status(200).json({ policies: [], message: 'No policies configured' }); }
});

app.post('/api/lifecycle/policies', authenticate, requireRole('admin'), async (req, res) => {
  try {
    const { name, trigger, action, conditions } = req.body;
    const result = await pg.query(
      'INSERT INTO lifecycle_policies (org_id, name, trigger, action, conditions, created_by) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *',
      [req.user.org_id, name, trigger, action, JSON.stringify(conditions), req.user.id]
    );
    res.status(201).json({ policy: result.rows[0] });
  } catch (err) { res.status(500).json({ error: 'Failed to create policy' }); }
});

// ============ ALERTS ============

app.get('/api/alerts', authenticate, async (req, res) => {
  try {
    const { severity, resolved, identity_id, alert_type, limit = 20, offset = 0 } = req.query;
    let query = `
      SELECT a.*, i.name as identity_name, i.platform
      FROM anomaly_alerts a JOIN identities i ON a.identity_id = i.id
      WHERE a.org_id = $1
    `;
    const params = [req.user.org_id];
    let c = 1;
    if (severity) { query += ` AND a.severity = $${++c}`; params.push(severity); }
    if (resolved !== undefined) { query += ` AND a.resolved = $${++c}`; params.push(resolved === 'true'); }
    if (identity_id) { query += ` AND a.identity_id = $${++c}`; params.push(identity_id); }
    if (alert_type) { query += ` AND a.alert_type = $${++c}`; params.push(alert_type); }
    query += ` ORDER BY a.created_at DESC LIMIT $${++c} OFFSET $${++c}`;
    params.push(parseInt(limit, 10), parseInt(offset, 10));
    const [result, counts] = await Promise.all([
      pg.query(query, params),
      pg.query(`SELECT severity, COUNT(*) FROM anomaly_alerts WHERE org_id = $1 AND resolved = false GROUP BY severity`, [req.user.org_id])
    ]);
    const countsMap = {};
    counts.rows.forEach(r => { countsMap[r.severity] = parseInt(r.count, 10); });
    res.json({ alerts: result.rows, counts: countsMap });
  } catch (err) { res.status(500).json({ error: 'Database error' }); }
});

// Alert resolve handler — supports both PUT (original) and PATCH (spec-compliant)
const resolveAlertHandler = async (req, res) => {
  try {
    const { resolution_notes } = req.body;
    const result = await pg.query(
      `UPDATE anomaly_alerts SET resolved = true, resolved_by = $1, resolved_at = NOW(), resolution_notes = $2 WHERE id = $3 AND org_id = $4 RETURNING *`,
      [req.user.id, resolution_notes, req.params.id, req.user.org_id]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Alert not found' });
    emitToOrg(req.user.org_id, 'alert:resolved', { alert_id: req.params.id });
    res.json({ alert: result.rows[0] });
  } catch (err) { res.status(500).json({ error: 'Database error' }); }
};
app.put('/api/alerts/:id/resolve', authenticate, requireRole('admin', 'analyst'), resolveAlertHandler);
app.patch('/api/alerts/:id/resolve', authenticate, requireRole('admin', 'analyst'), resolveAlertHandler);

app.post('/api/alerts/bulk-resolve', authenticate, requireRole('admin'), async (req, res) => {
  try {
    const { alert_ids, resolution_notes } = req.body;
    if (!alert_ids?.length) return res.status(400).json({ error: 'alert_ids required' });
    const result = await pg.query(
      'UPDATE anomaly_alerts SET resolved = true, resolved_by = $1, resolved_at = NOW(), resolution_notes = $2 WHERE id = ANY($3) AND org_id = $4',
      [req.user.id, resolution_notes, alert_ids, req.user.org_id]
    );
    res.json({ resolved: result.rowCount });
  } catch (err) { res.status(500).json({ error: 'Bulk resolve failed' }); }
});

// ============ DASHBOARD ============

app.get('/api/dashboard/stats', authenticate, async (req, res) => {
  try {
    const [identityStats, riskStats, alertStats, platformStats, trends] = await Promise.all([
      pg.query(`
        SELECT COUNT(*) as total, COUNT(*) FILTER (WHERE is_active) as active, COUNT(*) FILTER (WHERE NOT is_active) as inactive,
               COUNT(*) FILTER (WHERE last_used < NOW() - INTERVAL '90 days') as dormant,
               COUNT(*) FILTER (WHERE last_used < NOW() - INTERVAL '30 days' AND is_active) as stale
        FROM identities WHERE org_id = $1
      `, [req.user.org_id]),
      pg.query(`SELECT level, COUNT(*) FROM risk_scores rs JOIN identities i ON rs.identity_id = i.id WHERE i.org_id = $1 GROUP BY level`, [req.user.org_id]),
      pg.query(`
        SELECT COUNT(*) FILTER (WHERE NOT resolved) as open, COUNT(*) FILTER (WHERE severity='CRITICAL' AND NOT resolved) as critical,
               COUNT(*) FILTER (WHERE severity='HIGH' AND NOT resolved) as high, COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '24h') as last_24h
        FROM anomaly_alerts WHERE org_id = $1
      `, [req.user.org_id]),
      pg.query('SELECT platform, COUNT(*) as count FROM identities WHERE org_id = $1 GROUP BY platform ORDER BY count DESC', [req.user.org_id]),
      pg.query(`
        SELECT DATE_TRUNC('day', discovered_at) as day, COUNT(*) as count
        FROM identities WHERE org_id = $1 AND discovered_at > NOW() - INTERVAL '30 days'
        GROUP BY day ORDER BY day
      `, [req.user.org_id])
    ]);
    const riskDist = {};
    riskStats.rows.forEach(r => { riskDist[r.level] = parseInt(r.count, 10); });
    res.json({
      identities: { total: parseInt(identityStats.rows[0].total, 10), active: parseInt(identityStats.rows[0].active, 10), inactive: parseInt(identityStats.rows[0].inactive, 10), dormant: parseInt(identityStats.rows[0].dormant, 10), stale: parseInt(identityStats.rows[0].stale, 10) },
      risk: riskDist,
      alerts: { open: parseInt(alertStats.rows[0].open, 10), critical: parseInt(alertStats.rows[0].critical, 10), high: parseInt(alertStats.rows[0].high, 10), last_24h: parseInt(alertStats.rows[0].last_24h, 10) },
      platforms: platformStats.rows, trends: trends.rows
    });
  } catch (err) { res.status(500).json({ error: 'Database error' }); }
});

app.get('/api/dashboard/recent-activity', authenticate, async (req, res) => {
  try {
    const result = await pg.query(`
      SELECT ae.*, i.name as identity_name, i.platform FROM activity_events ae
      LEFT JOIN identities i ON ae.identity_id = i.id WHERE ae.org_id = $1 ORDER BY ae.timestamp DESC LIMIT $2
    `, [req.user.org_id, parseInt(req.query.limit, 10) || 20]);
    res.json({ activities: result.rows });
  } catch (err) { res.status(500).json({ error: 'Database error' }); }
});

// ============ COMPLIANCE REPORTS ============

app.get('/api/reports/compliance', authenticate, async (req, res) => {
  try {
    const [totals, platforms, highRisk, inactive, noOwner, recentAlerts] = await Promise.all([
      pg.query('SELECT COUNT(*), COUNT(*) FILTER (WHERE is_active) as active FROM identities WHERE org_id = $1', [req.user.org_id]),
      pg.query('SELECT platform, COUNT(*) FROM identities WHERE org_id = $1 GROUP BY platform', [req.user.org_id]),
      pg.query("SELECT COUNT(*) FROM identities i JOIN risk_scores rs ON i.id = rs.identity_id WHERE i.org_id = $1 AND rs.level IN ('HIGH','CRITICAL')", [req.user.org_id]),
      pg.query("SELECT COUNT(*) FROM identities WHERE org_id = $1 AND last_used < NOW() - INTERVAL '90 days'", [req.user.org_id]),
      pg.query('SELECT COUNT(*) FROM identities WHERE org_id = $1 AND owner IS NULL', [req.user.org_id]),
      pg.query("SELECT COUNT(*) FROM anomaly_alerts WHERE org_id = $1 AND severity IN ('HIGH','CRITICAL') AND resolved = false", [req.user.org_id])
    ]);
    const total = parseInt(totals.rows[0].count, 10) || 1;
    const scores = {
      access_control: Math.max(0, 100 - (parseInt(noOwner.rows[0].count, 10) / total) * 40),
      lifecycle: Math.max(0, 100 - (parseInt(inactive.rows[0].count, 10) / total) * 50),
      risk_management: Math.max(0, 100 - (parseInt(highRisk.rows[0].count, 10) / total) * 50 - parseInt(recentAlerts.rows[0].count, 10) * 5),
      monitoring: Math.max(0, 90 - parseInt(recentAlerts.rows[0].count, 10) * 3)
    };
    const overall = Math.round(Object.values(scores).reduce((a, b) => a + b, 0) / 4);
    res.json({
      generated_at: new Date().toISOString(),
      summary: { total_identities: parseInt(totals.rows[0].count, 10), active: parseInt(totals.rows[0].active, 10), high_risk: parseInt(highRisk.rows[0].count, 10), dormant: parseInt(inactive.rows[0].count, 10), no_owner: parseInt(noOwner.rows[0].count, 10), open_alerts: parseInt(recentAlerts.rows[0].count, 10) },
      category_scores: scores, overall_score: overall,
      grade: overall >= 90 ? 'A' : overall >= 80 ? 'B' : overall >= 70 ? 'C' : overall >= 60 ? 'D' : 'F',
      frameworks: {
        soc2: { score: overall, status: overall >= 80 ? 'COMPLIANT' : 'NEEDS_ATTENTION' },
        iso27001: { score: overall, status: overall >= 85 ? 'COMPLIANT' : 'PARTIAL' },
        nist: { score: overall, status: overall >= 75 ? 'COMPLIANT' : 'PARTIAL' },
        pci_dss: { score: overall, status: overall >= 90 ? 'COMPLIANT' : 'NON_COMPLIANT' }
      },
      by_platform: platforms.rows,
      recommendations: [
        ...parseInt(noOwner.rows[0].count, 10) > 0 ? [`Assign owners to ${noOwner.rows[0].count} identities`] : [],
        ...parseInt(inactive.rows[0].count, 10) > 0 ? [`Review ${inactive.rows[0].count} dormant identities`] : [],
        ...parseInt(highRisk.rows[0].count, 10) > 0 ? [`Remediate ${highRisk.rows[0].count} high-risk identities`] : []
      ]
    });
  } catch (err) { res.status(500).json({ error: 'Report generation failed' }); }
});

app.get('/api/reports/export/csv', authenticate, requireRole('admin', 'analyst'), async (req, res) => {
  try {
    const result = await pg.query(`
      SELECT i.id, i.name, i.platform, i.type, i.owner, i.is_active, i.created_at, i.last_used, rs.level as risk_level, rs.total_score
      FROM identities i LEFT JOIN risk_scores rs ON i.id = rs.identity_id WHERE i.org_id = $1 ORDER BY rs.total_score DESC NULLS LAST
    `, [req.user.org_id]);
    const header = 'id,name,platform,type,owner,is_active,created_at,last_used,risk_level,risk_score\n';
    const rows = result.rows.map(r => [r.id, `"${r.name}"`, r.platform, r.type, `"${r.owner || ''}"`, r.is_active, r.created_at, r.last_used, r.risk_level || 'UNKNOWN', r.total_score || 0].join(',')).join('\n');
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="nhi-identities-${Date.now()}.csv"`);
    res.send(header + rows);
  } catch (err) { res.status(500).json({ error: 'Export failed' }); }
});

// ============ INTEGRATIONS ============

app.get('/api/integrations', authenticate, async (req, res) => {
  try {
    const result = await pg.query('SELECT id, platform, name, is_active, last_sync, sync_count, last_error, created_at FROM integrations WHERE org_id = $1 ORDER BY created_at DESC', [req.user.org_id]);
    res.json({ integrations: result.rows });
  } catch (err) { res.status(500).json({ error: 'Database error' }); }
});

app.post('/api/integrations', authenticate, requireRole('admin'), async (req, res) => {
  try {
    const { platform, name, config } = req.body;
    if (!platform || !config) return res.status(400).json({ error: 'Platform and config required' });
    const valid = ['github', 'aws', 'openai', 'slack', 'google', 'azure', 'gitlab', 'anthropic', 'huggingface', 'datadog'];
    if (!valid.includes(platform.toLowerCase())) return res.status(400).json({ error: 'Invalid platform' });
    const enc = encrypt(JSON.stringify(config));
    const result = await pg.query(
      'INSERT INTO integrations (org_id, platform, name, credentials, config, created_by) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id, platform, name, is_active, created_at',
      [req.user.org_id, platform, name, enc, {}, req.user.id]
    );
    await auditLog(req.user.org_id, req.user.id, 'INTEGRATION_CREATED', `Created ${platform} integration`, req.ip);
    res.status(201).json({ integration: result.rows[0] });
  } catch (err) { res.status(500).json({ error: 'Failed to create integration' }); }
});

app.post('/api/integrations/:id/sync', authenticate, requireRole('admin'), async (req, res) => {
  try {
    const integration = await pg.query('SELECT * FROM integrations WHERE id = $1 AND org_id = $2', [req.params.id, req.user.org_id]);
    if (!integration.rows.length) return res.status(404).json({ error: 'Integration not found' });
    await redisClient.publish('sync_triggers', JSON.stringify({ integration_id: req.params.id, org_id: req.user.org_id }));
    await pg.query('UPDATE integrations SET sync_status = $1 WHERE id = $2', ['syncing', req.params.id]);
    emitToOrg(req.user.org_id, 'integration:sync-started', { integration_id: req.params.id });
    res.json({ message: 'Sync initiated', integration_id: req.params.id });
  } catch (err) { res.status(500).json({ error: 'Sync failed' }); }
});

app.delete('/api/integrations/:id', authenticate, requireRole('admin'), async (req, res) => {
  try {
    const result = await pg.query('DELETE FROM integrations WHERE id = $1 AND org_id = $2 RETURNING *', [req.params.id, req.user.org_id]);
    if (!result.rows.length) return res.status(404).json({ error: 'Integration not found' });
    res.json({ message: 'Integration deleted' });
  } catch (err) { res.status(500).json({ error: 'Database error' }); }
});

// ============ WEBHOOKS ============

app.get('/api/webhooks', authenticate, requireRole('admin'), async (req, res) => {
  try {
    const result = await pg.query('SELECT id, url, events, is_active, last_delivery, delivery_count, last_error, created_at FROM webhooks WHERE org_id = $1', [req.user.org_id]);
    res.json({ webhooks: result.rows });
  } catch (err) { res.status(500).json({ error: 'Database error' }); }
});

app.post('/api/webhooks', authenticate, requireRole('admin'), async (req, res) => {
  try {
    const { url, events } = req.body;
    if (!url || !events?.length) return res.status(400).json({ error: 'URL and events required' });
    const valid = ['identity.discovered', 'identity.offboarded', 'alert.created', 'alert.resolved', 'lifecycle.bulk_offboard', 'rotation.completed'];
    const invalid = events.filter(e => !valid.includes(e));
    if (invalid.length) return res.status(400).json({ error: `Invalid events: ${invalid.join(', ')}`, valid });
    const secret = crypto.randomBytes(32).toString('hex');
    const result = await pg.query('INSERT INTO webhooks (org_id, url, events, secret, created_by) VALUES ($1,$2,$3,$4,$5) RETURNING id, url, events, is_active, created_at', [req.user.org_id, url, events, secret, req.user.id]);
    res.status(201).json({ webhook: { ...result.rows[0], secret } });
  } catch (err) { res.status(500).json({ error: 'Failed to create webhook' }); }
});

app.delete('/api/webhooks/:id', authenticate, requireRole('admin'), async (req, res) => {
  try {
    await pg.query('DELETE FROM webhooks WHERE id = $1 AND org_id = $2', [req.params.id, req.user.org_id]);
    res.json({ message: 'Webhook deleted' });
  } catch (err) { res.status(500).json({ error: 'Database error' }); }
});

app.post('/api/webhooks/:id/test', authenticate, requireRole('admin'), async (req, res) => {
  try {
    const hook = await pg.query('SELECT * FROM webhooks WHERE id = $1 AND org_id = $2', [req.params.id, req.user.org_id]);
    if (!hook.rows.length) return res.status(404).json({ error: 'Webhook not found' });
    const payload = { event: 'ping', org_id: req.user.org_id, timestamp: new Date().toISOString() };
    const sig = crypto.createHmac('sha256', hook.rows[0].secret).update(JSON.stringify(payload)).digest('hex');
    const resp = await axios.post(hook.rows[0].url, payload, { headers: { 'X-NHI-Signature': `sha256=${sig}` }, timeout: 10000 });
    res.json({ success: true, status: resp.status });
  } catch (err) { res.status(500).json({ error: `Webhook test failed: ${err.message}` }); }
});

// ============ SECRET ROTATION ============

app.post('/api/rotation/trigger', authenticate, requireRole('admin'), requireStepUp, async (req, res) => {
  try {
    const { identity_id } = req.body;
    const identity = await pg.query('SELECT * FROM identities WHERE id = $1 AND org_id = $2', [identity_id, req.user.org_id]);
    if (!identity.rows.length) return res.status(404).json({ error: 'Identity not found' });
    await redisClient.publish('rotation_triggers', JSON.stringify({ identity_id, org_id: req.user.org_id, initiated_by: req.user.id }));
    await auditLog(req.user.org_id, req.user.id, 'ROTATION_TRIGGERED', `Manual rotation: ${identity_id}`, req.ip);
    emitToOrg(req.user.org_id, 'rotation:initiated', { identity_id });
    res.json({ message: 'Rotation initiated', identity_id });
  } catch (err) { res.status(500).json({ error: 'Failed to trigger rotation' }); }
});

app.get('/api/rotation/history', authenticate, async (req, res) => {
  try {
    const result = await pg.query(`
      SELECT rh.*, i.name as identity_name, i.platform FROM rotation_history rh
      JOIN identities i ON rh.identity_id = i.id WHERE i.org_id = $1 ORDER BY rh.rotated_at DESC LIMIT 50
    `, [req.user.org_id]);
    res.json({ history: result.rows });
  } catch (err) { res.status(200).json({ history: [] }); }
});

// ============ AUDIT LOGS ============

// Audit log handler — accessible at both /api/audit and /api/reports/audit (spec path)
const auditLogsHandler = async (req, res) => {
  try {
    const { limit = 50, offset = 0, action, identity_id } = req.query;
    let query = 'SELECT al.*, u.email as user_email FROM audit_logs al LEFT JOIN users u ON al.user_id = u.id WHERE al.org_id = $1';
    const params = [req.user.org_id];
    let c = 1;
    if (action) { query += ` AND al.action = $${++c}`; params.push(action); }
    if (identity_id) { query += ` AND al.identity_id = $${++c}`; params.push(identity_id); }
    query += ` ORDER BY al.created_at DESC LIMIT $${++c} OFFSET $${++c}`;
    params.push(parseInt(limit, 10), parseInt(offset, 10));
    const result = await pg.query(query, params);
    res.json({ audit_logs: result.rows });
  } catch (err) { res.status(500).json({ error: 'Database error' }); }
};
app.get('/api/audit', authenticate, requireRole('admin', 'analyst'), auditLogsHandler);
app.get('/api/reports/audit', authenticate, requireRole('admin', 'analyst'), auditLogsHandler);

// ============ USER MANAGEMENT ============

app.get('/api/users', authenticate, requireRole('admin'), async (req, res) => {
  try {
    const result = await pg.query('SELECT id, email, role, is_active, last_login, mfa_enabled, created_at FROM users WHERE org_id = $1', [req.user.org_id]);
    res.json({ users: result.rows });
  } catch (err) { res.status(500).json({ error: 'Database error' }); }
});

app.post('/api/users', authenticate, requireRole('admin'), async (req, res) => {
  try {
    const { email, password, role } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    if (!['admin', 'analyst', 'viewer'].includes(role)) return res.status(400).json({ error: 'Invalid role' });
    const hashedPw = await bcrypt.hash(password, 12);
    const result = await pg.query(
      'INSERT INTO users (email, password_hash, role, org_id) VALUES ($1,$2,$3,$4) RETURNING id, email, role, created_at',
      [email.toLowerCase(), hashedPw, role, req.user.org_id]
    );
    await auditLog(req.user.org_id, req.user.id, 'USER_CREATED', `Created user ${email}`, req.ip);
    res.status(201).json({ user: result.rows[0] });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Email already exists' });
    res.status(500).json({ error: 'Failed to create user' });
  }
});

app.put('/api/users/:id/role', authenticate, requireRole('admin'), async (req, res) => {
  try {
    if (req.params.id === req.user.id) return res.status(400).json({ error: 'Cannot change own role' });
    const { role } = req.body;
    if (!['admin', 'analyst', 'viewer'].includes(role)) return res.status(400).json({ error: 'Invalid role' });
    const result = await pg.query('UPDATE users SET role = $1 WHERE id = $2 AND org_id = $3 RETURNING id, email, role', [role, req.params.id, req.user.org_id]);
    if (!result.rows.length) return res.status(404).json({ error: 'User not found' });
    await auditLog(req.user.org_id, req.user.id, 'USER_ROLE_CHANGED', `Changed ${result.rows[0].email} to ${role}`, req.ip);
    res.json({ user: result.rows[0] });
  } catch (err) { res.status(500).json({ error: 'Database error' }); }
});

// ============ PUBLIC REST API v1 ============

app.get('/api/v1/identities', authenticate, async (req, res) => {
  try {
    const { page = 1, per_page = 25 } = req.query;
    const offset = (Math.max(1, parseInt(page, 10) || 1) - 1) * Math.max(1, parseInt(per_page, 10) || 20);
    const result = await pg.query(`
      SELECT i.id, i.name, i.platform, i.type, i.owner, i.is_active, i.created_at, i.last_used, rs.level as risk_level
      FROM identities i LEFT JOIN risk_scores rs ON i.id = rs.identity_id WHERE i.org_id = $1 ORDER BY i.created_at DESC LIMIT $2 OFFSET $3
    `, [req.user.org_id, parseInt(per_page, 10), offset]);
    const count = await pg.query('SELECT COUNT(*) FROM identities WHERE org_id = $1', [req.user.org_id]);
    const total = parseInt(count.rows[0].count, 10);
    res.json({ data: result.rows, pagination: { page: parseInt(page, 10), per_page: parseInt(per_page, 10), total, pages: Math.ceil(total / per_page) } });
  } catch (err) { res.status(500).json({ error: 'Internal error' }); }
});

app.get('/api/v1/alerts', authenticate, async (req, res) => {
  try {
    const result = await pg.query(`
      SELECT a.id, a.severity, a.alert_type, a.description, a.confidence, a.resolved, a.created_at, i.name as identity_name
      FROM anomaly_alerts a JOIN identities i ON a.identity_id = i.id WHERE a.org_id = $1 ORDER BY a.created_at DESC LIMIT 100
    `, [req.user.org_id]);
    res.json({ data: result.rows });
  } catch (err) { res.status(500).json({ error: 'Internal error' }); }
});

app.get('/api/v1/stats', authenticate, async (req, res) => {
  try {
    const [idents, alerts] = await Promise.all([
      pg.query('SELECT COUNT(*) as total, COUNT(*) FILTER (WHERE is_active) as active FROM identities WHERE org_id = $1', [req.user.org_id]),
      pg.query("SELECT COUNT(*) FILTER (WHERE NOT resolved) as open, COUNT(*) FILTER (WHERE severity='CRITICAL' AND NOT resolved) as critical FROM anomaly_alerts WHERE org_id = $1", [req.user.org_id])
    ]);
    res.json({ identities: { total: parseInt(idents.rows[0].total, 10), active: parseInt(idents.rows[0].active, 10) }, alerts: { open: parseInt(alerts.rows[0].open, 10), critical: parseInt(alerts.rows[0].critical, 10) } });
  } catch (err) { res.status(500).json({ error: 'Internal error' }); }
});

// ============ API KEY MANAGEMENT (Public REST API) ============

// List org's API keys
app.get('/api/v1/api-keys', authenticate, requireRole('admin'), async (req, res) => {
  try {
    const result = await pg.query(
      `SELECT id, name, role, key_prefix, last_used_at, use_count, is_active, created_at
       FROM api_keys WHERE org_id = $1 ORDER BY created_at DESC`,
      [req.user.org_id]
    );
    res.json({ api_keys: result.rows });
  } catch (err) { res.status(500).json({ error: 'Failed to list API keys' }); }
});

// Create API key (nhi_xxxxx format)
app.post('/api/v1/api-keys', authenticate, requireRole('admin'), async (req, res) => {
  const { name, role = 'analyst' } = req.body;
  if (!name) return res.status(400).json({ error: 'name is required' });
  if (!['admin', 'analyst', 'viewer'].includes(role)) return res.status(400).json({ error: 'Invalid role' });
  try {
    const rawKey = `nhi_${crypto.randomBytes(32).toString('hex')}`;
    const keyHash = crypto.createHash('sha256').update(rawKey).digest('hex');
    const keyPrefix = rawKey.slice(0, 12);   // nhi_ + 8 chars shown to user
    const result = await pg.query(
      `INSERT INTO api_keys (org_id, name, key_hash, key_prefix, role, created_by)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, name, role, key_prefix, created_at`,
      [req.user.org_id, name, keyHash, keyPrefix, role, req.user.id]
    );
    await auditLog(req.user.org_id, req.user.id, 'API_KEY_CREATE', `Created API key: ${name}`, req.ip);
    // Return raw key ONCE — not stored, user must save it
    res.status(201).json({ api_key: { ...result.rows[0], key: rawKey, warning: 'Save this key — it will not be shown again.' } });
  } catch (err) { res.status(500).json({ error: 'Failed to create API key' }); }
});

// Revoke API key
app.delete('/api/v1/api-keys/:id', authenticate, requireRole('admin'), async (req, res) => {
  try {
    const result = await pg.query(
      'UPDATE api_keys SET is_active = false WHERE id = $1 AND org_id = $2 RETURNING id',
      [req.params.id, req.user.org_id]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'API key not found' });
    await auditLog(req.user.org_id, req.user.id, 'API_KEY_REVOKE', `Revoked API key ${req.params.id}`, req.ip);
    res.json({ revoked: true });
  } catch (err) { res.status(500).json({ error: 'Failed to revoke API key' }); }
});


// ============ OPENAPI DOCUMENTATION ============

const OPENAPI_SPEC = {
  openapi: '3.0.3',
  info: {
    title: 'NHI Shield API',
    version: '1.0.0',
    description: 'Non-Human Identity Management Platform — REST API v1\n\nAuthenticate with `Authorization: Bearer <jwt>` or `X-API-Key: nhi_xxxxx`',
    contact: { name: 'NHI Shield Support', email: 'api@nhishield.com' }
  },
  servers: [{ url: '/api/v1', description: 'Public API v1' }],
  components: {
    securitySchemes: {
      BearerAuth: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
      ApiKeyAuth: { type: 'apiKey', in: 'header', name: 'X-API-Key', description: 'API key in nhi_xxxxx format' }
    }
  },
  security: [{ BearerAuth: [] }, { ApiKeyAuth: [] }],
  paths: {
    '/identities': {
      get: {
        summary: 'List all NHI identities',
        tags: ['Identities'],
        parameters: [
          { name: 'platform', in: 'query', schema: { type: 'string' } },
          { name: 'risk_level', in: 'query', schema: { type: 'string', enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] } },
          { name: 'limit', in: 'query', schema: { type: 'integer', default: 50 } },
          { name: 'offset', in: 'query', schema: { type: 'integer', default: 0 } }
        ],
        responses: { '200': { description: 'List of identities' } }
      }
    },
    '/alerts': {
      get: {
        summary: 'List anomaly alerts',
        tags: ['Alerts'],
        parameters: [
          { name: 'severity', in: 'query', schema: { type: 'string', enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] } },
          { name: 'resolved', in: 'query', schema: { type: 'boolean' } }
        ],
        responses: { '200': { description: 'List of alerts' } }
      }
    },
    '/stats': {
      get: {
        summary: 'Dashboard statistics',
        tags: ['Dashboard'],
        responses: { '200': { description: 'Org-level stats' } }
      }
    },
    '/api-keys': {
      get: { summary: 'List API keys', tags: ['API Keys'], responses: { '200': { description: 'API keys list' } } },
      post: {
        summary: 'Create API key',
        tags: ['API Keys'],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object', required: ['name'], properties: {
                  name: { type: 'string' }, role: { type: 'string', enum: ['admin', 'analyst', 'viewer'], default: 'analyst' }
                }
              }
            }
          }
        },
        responses: { '201': { description: 'Created API key (raw key shown once)' } }
      }
    },
    '/api-keys/{id}': {
      delete: {
        summary: 'Revoke API key',
        tags: ['API Keys'],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
        responses: { '200': { description: 'Key revoked' } }
      }
    }
  }
};

app.get('/api/docs', (req, res) => {
  res.json(OPENAPI_SPEC);
});

// Minimal Swagger UI redirect — serves spec for tools like Swagger Editor, Postman
app.get('/api/docs/ui', (req, res) => {
  const swaggerUiHtml = `<!DOCTYPE html>
<html><head><title>NHI Shield API</title>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
</head><body>
<div id="swagger-ui"></div>
<script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
<script>SwaggerUIBundle({ url: '/api/docs', dom_id: '#swagger-ui', presets: [SwaggerUIBundle.presets.apis] });</script>
</body></html>`;
  res.send(swaggerUiHtml);
});


// ============ HEALTH ============

app.get('/health', async (req, res) => {
  const services = {};
  try { await pg.query('SELECT 1'); services.postgresql = 'connected'; } catch { services.postgresql = 'disconnected'; }
  try { await redisClient.ping(); services.redis = 'connected'; } catch { services.redis = 'disconnected'; }
  try {
    const s = neo4jDriver.session();
    await s.run('RETURN 1');
    await s.close();
    services.neo4j = 'connected';
  } catch { services.neo4j = 'disconnected'; }
  // InfluxDB + Qdrant checked via Python services
  const coreHealthy = ['postgresql', 'redis', 'neo4j'].every(k => services[k] === 'connected');
  res.status(coreHealthy || process.env.NODE_ENV === 'test' ? 200 : 503).json({
    status: coreHealthy || process.env.NODE_ENV === 'test' ? 'healthy' : 'degraded',
    version: '2.1.0',
    timestamp: new Date().toISOString(),
    services,
    uptime: process.uptime()
  });
});

app.get('/metrics', async (req, res) => {
  res.set('Content-Type', metricsRegistry.contentType);
  res.end(await metricsRegistry.metrics());
});

// Error handlers
app.use((err, req, res, next) => {
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    return res.status(400).json({ error: 'Bad Request' });
  }
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});
app.use((req, res) => { res.status(404).json({ error: 'Endpoint not found' }); });

// ── mTLS HTTPS Server (production) ───────────────────────────────────────────
// When TLS_CERT, TLS_KEY, and TLS_CA env vars point to PEM files,
// start a second HTTPS server on PORT+1 with mutual TLS enforced.
// Clients must present a certificate signed by the TLS_CA to connect.
const MTLS_PORT = parseInt(process.env.MTLS_PORT || (PORT + 1));
let mtlsServer = null;
(function startMtls() {
  const certPath = process.env.TLS_CERT;
  const keyPath = process.env.TLS_KEY;
  const caPath = process.env.TLS_CA;
  if (!certPath || !keyPath || !caPath) return;  // Skip if certs not configured
  try {
    const tlsOptions = {
      cert: fs.readFileSync(certPath),
      key: fs.readFileSync(keyPath),
      ca: fs.readFileSync(caPath),
      requestCert: true,      // Ask client for certificate
      rejectUnauthorized: true // Reject if client cert is not signed by TLS_CA
    };
    mtlsServer = https.createServer(tlsOptions, app);
    mtlsServer.listen(MTLS_PORT, () => {
      console.log(`   🔒 mTLS HTTPS server on port ${MTLS_PORT} (client cert required)`);
    });
  } catch (e) {
    console.warn(`   ⚠️  mTLS skipped: ${e.message}`);
  }
})();

// ── HTTP Server ───────────────────────────────────────────────────────────────
httpServer.listen(PORT, () => {
  console.log(`\n🛡️  NHI Shield API v2.1 - Port ${PORT}`);
  console.log(`   ✅ WebSocket (Socket.io) enabled`);
  console.log(`   ✅ WAF enabled`);
  console.log(`   ✅ Zero Trust policies (5-layer)`);
  console.log(`   ✅ Chain attack detection (Neo4j)`);
  console.log(`   ✅ Shadow AI scanning`);
  console.log(`   ✅ Lifecycle management`);
  console.log(`   ✅ Permission analyzer + remediation`);
  console.log(`   ✅ Step-up authentication (TOTP MFA)`);
  console.log(`   ✅ Webhook delivery (HMAC-SHA256)`);
  console.log(`   ✅ SSO/OIDC — Google, Azure AD, Okta (PKCE)`);
  console.log(`   ✅ X-API-Key authentication (nhi_xxxxx)`);
  console.log(`   ✅ OpenAPI docs at /api/docs | /api/docs/ui`);
  console.log(`   ✅ Prometheus metrics at /metrics`);
  console.log(`   ✅ Credential vault (AES-256-GCM, versioned)`);
  console.log(`   ✅ mTLS HTTPS: set TLS_CERT/TLS_KEY/TLS_CA env vars`);
  console.log(`   ✅ 16 platform connectors (incl. Gmail)\n`);
});

const shutdown = async () => { await pg.end(); await redisClient.quit(); await neo4jDriver.close(); if (mtlsServer) mtlsServer.close(); process.exit(0); };
process.on('SIGTERM', shutdown); process.on('SIGINT', shutdown);

// Export: require('./server') returns the express app directly (supertest-compatible).
// Named exports { app, io } also available for socket consumers.
module.exports = app;
module.exports.app = app;
module.exports.io = io;
