/**
 * NHI Shield API — Production Test Suite
 * Tests: Auth, Identity, Alerts, Reports, Integrations, Security Headers,
 *        Rate Limiting, CORS, Input Validation, API Keys, OpenAPI, Error Handling
 */

const JWT_SECRET = process.env.JWT_SECRET || 'test_jwt_secret_key_for_testing_must_be_32_chars';
process.env.JWT_SECRET = JWT_SECRET;
process.env.NODE_ENV = 'test';

const request = require('supertest');
const app = require('./server');   // works because module.exports = app
const jwt = require('jsonwebtoken');

// ─── Helpers ─────────────────────────────────────────────────────────────────
function makeToken(overrides = {}) {
  return jwt.sign(
    { userId: 'test-user-001', email: 'admin@test.com', role: 'admin', orgId: 'org-001', ...overrides },
    JWT_SECRET,
    { expiresIn: '1h' }
  );
}

const adminToken = makeToken({ role: 'admin' });
const viewerToken = makeToken({ role: 'viewer' });
const expiredToken = jwt.sign({ userId: 'x' }, JWT_SECRET, { expiresIn: '-1s' });

// ─── Health Check ─────────────────────────────────────────────────────────────
describe('Health Check', () => {
  test('GET /health returns 200 with status field', async () => {
    const res = await request(app).get('/health').expect(200);
    expect(res.body).toHaveProperty('status');
    expect(['healthy', 'degraded']).toContain(res.body.status);
  });
});

// ─── Security Headers ─────────────────────────────────────────────────────────
describe('Security Headers (Helmet)', () => {
  test('Includes X-Frame-Options', async () => {
    const res = await request(app).get('/health');
    expect(res.headers).toHaveProperty('x-frame-options');
  });
  test('Includes X-Content-Type-Options', async () => {
    const res = await request(app).get('/health');
    expect(res.headers['x-content-type-options']).toBe('nosniff');
  });
  test('Includes X-DNS-Prefetch-Control', async () => {
    const res = await request(app).get('/health');
    expect(res.headers).toHaveProperty('x-dns-prefetch-control');
  });
});

// ─── CORS ─────────────────────────────────────────────────────────────────────
describe('CORS', () => {
  test('Includes access-control-allow-origin for allowed origin', async () => {
    const res = await request(app)
      .get('/health')
      .set('Origin', process.env.FRONTEND_URL || 'http://localhost:3001');
    expect(res.headers).toHaveProperty('access-control-allow-origin');
  });
});

// ─── Authentication ───────────────────────────────────────────────────────────
describe('POST /api/auth/login', () => {
  test('400 when body is empty', async () => {
    const res = await request(app).post('/api/auth/login').send({}).expect(400);
    expect(res.body.error).toBe('Email and password are required');
  });

  test('400 when password is missing', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: 'a@b.com' })
      .expect(400);
    expect(res.body.error).toBe('Email and password are required');
  });

  test('400 when email is missing', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ password: 'hunter2' })
      .expect(400);
    expect(res.body.error).toBe('Email and password are required');
  });

  test('401 for unknown credentials (DB returns no user)', async () => {
    // Will hit DB and get 401 invalid credentials or 500 if DB is down — both are non-200
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: 'nobody@nowhere.com', password: 'wrong' });
    expect([401, 500]).toContain(res.status);
  });
});

describe('POST /api/auth/logout', () => {
  test('401 without token', async () => {
    await request(app).post('/api/auth/logout').expect(401);
  });

  test('401 with expired token', async () => {
    const res = await request(app)
      .post('/api/auth/logout')
      .set('Authorization', `Bearer ${expiredToken}`)
      .expect(401);
    expect(res.body.error).toMatch(/token expired|invalid token/i);
  });

  test('401 with malformed token', async () => {
    const res = await request(app)
      .post('/api/auth/logout')
      .set('Authorization', 'Bearer not.a.jwt')
      .expect(401);
    expect(res.body.error).toBe('Invalid token');
  });
});

// ─── Protected Route Pattern (all protected routes return 401 without token) ──
describe('Protected Routes — 401 without token', () => {
  const protectedRoutes = [
    ['get', '/api/identities'],
    ['get', '/api/identities/some-id'],
    ['put', '/api/identities/some-id'],
    ['post', '/api/identities/some-id/offboard'],
    ['get', '/api/alerts'],
    ['put', '/api/alerts/some-id/resolve'],
    ['patch', '/api/alerts/some-id/resolve'],
    ['get', '/api/reports/compliance'],
    ['get', '/api/reports/audit'],
    ['get', '/api/audit'],
    ['get', '/api/integrations'],
    ['post', '/api/integrations'],
    ['get', '/api/graph'],
    ['get', '/api/dashboard/stats'],
    ['get', '/api/dashboard/recent-activity'],
    ['get', '/api/rotation/history'],
    ['get', '/api/webhooks'],
    ['get', '/api/users'],
    ['get', '/api/v1/identities'],
    ['get', '/api/v1/alerts'],
    ['get', '/api/v1/stats'],
    ['get', '/api/v1/api-keys'],
  ];

  protectedRoutes.forEach(([method, path]) => {
    test(`${method.toUpperCase()} ${path} → 401`, async () => {
      const res = await request(app)[method](path);
      expect(res.status).toBe(401);
      expect(res.body).toHaveProperty('error');
    });
  });
});

// ─── Input Validation ─────────────────────────────────────────────────────────
describe('Input Validation', () => {
  test('Malformed JSON body returns 400', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .set('Content-Type', 'application/json')
      .send('{ "email": bad json }')
      .expect(400);
  });

  test('SQL injection in login email does not crash server', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: "' OR 1=1; DROP TABLE users; --", password: 'x' });
    // Must be 400 (validation) or 401/500 (db error), never 200
    expect(res.status).not.toBe(200);
  });

  test('XSS in login fields does not crash server', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: '<script>alert(1)</script>@evil.com', password: 'x' });
    expect(res.status).not.toBe(200);
  });
});

// ─── Rate Limiting ─────────────────────────────────────────────────────────────
describe('Rate Limiting', () => {
  test('Auth rate limiter triggers after 10 rapid requests', async () => {
    // Auth limiter is 10 per 15min — hit it 11 times
    const responses = [];
    for (let i = 0; i < 11; i++) {
      responses.push(
        await request(app)
          .post('/api/auth/login')
          .send({ email: `ratelimit${i}@test.com`, password: 'x' })
      );
    }
    const rateLimited = responses.filter(r => r.status === 429);
    expect(rateLimited.length).toBeGreaterThan(0);
  }, 30000);
});

// ─── Error Handling ───────────────────────────────────────────────────────────
describe('Error Handling', () => {
  test('404 for unknown endpoint', async () => {
    const res = await request(app).get('/api/totally/unknown/route').expect(404);
    expect(res.body.error).toBe('Endpoint not found');
  });

  test('404 for unknown deep path', async () => {
    const res = await request(app).get('/not-an-api/path').expect(404);
    expect(res.body.error).toBe('Endpoint not found');
  });
});

// ─── OpenAPI Documentation ─────────────────────────────────────────────────────
describe('OpenAPI Docs', () => {
  test('GET /api/docs returns valid OpenAPI 3.0 JSON', async () => {
    const res = await request(app).get('/api/docs').expect(200);
    expect(res.body.openapi).toBe('3.0.3');
    expect(res.body.info.title).toBe('NHI Shield API');
    expect(res.body.paths).toHaveProperty('/identities');
    expect(res.body.paths).toHaveProperty('/alerts');
    expect(res.body.paths).toHaveProperty('/api-keys');
    expect(res.body.components.securitySchemes).toHaveProperty('ApiKeyAuth');
    expect(res.body.components.securitySchemes).toHaveProperty('BearerAuth');
  });

  test('GET /api/docs/ui returns Swagger HTML', async () => {
    const res = await request(app).get('/api/docs/ui').expect(200);
    expect(res.text).toContain('swagger-ui');
    expect(res.text).toContain('NHI Shield API');
  });
});

// ─── Prometheus Metrics ───────────────────────────────────────────────────────
describe('Prometheus Metrics', () => {
  test('GET /metrics returns prometheus text format', async () => {
    const res = await request(app).get('/metrics').expect(200);
    expect(res.headers['content-type']).toMatch(/text\/plain/);
    expect(res.text).toContain('# HELP');
    expect(res.text).toContain('# TYPE');
  });
});

// ─── API Key Auth ─────────────────────────────────────────────────────────────
describe('X-API-Key Authentication', () => {
  test('Invalid API key returns 401', async () => {
    const res = await request(app)
      .get('/api/identities')
      .set('X-API-Key', 'nhi_fakekeynotindb123456')
      .expect(401);
    expect(res.body.error).toMatch(/Invalid|inactive|api key/i);
  });

  test('Non-nhi_ prefixed key is not treated as API key', async () => {
    const res = await request(app)
      .get('/api/identities')
      .set('X-API-Key', 'sk-someOpenAIkey');
    // Falls through to JWT auth, gets 401 no token
    expect(res.status).toBe(401);
  });
});

// ─── Spec Route Presence ──────────────────────────────────────────────────────
describe('All Spec Routes Present', () => {
  // Just verify the routes exist and respond (not 404), not their business logic
  const routes = [
    ['get', '/api/graph'],
    ['get', '/api/reports/audit'],
    ['patch', '/api/alerts/nonexistent/resolve'],
    ['put', '/api/alerts/nonexistent/resolve'],
  ];

  routes.forEach(([method, path]) => {
    test(`${method.toUpperCase()} ${path} exists (not 404)`, async () => {
      const res = await request(app)[method](path);
      expect(res.status).not.toBe(404);
    });
  });
});
