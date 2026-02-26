/**
 * NHI Shield — Complete SSO / OIDC Implementation
 * Supports: Google, Microsoft (Azure AD), Okta
 * Full token exchange, user provisioning, and session creation
 */

const axios = require('axios');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'jwt_super_secret_key_2026_change_in_production';
const API_URL    = process.env.API_URL    || 'http://localhost:3000';

// ─── Provider Configurations ──────────────────────────────────────────────────

function getProviderConfig(provider) {
  const configs = {
    google: {
      authUrl:    'https://accounts.google.com/o/oauth2/v2/auth',
      tokenUrl:   'https://oauth2.googleapis.com/token',
      userinfoUrl:'https://www.googleapis.com/oauth2/v3/userinfo',
      clientId:   process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      scope: 'openid email profile',
    },
    microsoft: {
      authUrl:    `https://login.microsoftonline.com/${process.env.AZURE_TENANT_ID || 'common'}/oauth2/v2.0/authorize`,
      tokenUrl:   `https://login.microsoftonline.com/${process.env.AZURE_TENANT_ID || 'common'}/oauth2/v2.0/token`,
      userinfoUrl:`https://graph.microsoft.com/v1.0/me`,
      clientId:   process.env.AZURE_CLIENT_ID,
      clientSecret: process.env.AZURE_CLIENT_SECRET,
      scope: 'openid email profile User.Read',
    },
    okta: {
      authUrl:    `${process.env.OKTA_DOMAIN}/oauth2/default/v1/authorize`,
      tokenUrl:   `${process.env.OKTA_DOMAIN}/oauth2/default/v1/token`,
      userinfoUrl:`${process.env.OKTA_DOMAIN}/oauth2/default/v1/userinfo`,
      clientId:   process.env.OKTA_CLIENT_ID,
      clientSecret: process.env.OKTA_CLIENT_SECRET,
      scope: 'openid email profile',
    },
  };
  return configs[provider] || null;
}

function getCallbackUrl(provider) {
  return `${API_URL}/api/auth/sso/${provider}/callback`;
}

// ─── Initiate SSO Flow ────────────────────────────────────────────────────────

async function initiateSSOFlow(provider, redisClient) {
  const config = getProviderConfig(provider);
  if (!config?.clientId) {
    throw new Error(`SSO provider '${provider}' not configured. Set ${provider.toUpperCase()}_CLIENT_ID in .env`);
  }
  // PKCE code verifier + challenge
  const codeVerifier  = crypto.randomBytes(32).toString('base64url');
  const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
  const state         = crypto.randomBytes(16).toString('hex');

  // Store state + verifier in Redis (5 min TTL)
  await redisClient.setEx(`sso:${state}`, 300, JSON.stringify({ provider, codeVerifier }));

  const params = new URLSearchParams({
    client_id:             config.clientId,
    response_type:         'code',
    scope:                 config.scope,
    redirect_uri:          getCallbackUrl(provider),
    state,
    code_challenge:        codeChallenge,
    code_challenge_method: 'S256',
    access_type:           'offline',
    prompt:                'select_account',
  });

  return `${config.authUrl}?${params}`;
}

// ─── Handle Callback & Token Exchange ─────────────────────────────────────────

async function handleSSOCallback(provider, code, state, redisClient, pg) {
  // Validate state
  const stored = await redisClient.get(`sso:${state}`);
  if (!stored) throw new Error('Invalid or expired SSO state');
  const { provider: storedProvider, codeVerifier } = JSON.parse(stored);
  if (storedProvider !== provider) throw new Error('Provider mismatch');
  await redisClient.del(`sso:${state}`);

  const config = getProviderConfig(provider);
  if (!config) throw new Error('Unknown provider');

  // Exchange code for tokens
  const tokenRes = await axios.post(config.tokenUrl,
    new URLSearchParams({
      grant_type:    'authorization_code',
      code,
      redirect_uri:  getCallbackUrl(provider),
      client_id:     config.clientId,
      client_secret: config.clientSecret,
      code_verifier: codeVerifier,
    }),
    { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
  );

  const { access_token, id_token } = tokenRes.data;

  // Fetch user info
  const userRes = await axios.get(config.userinfoUrl, {
    headers: { Authorization: `Bearer ${access_token}` },
  });

  const profile = normalizeProfile(provider, userRes.data, id_token);

  // Provision or update user in DB
  const user = await provisionSSOUser(profile, provider, pg);

  // Issue NHI Shield JWT
  const token = jwt.sign(
    { userId: user.id, email: user.email, role: user.role, orgId: user.org_id },
    JWT_SECRET,
    { expiresIn: '24h' }
  );

  return { token, user: { id: user.id, email: user.email, role: user.role, orgId: user.org_id } };
}

// ─── Normalize Provider Profiles ─────────────────────────────────────────────

function normalizeProfile(provider, data, idToken) {
  switch (provider) {
    case 'google':
      return {
        email: data.email,
        name:  data.name,
        avatarUrl: data.picture,
        ssoId: data.sub,
      };
    case 'microsoft': {
      // Decode id_token or use graph profile
      const email = data.mail || data.userPrincipalName || '';
      return {
        email,
        name:  data.displayName || data.givenName,
        avatarUrl: null,
        ssoId: data.id,
      };
    }
    case 'okta':
      return {
        email: data.email,
        name:  data.name || `${data.given_name} ${data.family_name}`.trim(),
        avatarUrl: null,
        ssoId: data.sub,
      };
    default:
      throw new Error(`Unknown provider: ${provider}`);
  }
}

// ─── Provision or Update SSO User ─────────────────────────────────────────────

async function provisionSSOUser(profile, provider, pg) {
  if (!profile.email) throw new Error('SSO profile missing email');

  // Check if user exists
  let result = await pg.query(
    'SELECT id, email, role, org_id, is_active FROM users WHERE email = $1',
    [profile.email.toLowerCase()]
  );

  if (result.rows.length > 0) {
    const user = result.rows[0];
    if (!user.is_active) throw new Error('Account is disabled');

    // Update last SSO login
    await pg.query(
      'UPDATE users SET last_login = NOW(), sso_provider = $1 WHERE id = $2',
      [provider, user.id]
    );
    return user;
  }

  // Auto-provision: find or create org based on email domain
  const domain = profile.email.split('@')[1];
  let orgResult = await pg.query(
    'SELECT id FROM organizations WHERE domain = $1', [domain]
  );

  let orgId;
  if (orgResult.rows.length > 0) {
    orgId = orgResult.rows[0].id;
  } else {
    // Create new org for this domain
    const newOrg = await pg.query(
      "INSERT INTO organizations (name, domain, plan) VALUES ($1, $2, 'starter') RETURNING id",
      [`${domain} Organization`, domain]
    );
    orgId = newOrg.rows[0].id;
  }

  // Create new user (viewer role by default — admin must promote)
  const newUser = await pg.query(
    `INSERT INTO users (email, password_hash, name, role, org_id, sso_provider, is_active, last_login)
     VALUES ($1, '', $2, 'viewer', $3, $4, true, NOW()) RETURNING id, email, role, org_id`,
    [profile.email.toLowerCase(), profile.name || profile.email, orgId, provider]
  );

  return newUser.rows[0];
}

module.exports = { initiateSSOFlow, handleSSOCallback };
