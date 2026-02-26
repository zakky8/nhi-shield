-- NHI Shield - Database Migration v2.0
-- Adds all new tables for enterprise features
-- Run AFTER 001_initial.sql

-- ─── Extend existing tables ────────────────────────────────────────────────

-- Users: add SSO + failed login tracking + MFA temp + permissions column
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS name VARCHAR(255),
  ADD COLUMN IF NOT EXISTS sso_provider VARCHAR(50),
  ADD COLUMN IF NOT EXISTS mfa_secret_temp VARCHAR(255),
  ADD COLUMN IF NOT EXISTS failed_login_attempts INT DEFAULT 0,
  ADD COLUMN IF NOT EXISTS last_failed_login TIMESTAMP WITH TIME ZONE,
  ADD COLUMN IF NOT EXISTS permissions JSONB DEFAULT '[]';

-- Identities: add offboard fields + lifecycle fields
ALTER TABLE identities
  ADD COLUMN IF NOT EXISTS offboarded_at TIMESTAMP WITH TIME ZONE,
  ADD COLUMN IF NOT EXISTS offboarded_by UUID REFERENCES users(id),
  ADD COLUMN IF NOT EXISTS offboard_reason TEXT,
  ADD COLUMN IF NOT EXISTS last_synced_at TIMESTAMP WITH TIME ZONE,
  ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW();

-- Integrations: add sync tracking
ALTER TABLE integrations
  ADD COLUMN IF NOT EXISTS sync_status VARCHAR(50) DEFAULT 'idle',
  ADD COLUMN IF NOT EXISTS sync_count INT DEFAULT 0,
  ADD COLUMN IF NOT EXISTS last_error TEXT;

-- Audit logs: add metadata column
ALTER TABLE audit_logs
  ADD COLUMN IF NOT EXISTS metadata JSONB DEFAULT '{}',
  ADD COLUMN IF NOT EXISTS identity_id VARCHAR(255),
  ADD COLUMN IF NOT EXISTS reason TEXT,
  ADD COLUMN IF NOT EXISTS old_state JSONB,
  ADD COLUMN IF NOT EXISTS new_state JSONB;

-- ─── Webhooks ──────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS webhooks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    events TEXT[] NOT NULL DEFAULT '{}',
    secret VARCHAR(128) NOT NULL,
    is_active BOOLEAN DEFAULT true,
    last_delivery TIMESTAMP WITH TIME ZONE,
    delivery_count INT DEFAULT 0,
    last_error TEXT,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_webhooks_org ON webhooks(org_id);

-- ─── Secret Rotation History ────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS rotation_history (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    identity_id VARCHAR(255) NOT NULL,
    org_id UUID REFERENCES organizations(id),
    platform VARCHAR(100),
    status VARCHAR(50) NOT NULL,
    old_credential_id TEXT,
    new_credential_id TEXT,
    duration_seconds FLOAT,
    error_message TEXT,
    initiated_by UUID REFERENCES users(id),
    rotated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_rotation_identity ON rotation_history(identity_id);
CREATE INDEX IF NOT EXISTS idx_rotation_org ON rotation_history(org_id);

-- ─── Credential Vault ────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS credential_vault (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    identity_id VARCHAR(255) UNIQUE NOT NULL,
    credential_id TEXT,
    encrypted_value TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ─── Zero Trust Policy Engine ────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS zero_trust_policies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    resource_pattern TEXT DEFAULT '*',
    action_pattern TEXT DEFAULT '*',
    decision VARCHAR(50) NOT NULL CHECK (decision IN ('ALLOW','DENY','STEP_UP','LOG_ONLY','QUARANTINE')),
    conditions JSONB DEFAULT '{}',
    priority INT DEFAULT 100,
    is_active BOOLEAN DEFAULT true,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ztp_org ON zero_trust_policies(org_id);

-- ─── Policy Decisions Log ───────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS policy_decisions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID REFERENCES organizations(id),
    identity_id VARCHAR(255),
    action TEXT,
    resource TEXT,
    decision VARCHAR(50),
    reason TEXT,
    layer VARCHAR(50),
    confidence FLOAT,
    factors JSONB DEFAULT '[]',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_pd_org ON policy_decisions(org_id);
CREATE INDEX IF NOT EXISTS idx_pd_identity ON policy_decisions(identity_id);
CREATE INDEX IF NOT EXISTS idx_pd_decision ON policy_decisions(decision);

-- ─── Lifecycle Policies ──────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS lifecycle_policies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    trigger VARCHAR(100) NOT NULL, -- e.g. 'DORMANT_90D', 'EXPIRED', 'OWNER_DEPARTED'
    action VARCHAR(100) NOT NULL,  -- e.g. 'OFFBOARD', 'ALERT', 'ROTATE'
    conditions JSONB DEFAULT '{}',
    is_active BOOLEAN DEFAULT true,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_lp_org ON lifecycle_policies(org_id);

-- ─── Role Permissions (fine-grained RBAC) ───────────────────────────────────

CREATE TABLE IF NOT EXISTS role_permissions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    role VARCHAR(50) NOT NULL,
    resource VARCHAR(100) NOT NULL,
    action VARCHAR(100) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(role, resource, action)
);

-- Seed default permissions
INSERT INTO role_permissions (role, resource, action) VALUES
  ('admin',   'identities', 'read'),   ('admin',   'identities', 'write'),
  ('admin',   'identities', 'delete'), ('admin',   'alerts',     'read'),
  ('admin',   'alerts',     'write'),  ('admin',   'users',      'read'),
  ('admin',   'users',      'write'),  ('admin',   'integrations','read'),
  ('admin',   'integrations','write'), ('admin',   'reports',    'read'),
  ('admin',   'webhooks',   'read'),   ('admin',   'webhooks',   'write'),
  ('analyst', 'identities', 'read'),   ('analyst', 'identities', 'write'),
  ('analyst', 'alerts',     'read'),   ('analyst', 'alerts',     'write'),
  ('analyst', 'reports',    'read'),
  ('viewer',  'identities', 'read'),   ('viewer',  'alerts',     'read'),
  ('viewer',  'reports',    'read')
ON CONFLICT (role, resource, action) DO NOTHING;

-- activity_events table created in 001_initial.sql (partitioned)

-- ─── Anomaly Alerts (ensure alert_type field) ────────────────────────────────

ALTER TABLE anomaly_alerts
  ADD COLUMN IF NOT EXISTS alert_type VARCHAR(100),
  ADD COLUMN IF NOT EXISTS confidence FLOAT DEFAULT 0.8,
  ADD COLUMN IF NOT EXISTS evidence JSONB DEFAULT '{}',
  ADD COLUMN IF NOT EXISTS resolution_notes TEXT,
  ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMP WITH TIME ZONE,
  ADD COLUMN IF NOT EXISTS resolved_by UUID REFERENCES users(id);

-- risk_scores table created in 001_initial.sql

-- ─── Default org + admin user (development seed) ────────────────────────────

INSERT INTO organizations (id, name, domain, plan)
VALUES ('00000000-0000-0000-0000-000000000001', 'Demo Organization', 'demo.nhishield.io', 'enterprise')
ON CONFLICT (id) DO NOTHING;

-- Password = "Admin123!" (change immediately in production)
INSERT INTO users (id, org_id, email, password_hash, name, role, is_active)
VALUES (
  '00000000-0000-0000-0000-000000000002',
  '00000000-0000-0000-0000-000000000001',
  'admin@demo.nhishield.io',
  '$2b$12$LpSGF6SqFfRSaCYtJO4LLOOQpMHq1/4fkpSwxiMaXiLfKPO7nH4.y', -- Admin123!
  'Demo Admin',
  'admin',
  true
) ON CONFLICT (email) DO NOTHING;

-- ─── Indexes for performance ─────────────────────────────────────────────────

CREATE INDEX IF NOT EXISTS idx_identities_org_platform ON identities(org_id, platform);
CREATE INDEX IF NOT EXISTS idx_identities_active ON identities(org_id, is_active);
CREATE INDEX IF NOT EXISTS idx_identities_last_used ON identities(last_used);
CREATE INDEX IF NOT EXISTS idx_audit_org_time ON audit_logs(org_id, created_at DESC);

-- ─── Credential Vault (versioned) ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS credential_vault (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_id  VARCHAR(255) NOT NULL,
    version      INTEGER NOT NULL DEFAULT 1,
    credential_id VARCHAR(255),
    encrypted_value TEXT NOT NULL,
    salt         VARCHAR(64) NOT NULL,
    hash_fingerprint VARCHAR(64) NOT NULL,
    created_by   UUID REFERENCES users(id),
    rotation_reason TEXT,
    is_active    BOOLEAN DEFAULT true,
    created_at   TIMESTAMP DEFAULT NOW(),
    UNIQUE (identity_id, version)
);

CREATE INDEX IF NOT EXISTS idx_vault_identity_active ON credential_vault(identity_id, is_active);
CREATE INDEX IF NOT EXISTS idx_vault_identity_version ON credential_vault(identity_id, version DESC);

-- ─── SSO provider columns ─────────────────────────────────────────────────────
ALTER TABLE users ADD COLUMN IF NOT EXISTS sso_provider VARCHAR(50);
ALTER TABLE users ADD COLUMN IF NOT EXISTS sso_id VARCHAR(255);
ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_url TEXT;

-- ─── Organizations: domain for SSO auto-provisioning ─────────────────────────
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS domain VARCHAR(255);

-- ─── Audit log: description + metadata columns ───────────────────────────────
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS description TEXT;
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS metadata JSONB DEFAULT '{}';

-- ─── Webhooks ─────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS webhooks (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       UUID REFERENCES organizations(id) ON DELETE CASCADE,
    url          TEXT NOT NULL,
    secret       VARCHAR(255),
    events       TEXT[] DEFAULT '{}',
    is_active    BOOLEAN DEFAULT true,
    last_triggered TIMESTAMP,
    created_by   UUID REFERENCES users(id),
    created_at   TIMESTAMP DEFAULT NOW()
);

-- ─── On-Premise agents ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS agents (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       UUID REFERENCES organizations(id) ON DELETE CASCADE,
    name         VARCHAR(255) NOT NULL,
    token_hash   VARCHAR(255) UNIQUE NOT NULL,
    platform     VARCHAR(100),
    version      VARCHAR(50),
    last_heartbeat TIMESTAMP,
    ip_address   INET,
    is_active    BOOLEAN DEFAULT true,
    created_at   TIMESTAMP DEFAULT NOW()
);

