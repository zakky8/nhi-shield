-- NHI Shield — Migration 003: Complete Enterprise Schema
-- Adds all tables needed for missing features
-- Run AFTER 001_initial.sql and 002_enterprise_upgrade.sql

-- ─── Activity Events (core telemetry table) ──────────────────────────────────
CREATE TABLE IF NOT EXISTS activity_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    identity_id VARCHAR(255) NOT NULL,
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    action VARCHAR(255) NOT NULL,
    resource TEXT,
    ip_address VARCHAR(45),
    success BOOLEAN DEFAULT true,
    metadata JSONB DEFAULT '{}',
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ae_identity ON activity_events(identity_id);
CREATE INDEX IF NOT EXISTS idx_ae_org ON activity_events(org_id);
CREATE INDEX IF NOT EXISTS idx_ae_ts ON activity_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_ae_identity_ts ON activity_events(identity_id, timestamp DESC);

-- ─── Credential Vault with Versioning ────────────────────────────────────────
DROP TABLE IF EXISTS credential_vault;
CREATE TABLE IF NOT EXISTS credential_vault (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    identity_id VARCHAR(255) NOT NULL,
    version INT NOT NULL DEFAULT 1,
    credential_id TEXT,
    encrypted_value TEXT NOT NULL,
    salt VARCHAR(64) NOT NULL DEFAULT '',
    hash_fingerprint VARCHAR(64) NOT NULL DEFAULT '',
    created_by VARCHAR(255),
    rotation_reason TEXT,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(identity_id, version)
);

CREATE INDEX IF NOT EXISTS idx_vault_identity ON credential_vault(identity_id);
CREATE INDEX IF NOT EXISTS idx_vault_active ON credential_vault(identity_id) WHERE is_active=true;

-- ─── Secret Rotation History ─────────────────────────────────────────────────
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

CREATE INDEX IF NOT EXISTS idx_rot_identity ON rotation_history(identity_id);
CREATE INDEX IF NOT EXISTS idx_rot_org ON rotation_history(org_id);
CREATE INDEX IF NOT EXISTS idx_rot_ts ON rotation_history(rotated_at DESC);

-- ─── Zero Trust Policy Tables ─────────────────────────────────────────────────
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

CREATE TABLE IF NOT EXISTS policy_decisions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID REFERENCES organizations(id),
    identity_id VARCHAR(255),
    action VARCHAR(255),
    resource TEXT,
    decision VARCHAR(50),
    reason TEXT,
    layer VARCHAR(50),
    confidence FLOAT,
    factors JSONB DEFAULT '[]',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_pd_identity ON policy_decisions(identity_id);
CREATE INDEX IF NOT EXISTS idx_pd_org ON policy_decisions(org_id);
CREATE INDEX IF NOT EXISTS idx_pd_ts ON policy_decisions(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_pd_decision ON policy_decisions(decision);

-- ─── Identity Reviews (lifecycle) ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS identity_reviews (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    identity_id VARCHAR(255) UNIQUE NOT NULL,
    org_id UUID REFERENCES organizations(id),
    review_date TIMESTAMP WITH TIME ZONE,
    assigned_to VARCHAR(255),
    status VARCHAR(50) DEFAULT 'PENDING'
        CHECK (status IN ('PENDING','IN_PROGRESS','COMPLETED','OVERDUE')),
    notes TEXT,
    completed_at TIMESTAMP WITH TIME ZONE,
    completed_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ir_org ON identity_reviews(org_id);
CREATE INDEX IF NOT EXISTS idx_ir_status ON identity_reviews(status);
CREATE INDEX IF NOT EXISTS idx_ir_date ON identity_reviews(review_date);

-- ─── Permission Analysis Cache ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS permission_analysis (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    identity_id VARCHAR(255) UNIQUE NOT NULL,
    org_id UUID REFERENCES organizations(id),
    unused_permissions JSONB DEFAULT '[]',
    dangerous_permissions JSONB DEFAULT '[]',
    recommendation TEXT,
    risk_reduction_pct INT DEFAULT 0,
    analyzed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_pa_org ON permission_analysis(org_id);

-- ─── Shadow AI Findings ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS shadow_findings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    finding_type VARCHAR(100) NOT NULL,
    platform VARCHAR(100),
    name VARCHAR(255),
    description TEXT,
    severity VARCHAR(20),
    location TEXT,
    masked_value TEXT,
    metadata JSONB DEFAULT '{}',
    is_resolved BOOLEAN DEFAULT false,
    resolved_at TIMESTAMP WITH TIME ZONE,
    resolved_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sf_org ON shadow_findings(org_id);
CREATE INDEX IF NOT EXISTS idx_sf_severity ON shadow_findings(severity);
CREATE INDEX IF NOT EXISTS idx_sf_resolved ON shadow_findings(is_resolved);

-- ─── Compliance Reports Archive ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS compliance_reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    report_type VARCHAR(50) NOT NULL,
    compliance_score INT,
    generated_by UUID REFERENCES users(id),
    pdf_size_bytes INT,
    report_data JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cr_org ON compliance_reports(org_id);
CREATE INDEX IF NOT EXISTS idx_cr_type ON compliance_reports(report_type);

-- ─── Public API Keys ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    key_hash VARCHAR(64) NOT NULL UNIQUE,   -- SHA-256 of actual key
    key_prefix VARCHAR(20) NOT NULL,        -- e.g. "nhi_abc123" (first 10 chars)
    permissions JSONB DEFAULT '["read"]',
    rate_limit_per_hour INT DEFAULT 1000,
    is_active BOOLEAN DEFAULT true,
    last_used TIMESTAMP WITH TIME ZONE,
    usage_count BIGINT DEFAULT 0,
    created_by UUID REFERENCES users(id),
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ak_org ON api_keys(org_id);
CREATE INDEX IF NOT EXISTS idx_ak_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_ak_active ON api_keys(is_active);

-- ─── MFA / Step-up Auth ───────────────────────────────────────────────────────
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS mfa_enabled BOOLEAN DEFAULT false,
    ADD COLUMN IF NOT EXISTS mfa_secret VARCHAR(255),
    ADD COLUMN IF NOT EXISTS mfa_backup_codes JSONB DEFAULT '[]',
    ADD COLUMN IF NOT EXISTS step_up_until TIMESTAMP WITH TIME ZONE;

-- ─── Identities: new columns for enterprise features ─────────────────────────
ALTER TABLE identities
    ADD COLUMN IF NOT EXISTS created_by_identity VARCHAR(255),  -- for chain tracking
    ADD COLUMN IF NOT EXISTS last_rotated TIMESTAMP WITH TIME ZONE,
    ADD COLUMN IF NOT EXISTS external_id VARCHAR(255),          -- platform-side ID
    ADD COLUMN IF NOT EXISTS shadow_detected BOOLEAN DEFAULT false;

CREATE INDEX IF NOT EXISTS idx_i_external_id ON identities(external_id);
CREATE INDEX IF NOT EXISTS idx_i_created_by ON identities(created_by_identity);

-- ─── Risk scores: add is_current flag ────────────────────────────────────────
ALTER TABLE risk_scores
    ADD COLUMN IF NOT EXISTS is_current BOOLEAN DEFAULT false,
    ADD COLUMN IF NOT EXISTS factors JSONB DEFAULT '{}';

CREATE INDEX IF NOT EXISTS idx_rs_current ON risk_scores(identity_id) WHERE is_current=true;

-- ─── Webhooks ─────────────────────────────────────────────────────────────────
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

CREATE INDEX IF NOT EXISTS idx_wh_org ON webhooks(org_id);

-- ─── Compliance templates ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS compliance_templates (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    framework VARCHAR(50),
    template_data JSONB DEFAULT '{}',
    is_builtin BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

INSERT INTO compliance_templates (name, framework, template_data, is_builtin)
VALUES
    ('SOC 2 Type II', 'soc2', '{"controls": ["CC6.1","CC6.2","CC6.3","CC7.2","CC7.3"]}', true),
    ('GDPR Assessment', 'gdpr', '{"articles": ["Art.5","Art.25","Art.30","Art.32","Art.33"]}', true),
    ('ISO 27001', 'iso27001', '{"controls": ["A.9.2.3","A.9.2.5","A.10.1.1","A.12.4.1"]}', true),
    ('PCI-DSS', 'pci_dss', '{"requirements": ["7.1","7.2","8.2","10.1","10.5"]}', true),
    ('HIPAA', 'hipaa', '{"safeguards": ["164.312(a)","164.312(b)","164.312(d)"]}', true)
ON CONFLICT DO NOTHING;

-- ─── Auto-timestamp triggers ────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN NEW.updated_at = NOW(); RETURN NEW; END;
$$ LANGUAGE plpgsql;

DO $$
DECLARE t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY['identity_reviews','credential_vault'] LOOP
        IF NOT EXISTS (
            SELECT 1 FROM pg_trigger WHERE tgname = 'trg_' || t || '_updated'
        ) THEN
            EXECUTE format(
                'CREATE TRIGGER trg_%s_updated BEFORE UPDATE ON %s
                 FOR EACH ROW EXECUTE FUNCTION update_updated_at()', t, t);
        END IF;
    END LOOP;
END;
$$;

-- Done
SELECT 'Migration 003 applied successfully' AS status;
