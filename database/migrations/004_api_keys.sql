-- Migration 004: API Keys table for X-API-Key public REST API (nhi_xxxxx format)

CREATE TABLE IF NOT EXISTS api_keys (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name         VARCHAR(255) NOT NULL,
    key_hash     VARCHAR(64) NOT NULL UNIQUE,  -- SHA-256 of raw key (raw key never stored)
    key_prefix   VARCHAR(16) NOT NULL,          -- First 12 chars for display (e.g. "nhi_a1b2c3d4")
    role         VARCHAR(20) NOT NULL DEFAULT 'analyst' CHECK (role IN ('admin','analyst','viewer')),
    is_active    BOOLEAN NOT NULL DEFAULT TRUE,
    last_used_at TIMESTAMP WITH TIME ZONE,
    use_count    BIGINT NOT NULL DEFAULT 0,
    created_by   UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at   TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at   TIMESTAMP WITH TIME ZONE  -- NULL = never expires
);

CREATE INDEX IF NOT EXISTS idx_api_keys_org     ON api_keys(org_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash    ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_active  ON api_keys(org_id, is_active);

COMMENT ON TABLE  api_keys            IS 'API keys for X-API-Key authentication (nhi_xxxxx format). Raw keys are never stored — only SHA-256 hash.';
COMMENT ON COLUMN api_keys.key_hash   IS 'SHA-256 hash of the raw API key. Used for lookup and verification.';
COMMENT ON COLUMN api_keys.key_prefix IS 'First 12 characters of raw key shown in UI for identification (nhi_XXXXXXXX).';
