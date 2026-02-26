-- NHI Shield - Initial Database Schema
-- PostgreSQL 16+ Required

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Organizations table
CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    domain VARCHAR(255),
    plan VARCHAR(50) DEFAULT 'starter' CHECK (plan IN ('starter', 'business', 'enterprise')),
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    role VARCHAR(50) DEFAULT 'viewer' CHECK (role IN ('viewer', 'analyst', 'admin', 'superadmin')),
    mfa_enabled BOOLEAN DEFAULT false,
    mfa_secret VARCHAR(255),
    last_login TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- NHI Identities table (core table)
CREATE TABLE identities (
    id VARCHAR(255) PRIMARY KEY,
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(500) NOT NULL,
    platform VARCHAR(100) NOT NULL,
    type VARCHAR(100) NOT NULL,
    permissions TEXT[] DEFAULT '{}',
    owner VARCHAR(255),
    owner_user_id UUID REFERENCES users(id),
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE,
    last_used TIMESTAMP WITH TIME ZONE,
    offboarded_at TIMESTAMP WITH TIME ZONE,
    offboarded_by UUID REFERENCES users(id),
    offboard_reason TEXT,
    metadata JSONB DEFAULT '{}',
    discovered_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_synced_at TIMESTAMP WITH TIME ZONE
);

-- Risk Scores table
CREATE TABLE risk_scores (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    identity_id VARCHAR(255) REFERENCES identities(id) ON DELETE CASCADE,
    total_score INTEGER NOT NULL CHECK (total_score >= 0 AND total_score <= 100),
    level VARCHAR(20) NOT NULL CHECK (level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    factors JSONB DEFAULT '[]',
    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(identity_id)
);

-- Anomaly Alerts table
CREATE TABLE anomaly_alerts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    identity_id VARCHAR(255) REFERENCES identities(id) ON DELETE CASCADE,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    alert_type VARCHAR(100) NOT NULL,
    description TEXT NOT NULL,
    confidence DECIMAL(3,2) CHECK (confidence >= 0 AND confidence <= 1),
    evidence JSONB DEFAULT '{}',
    resolved BOOLEAN DEFAULT false,
    resolved_by UUID REFERENCES users(id),
    resolved_at TIMESTAMP WITH TIME ZONE,
    resolution_notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Audit Logs table (immutable - never delete)
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    identity_id VARCHAR(255) REFERENCES identities(id) ON DELETE SET NULL,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100),
    resource_id VARCHAR(255),
    description TEXT,
    old_state JSONB,
    new_state JSONB,
    ip_address INET,
    user_agent TEXT,
    session_id VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create partitions for audit logs (monthly)
-- COMMENTED OUT: Partitioning not needed for CI/test environments
-- CREATE TABLE audit_logs_2026_01 PARTITION OF audit_logs
--     FOR VALUES FROM ('2026-01-01') TO ('2026-02-01');
-- CREATE TABLE audit_logs_2026_02 PARTITION OF audit_logs
--     FOR VALUES FROM ('2026-02-01') TO ('2026-03-01');
-- CREATE TABLE audit_logs_2026_03 PARTITION OF audit_logs
--     FOR VALUES FROM ('2026-03-01') TO ('2026-04-01');
-- CREATE TABLE audit_logs_2026_04 PARTITION OF audit_logs
--     FOR VALUES FROM ('2026-04-01') TO ('2026-05-01');
-- CREATE TABLE audit_logs_2026_05 PARTITION OF audit_logs
--     FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');
-- CREATE TABLE audit_logs_2026_06 PARTITION OF audit_logs
--     FOR VALUES FROM ('2026-06-01') TO ('2026-07-01');

-- Integrations table
CREATE TABLE integrations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    platform VARCHAR(100) NOT NULL,
    name VARCHAR(255),
    credentials TEXT NOT NULL,
    config JSONB DEFAULT '{}',
    is_active BOOLEAN DEFAULT true,
    last_sync TIMESTAMP WITH TIME ZONE,
    last_error TEXT,
    error_count INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_by UUID REFERENCES users(id)
);

-- Activity Events table (for time-series data, mirrored in InfluxDB)
CREATE TABLE activity_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    identity_id VARCHAR(255) REFERENCES identities(id) ON DELETE CASCADE,
    platform VARCHAR(100) NOT NULL,
    action VARCHAR(255) NOT NULL,
    resource VARCHAR(500),
    resource_type VARCHAR(100),
    ip_address INET,
    user_agent TEXT,
    success BOOLEAN DEFAULT true,
    error_message TEXT,
    metadata JSONB DEFAULT '{}',
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create partitions for activity events (monthly)
-- COMMENTED OUT: Partitioning not needed for CI/test environments
-- CREATE TABLE activity_events_2026_01 PARTITION OF activity_events
--     FOR VALUES FROM ('2026-01-01') TO ('2026-02-01');
-- CREATE TABLE activity_events_2026_02 PARTITION OF activity_events
--     FOR VALUES FROM ('2026-02-01') TO ('2026-03-01');
-- CREATE TABLE activity_events_2026_03 PARTITION OF activity_events
--     FOR VALUES FROM ('2026-03-01') TO ('2026-04-01');

-- Policy Rules table
CREATE TABLE policy_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    rule_type VARCHAR(100) NOT NULL,
    conditions JSONB NOT NULL,
    actions JSONB NOT NULL,
    priority INTEGER DEFAULT 100,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_by UUID REFERENCES users(id)
);

-- Behavioral Baselines table
CREATE TABLE behavioral_baselines (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    identity_id VARCHAR(255) REFERENCES identities(id) ON DELETE CASCADE,
    baseline_vector JSONB,
    event_count INTEGER DEFAULT 0,
    time_window_days INTEGER DEFAULT 30,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(identity_id)
);

-- Notification Settings table
CREATE TABLE notification_settings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    channel VARCHAR(50) NOT NULL CHECK (channel IN ('email', 'slack', 'webhook')),
    config JSONB NOT NULL,
    alert_types TEXT[] DEFAULT '{}',
    min_severity VARCHAR(20) DEFAULT 'MEDIUM',
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX idx_organizations_domain ON organizations(domain);

CREATE INDEX idx_users_org ON users(org_id);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_role ON users(org_id, role);

CREATE INDEX idx_identities_org ON identities(org_id);
CREATE INDEX idx_identities_platform ON identities(org_id, platform);
CREATE INDEX idx_identities_type ON identities(org_id, type);
CREATE INDEX idx_identities_active ON identities(org_id, is_active);
CREATE INDEX idx_identities_owner ON identities(org_id, owner);
CREATE INDEX idx_identities_last_used ON identities(last_used);
CREATE INDEX idx_identities_risk ON identities(org_id, is_active, last_used);

CREATE INDEX idx_risk_scores_identity ON risk_scores(identity_id);
CREATE INDEX idx_risk_scores_level ON risk_scores(level);
CREATE INDEX idx_risk_scores_score ON risk_scores(total_score DESC);

CREATE INDEX idx_alerts_org ON anomaly_alerts(org_id);
CREATE INDEX idx_alerts_identity ON anomaly_alerts(identity_id);
CREATE INDEX idx_alerts_severity ON anomaly_alerts(org_id, severity);
CREATE INDEX idx_alerts_resolved ON anomaly_alerts(org_id, resolved);
CREATE INDEX idx_alerts_created ON anomaly_alerts(created_at DESC);

CREATE INDEX idx_audit_logs_org ON audit_logs(org_id);
CREATE INDEX idx_audit_logs_identity ON audit_logs(identity_id);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_created ON audit_logs(created_at DESC);

CREATE INDEX idx_integrations_org ON integrations(org_id);
CREATE INDEX idx_integrations_platform ON integrations(org_id, platform);

CREATE INDEX idx_activity_events_org ON activity_events(org_id);
CREATE INDEX idx_activity_events_identity ON activity_events(identity_id);
CREATE INDEX idx_activity_events_timestamp ON activity_events(timestamp DESC);

CREATE INDEX idx_policy_rules_org ON policy_rules(org_id);

-- Triggers for updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_organizations_updated_at BEFORE UPDATE ON organizations
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_identities_updated_at BEFORE UPDATE ON identities
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_integrations_updated_at BEFORE UPDATE ON integrations
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_policy_rules_updated_at BEFORE UPDATE ON policy_rules
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_notification_settings_updated_at BEFORE UPDATE ON notification_settings
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Insert default organization (for testing)
INSERT INTO organizations (name, domain, plan) VALUES 
    ('Default Organization', 'example.com', 'starter');

-- Insert default admin user (password: admin123 - change in production!)
-- Password hash is bcrypt of 'admin123'
INSERT INTO users (org_id, email, password_hash, first_name, last_name, role) VALUES 
    ((SELECT id FROM organizations LIMIT 1), 
     'admin@example.com', 
     '$2b$10$YourHashHere.ChangeInProduction', 
     'Admin', 
     'User', 
     'superadmin');
