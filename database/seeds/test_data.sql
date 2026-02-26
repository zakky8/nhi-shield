-- ============================================================
-- NHI SHIELD — Seed Data
-- Creates realistic test data for development
-- Run AFTER migrations: psql $DATABASE_URL < database/seeds/test_data.sql
-- WARNING: DO NOT run in production
-- ============================================================

-- Organization
INSERT INTO organizations (id, name, domain, plan) VALUES
    ('a0000000-0000-0000-0000-000000000001', 'TestOrg', 'testorg.com', 'business')
ON CONFLICT (id) DO NOTHING;

-- Admin user (password: Test1234!)
-- Hash generated with bcrypt rounds=12
INSERT INTO users (id, org_id, email, password_hash, role, mfa_enabled) VALUES
    (
        'b0000000-0000-0000-0000-000000000001',
        'a0000000-0000-0000-0000-000000000001',
        'admin@testorg.com',
        '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj3oW4yH5.5e',
        'admin',
        false
    ),
    (
        'b0000000-0000-0000-0000-000000000002',
        'a0000000-0000-0000-0000-000000000001',
        'analyst@testorg.com',
        '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj3oW4yH5.5e',
        'analyst',
        false
    )
ON CONFLICT (email) DO NOTHING;

-- ── 10 Sample NHI Identities ──────────────────────────────────
INSERT INTO identities
    (id, org_id, name, platform, type, permissions, owner, is_active, last_used, metadata, external_id)
VALUES

-- 1. GitHub Actions Bot - ACTIVE, well maintained
(
    'c0000000-0000-0000-0000-000000000001',
    'a0000000-0000-0000-0000-000000000001',
    'github-ci-deploy-bot',
    'github', 'github_app',
    ARRAY['contents:read', 'deployments:write', 'actions:read'],
    'admin@testorg.com',
    true,
    NOW() - INTERVAL '1 day',
    '{"app_id": 12345, "repository_selection": "selected", "repos": ["app", "infra"]}',
    'github-app-12345'
),

-- 2. AWS Lambda Execution Role - HIGH RISK (admin access)
(
    'c0000000-0000-0000-0000-000000000002',
    'a0000000-0000-0000-0000-000000000001',
    'lambda-data-processor-role',
    'aws', 'iam_role',
    ARRAY['AdministratorAccess'],
    NULL,
    true,
    NOW() - INTERVAL '5 days',
    '{"arn": "arn:aws:iam::123456789:role/lambda-data-processor", "trust_policy": "lambda.amazonaws.com"}',
    'aws-role-ABCDEF123456'
),

-- 3. OpenAI API Key - CRITICAL (no expiry, high usage)
(
    'c0000000-0000-0000-0000-000000000003',
    'a0000000-0000-0000-0000-000000000001',
    'prod-gpt4-integration-key',
    'openai', 'api_key',
    ARRAY['api_access'],
    'dev@testorg.com',
    true,
    NOW() - INTERVAL '2 hours',
    '{"key_id": "key-abc123", "usage_30d": 450000, "has_expiry": false, "model_access": ["gpt-4", "gpt-3.5-turbo"]}',
    'openai-key-abc123'
),

-- 4. Slack Customer Support Bot - ACTIVE
(
    'c0000000-0000-0000-0000-000000000004',
    'a0000000-0000-0000-0000-000000000001',
    'helpdesk-support-bot',
    'slack', 'slack_app',
    ARRAY['chat:write', 'channels:read', 'users:read'],
    'ops@testorg.com',
    true,
    NOW() - INTERVAL '30 minutes',
    '{"app_id": "A0123456", "installed_by": "ops@testorg.com", "workspace": "T0123456"}',
    'slack-app-A0123456'
),

-- 5. AWS Service Account - DORMANT (not used in 6 months)
(
    'c0000000-0000-0000-0000-000000000005',
    'a0000000-0000-0000-0000-000000000001',
    'old-backup-service-account',
    'aws', 'service_account',
    ARRAY['AmazonS3FullAccess', 'AmazonRDSReadOnlyAccess'],
    NULL,
    true,
    NOW() - INTERVAL '210 days',
    '{"arn": "arn:aws:iam::123456789:user/backup-svc", "access_key_age_days": 380}',
    'aws-user-BACKUP123'
),

-- 6. GitHub Deploy Key (write access) - HIGH RISK
(
    'c0000000-0000-0000-0000-000000000006',
    'a0000000-0000-0000-0000-000000000001',
    'prod-deploy-key-2022',
    'github', 'deploy_key',
    ARRAY['read', 'write'],
    NULL,
    true,
    NOW() - INTERVAL '95 days',
    '{"repo": "production-app", "read_only": false, "key_age_days": 720}',
    'github-deploy-key-789'
),

-- 7. Slack Admin Bot - CRITICAL (has admin scopes)
(
    'c0000000-0000-0000-0000-000000000007',
    'a0000000-0000-0000-0000-000000000001',
    'workspace-admin-automation',
    'slack', 'slack_app',
    ARRAY['admin', 'users:write', 'channels:manage', 'chat:write', 'files:write'],
    'unknown@testorg.com',
    true,
    NOW() - INTERVAL '3 days',
    '{"app_id": "A9999999", "admin_scopes": true, "installed_2021": true}',
    'slack-app-A9999999'
),

-- 8. AWS Lambda Role (well configured, low risk)
(
    'c0000000-0000-0000-0000-000000000008',
    'a0000000-0000-0000-0000-000000000001',
    'email-sender-lambda-role',
    'aws', 'lambda_role',
    ARRAY['ses:SendEmail', 'logs:CreateLogGroup', 'logs:PutLogEvents'],
    'devops@testorg.com',
    true,
    NOW() - INTERVAL '4 hours',
    '{"arn": "arn:aws:iam::123456789:role/email-sender", "function": "send-transactional-email"}',
    'aws-role-EMAILSENDER'
),

-- 9. OpenAI Key - INACTIVE/ABANDONED
(
    'c0000000-0000-0000-0000-000000000009',
    'a0000000-0000-0000-0000-000000000001',
    'old-chatbot-test-key',
    'openai', 'api_key',
    ARRAY['api_access'],
    NULL,
    true,
    NOW() - INTERVAL '150 days',
    '{"key_id": "key-old999", "usage_30d": 0, "has_expiry": false, "created_2023": true}',
    'openai-key-old999'
),

-- 10. GitHub App - ACTIVE, properly managed
(
    'c0000000-0000-0000-0000-000000000010',
    'a0000000-0000-0000-0000-000000000001',
    'dependabot-security-updates',
    'github', 'github_app',
    ARRAY['contents:read', 'pull_requests:write', 'security_events:read'],
    'admin@testorg.com',
    true,
    NOW() - INTERVAL '6 hours',
    '{"app_id": 67890, "repository_selection": "all", "auto_updates": true}',
    'github-app-67890'
);

-- ── Risk Scores for each identity ────────────────────────────
INSERT INTO risk_scores (identity_id, org_id, total_score, level, factors, recommendations) VALUES

-- 1. GitHub CI Bot - LOW
('c0000000-0000-0000-0000-000000000001', 'a0000000-0000-0000-0000-000000000001',
 12, 'LOW',
 '{"dormancy": 0, "permissions": 5, "hygiene": 5, "anomalies": 0, "age": 2}',
 '["Consider setting an expiry date on the GitHub App credentials"]'
),

-- 2. AWS Lambda Admin Role - CRITICAL
('c0000000-0000-0000-0000-000000000002', 'a0000000-0000-0000-0000-000000000001',
 82, 'CRITICAL',
 '{"dormancy": 0, "permissions": 55, "hygiene": 15, "anomalies": 0, "age": 12}',
 '["CRITICAL: Remove AdministratorAccess — apply least privilege immediately", "Assign an owner to this role", "Review and restrict IAM role permissions"]'
),

-- 3. OpenAI Prod Key - HIGH
('c0000000-0000-0000-0000-000000000003', 'a0000000-0000-0000-0000-000000000001',
 58, 'HIGH',
 '{"dormancy": 0, "permissions": 10, "hygiene": 25, "anomalies": 0, "age": 8}',
 '["Set an expiry date on this API key", "Consider rotating credentials", "Restrict key usage by IP address"]'
),

-- 4. Slack Support Bot - LOW
('c0000000-0000-0000-0000-000000000004', 'a0000000-0000-0000-0000-000000000001',
 15, 'LOW',
 '{"dormancy": 0, "permissions": 5, "hygiene": 5, "anomalies": 0, "age": 5}',
 '["Configuration looks good — no immediate action required"]'
),

-- 5. Dormant AWS Service Account - HIGH
('c0000000-0000-0000-0000-000000000005', 'a0000000-0000-0000-0000-000000000001',
 68, 'HIGH',
 '{"dormancy": 35, "permissions": 15, "hygiene": 15, "anomalies": 0, "age": 3}',
 '["NOT USED IN 210 DAYS — consider offboarding immediately", "No owner assigned — assign accountability", "Access keys are 380 days old — rotate or revoke"]'
),

-- 6. GitHub Deploy Key (write) - HIGH
('c0000000-0000-0000-0000-000000000006', 'a0000000-0000-0000-0000-000000000001',
 62, 'HIGH',
 '{"dormancy": 10, "permissions": 20, "hygiene": 25, "anomalies": 0, "age": 7}',
 '["Write-access deploy key is high risk — switch to read-only where possible", "No owner assigned", "Key is 720 days old — rotate immediately"]'
),

-- 7. Slack Admin Bot - CRITICAL
('c0000000-0000-0000-0000-000000000007', 'a0000000-0000-0000-0000-000000000001',
 79, 'CRITICAL',
 '{"dormancy": 0, "permissions": 45, "hygiene": 15, "anomalies": 0, "age": 12}',
 '["CRITICAL: Has workspace admin permissions — verify this is required", "Remove unused admin scopes", "Review who installed this app and why"]'
),

-- 8. Email Lambda Role - LOW
('c0000000-0000-0000-0000-000000000008', 'a0000000-0000-0000-0000-000000000001',
 18, 'LOW',
 '{"dormancy": 0, "permissions": 5, "hygiene": 5, "anomalies": 0, "age": 3}',
 '["Well configured — minimal permissions as expected"]'
),

-- 9. Old OpenAI Test Key - HIGH
('c0000000-0000-0000-0000-000000000009', 'a0000000-0000-0000-0000-000000000001',
 65, 'HIGH',
 '{"dormancy": 35, "permissions": 10, "hygiene": 15, "anomalies": 0, "age": 5}',
 '["NOT USED IN 150 DAYS — offboard this key", "No owner assigned — key may be orphaned", "Revoke and delete if no longer needed"]'
),

-- 10. Dependabot App - LOW
('c0000000-0000-0000-0000-000000000010', 'a0000000-0000-0000-0000-000000000001',
 10, 'LOW',
 '{"dormancy": 0, "permissions": 5, "hygiene": 5, "anomalies": 0, "age": 0}',
 '["No action required — properly configured"]'
);

-- ── Sample Alerts (2 HIGH, 1 CRITICAL) ───────────────────────
INSERT INTO anomaly_alerts
    (org_id, identity_id, severity, type, description, confidence, evidence, resolved)
VALUES

-- CRITICAL alert on Slack Admin Bot
(
    'a0000000-0000-0000-0000-000000000001',
    'c0000000-0000-0000-0000-000000000007',
    'CRITICAL',
    'UNUSUAL_TIME',
    'Slack admin bot accessed workspace user list at 3:14 AM — outside all normal activity windows',
    0.94,
    '{"hour": 3, "action": "users.list", "ip": "203.0.113.45", "country": "Unknown", "normal_hours": "9:00-18:00"}',
    false
),

-- HIGH alert on dormant service account (new activity after long silence)
(
    'a0000000-0000-0000-0000-000000000001',
    'c0000000-0000-0000-0000-000000000005',
    'HIGH',
    'VOLUME_SPIKE',
    'Dormant service account (inactive 210 days) made 847 S3 GetObject calls in 1 hour — 500x normal rate',
    0.97,
    '{"current_count": 847, "avg_count": 1.7, "multiplier": 498, "bucket": "prod-customer-data", "hours_active": 1}',
    false
),

-- HIGH alert on OpenAI key access from new region
(
    'a0000000-0000-0000-0000-000000000001',
    'c0000000-0000-0000-0000-000000000003',
    'HIGH',
    'SENSITIVE_RESOURCE_ACCESS',
    'OpenAI production key accessed from new IP region (Eastern Europe) — first time in 8 months of operation',
    0.78,
    '{"new_country": "Romania", "prev_countries": ["US", "IN"], "resource": "gpt-4", "action": "chat.completion"}',
    false
);

-- ── Integrations table (connected platforms) ─────────────────
-- NOTE: credentials are placeholder bytes — real ones would be AES-256 encrypted
INSERT INTO integrations (org_id, platform, credentials, is_active, last_sync, last_sync_count) VALUES
('a0000000-0000-0000-0000-000000000001', 'github',  '\xDEADBEEF'::bytea, true, NOW() - INTERVAL '2 hours', 4),
('a0000000-0000-0000-0000-000000000001', 'aws',     '\xDEADBEEF'::bytea, true, NOW() - INTERVAL '2 hours', 3),
('a0000000-0000-0000-0000-000000000001', 'openai',  '\xDEADBEEF'::bytea, true, NOW() - INTERVAL '2 hours', 2),
('a0000000-0000-0000-0000-000000000001', 'slack',   '\xDEADBEEF'::bytea, true, NOW() - INTERVAL '2 hours', 2)
ON CONFLICT (org_id, platform) DO NOTHING;

-- ── Audit log entries ─────────────────────────────────────────
INSERT INTO audit_logs (org_id, action, performed_by, reason, new_state) VALUES
(
    'a0000000-0000-0000-0000-000000000001',
    'SYSTEM_STARTUP',
    NULL,
    'NHI Shield initialized with seed data',
    '{"seed_version": "1.0", "identities_created": 10}'
);
