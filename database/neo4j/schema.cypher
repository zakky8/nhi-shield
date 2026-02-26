-- NHI Shield - Neo4j Graph Database Schema
-- Run these commands in Neo4j Browser or via cypher-shell

-- Create constraints and indexes
CREATE CONSTRAINT identity_id IF NOT EXISTS
    FOR (n:NHIdentity) REQUIRE n.id IS UNIQUE;

CREATE CONSTRAINT platform_name IF NOT EXISTS
    FOR (p:Platform) REQUIRE p.name IS UNIQUE;

CREATE CONSTRAINT resource_id IF NOT EXISTS
    FOR (r:Resource) REQUIRE r.id IS UNIQUE;

CREATE CONSTRAINT user_email IF NOT EXISTS
    FOR (u:User) REQUIRE u.email IS UNIQUE;

CREATE INDEX identity_platform IF NOT EXISTS
    FOR (n:NHIdentity) ON (n.platform);

CREATE INDEX identity_type IF NOT EXISTS
    FOR (n:NHIdentity) ON (n.type);

CREATE INDEX identity_risk_level IF NOT EXISTS
    FOR (n:NHIdentity) ON (n.risk_level);

CREATE INDEX identity_is_active IF NOT EXISTS
    FOR (n:NHIdentity) ON (n.is_active);

-- Create full-text index for search
CREATE FULLTEXT INDEX identitySearch IF NOT EXISTS
    FOR (n:NHIdentity) ON EACH [n.name, n.owner];

-- Sample data insertion (for testing)
// Create platforms
MERGE (aws:Platform {name: 'aws'})
    SET aws.type = 'cloud', aws.description = 'Amazon Web Services';

MERGE (github:Platform {name: 'github'})
    SET github.type = 'devops', github.description = 'GitHub';

MERGE (slack:Platform {name: 'slack'})
    SET slack.type = 'communication', slack.description = 'Slack';

MERGE (openai:Platform {name: 'openai'})
    SET openai.type = 'ai', openai.description = 'OpenAI';

MERGE (google:Platform {name: 'google'})
    SET google.type = 'cloud', google.description = 'Google Cloud Platform';

MERGE (azure:Platform {name: 'azure'})
    SET azure.type = 'cloud', azure.description = 'Microsoft Azure';

// Create sample identities
MERGE (n1:NHIdentity {id: 'aws-user-AIDA1234567890'})
    SET n1.name = 'deploy-bot',
        n1.platform = 'aws',
        n1.type = 'service_account',
        n1.permissions = ['ec2:DescribeInstances', 's3:GetObject'],
        n1.owner = 'devops-team',
        n1.is_active = true,
        n1.risk_level = 'MEDIUM',
        n1.created_at = datetime(),
        n1.updated_at = datetime();

MERGE (n2:NHIdentity {id: 'github-app-123456'})
    SET n2.name = 'ci-cd-app',
        n2.platform = 'github',
        n2.type = 'github_app',
        n2.permissions = ['contents:write', 'actions:read'],
        n2.owner = 'platform-team',
        n2.is_active = true,
        n2.risk_level = 'LOW',
        n2.created_at = datetime(),
        n2.updated_at = datetime();

MERGE (n3:NHIdentity {id: 'openai-key-sk-abc123'})
    SET n3.name = 'ai-assistant-key',
        n3.platform = 'openai',
        n3.type = 'api_key',
        n3.permissions = ['api_access'],
        n3.owner = 'ai-team',
        n3.is_active = true,
        n3.risk_level = 'HIGH',
        n3.created_at = datetime(),
        n3.updated_at = datetime();

// Create relationships
MATCH (n1:NHIdentity {id: 'aws-user-AIDA1234567890'}), (aws:Platform {name: 'aws'})
MERGE (n1)-[:BELONGS_TO]->(aws);

MATCH (n2:NHIdentity {id: 'github-app-123456'}), (github:Platform {name: 'github'})
MERGE (n2)-[:BELONGS_TO]->(github);

MATCH (n3:NHIdentity {id: 'openai-key-sk-abc123'}), (openai:Platform {name: 'openai'})
MERGE (n3)-[:BELONGS_TO]->(openai);

// Create identity-to-identity relationships (chain attack scenario)
MATCH (n1:NHIdentity {id: 'aws-user-AIDA1234567890'}), (n2:NHIdentity {id: 'github-app-123456'})
MERGE (n1)-[:CAN_IMPERSONATE {reason: 'shared_credentials', discovered_at: datetime()}]->(n2);

// Create resource access relationships
MERGE (r1:Resource {id: 's3://production-data', name: 'Production S3 Bucket', type: 'storage'})
MERGE (r2:Resource {id: 'arn:aws:rds:us-east-1:123456789:db:production', name: 'Production Database', type: 'database', sensitivity: 'critical'});

MATCH (n1:NHIdentity {id: 'aws-user-AIDA1234567890'}), (r1:Resource {id: 's3://production-data'})
MERGE (n1)-[:CAN_ACCESS {permission: 'read', scope: 'bucket'}]->(r1);

MATCH (n1:NHIdentity {id: 'aws-user-AIDA1234567890'}), (r2:Resource {id: 'arn:aws:rds:us-east-1:123456789:db:production'})
MERGE (n1)-[:CAN_ACCESS {permission: 'write', scope: 'database'}]->(r2);

// Query examples for the application

// Get all identities with their platforms
// MATCH (n:NHIdentity)-[:BELONGS_TO]->(p:Platform) RETURN n, p;

// Get identity graph (connections up to 3 hops)
// MATCH path = (n:NHIdentity {id: $id})-[:CAN_IMPERSONATE|CAN_ACCESS*1..3]-(connected) RETURN path;

// Find potential chain attacks (identities that can impersonate others)
// MATCH (n1:NHIdentity)-[:CAN_IMPERSONATE]->(n2:NHIdentity)-[:CAN_IMPERSONATE]->(n3:NHIdentity) RETURN n1, n2, n3;

// Find identities with access to critical resources
// MATCH (n:NHIdentity)-[:CAN_ACCESS]->(r:Resource {sensitivity: 'critical'}) RETURN n, r;

// Get risk distribution
// MATCH (n:NHIdentity) RETURN n.risk_level as level, count(n) as count;
