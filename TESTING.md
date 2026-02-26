# NHI Shield - Testing & Debugging Guide

## Overview
This document provides comprehensive testing procedures and debugging steps for the NHI Shield platform.

## Table of Contents
1. [Pre-Deployment Testing](#pre-deployment-testing)
2. [Manual Testing](#manual-testing)
3. [Automated Testing](#automated-testing)
4. [Integration Testing](#integration-testing)
5. [Security Testing](#security-testing)
6. [Performance Testing](#performance-testing)
7. [Debugging Guide](#debugging-guide)

---

## Pre-Deployment Testing

### 1. Environment Setup Verification

```bash
# Verify Docker is installed and running
docker --version
docker-compose --version

# Check system resources
docker system df
free -h

# Verify environment variables
cat .env.example
```

### 2. Configuration Validation

```bash
# Check all required environment variables are set
grep -E '^[A-Z_]+=' .env

# Validate encryption key length (must be 32+ characters)
echo $ENCRYPTION_KEY | wc -c
```

---

## Manual Testing

### 1. Database Services

```bash
# Start only database services
cd docker
docker-compose up -d postgres neo4j redis influxdb qdrant

# Test PostgreSQL connection
docker exec -it nhi-postgres psql -U nhiadmin -d nhishield -c "SELECT 1;"

# Test Neo4j connection
docker exec -it nhi-neo4j cypher-shell -u neo4j -p $NEO4J_PASSWORD "RETURN 1;"

# Test Redis connection
docker exec -it nhi-redis redis-cli -a $REDIS_PASSWORD ping

# Test InfluxDB connection
curl http://localhost:8086/health

# Test Qdrant connection
curl http://localhost:6333/healthz
```

### 2. API Server Testing

```bash
# Start API server
docker-compose up -d api

# Wait for health check
sleep 10

# Test health endpoint
curl http://localhost:3000/health

# Test authentication endpoint (should fail without credentials)
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"wrong"}'

# Test rate limiting
for i in {1..6}; do
  curl -X POST http://localhost:3000/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"test@example.com","password":"test"}' &
done
wait
```

### 3. Frontend Testing

```bash
# Start frontend
docker-compose up -d frontend

# Wait for startup
sleep 10

# Test frontend is serving
curl -I http://localhost/

# Check console logs
docker logs nhi-frontend
```

### 4. Discovery Engine Testing

```bash
# Test discovery engine
docker-compose up -d discovery

# Check logs
docker logs -f nhi-discovery

# Verify discoveries are being stored
docker exec -it nhi-postgres psql -U nhiadmin -d nhishield -c \
  "SELECT COUNT(*) FROM identities;"
```

---

## Automated Testing

### 1. Backend API Tests

```bash
cd backend/api

# Install test dependencies
npm install --save-dev jest supertest

# Run tests
npm test

# Run tests with coverage
npm test -- --coverage

# Run tests in watch mode
npm test -- --watch
```

### 2. Frontend Tests

```bash
cd frontend

# Run React tests
npm test

# Run tests with coverage
npm test -- --coverage --watchAll=false

# Run E2E tests (if configured)
npm run test:e2e
```

### 3. Python Service Tests

```bash
cd backend/discovery

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
pip install pytest pytest-asyncio pytest-cov

# Run tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=. --cov-report=html
```

---

## Integration Testing

### 1. End-to-End Workflow Test

```bash
#!/bin/bash
# test_e2e.sh - Complete workflow test

set -e

echo "=== NHI Shield E2E Test ==="

# 1. Start all services
echo "Starting services..."
cd docker
docker-compose up -d
sleep 30

# 2. Test health endpoints
echo "Testing health endpoints..."
curl -f http://localhost:3000/health || exit 1
curl -f http://localhost/ || exit 1

# 3. Create test user (requires database seeding)
echo "Testing authentication..."
TOKEN=$(curl -s -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"admin123"}' \
  | jq -r '.token')

if [ "$TOKEN" = "null" ] || [ -z "$TOKEN" ]; then
  echo "Authentication failed"
  exit 1
fi

# 4. Test protected endpoints
echo "Testing protected endpoints..."
curl -f -H "Authorization: Bearer $TOKEN" \
  http://localhost:3000/api/identities || exit 1

# 5. Test integration creation
echo "Testing integration creation..."
curl -f -X POST http://localhost:3000/api/integrations \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"platform":"github","name":"Test Integration","config":{"token":"test_token","org":"test_org"}}' \
  || exit 1

# 6. Test dashboard stats
echo "Testing dashboard..."
curl -f -H "Authorization: Bearer $TOKEN" \
  http://localhost:3000/api/dashboard/stats || exit 1

echo "✓ All E2E tests passed!"
```

### 2. Load Testing

```bash
# Install Apache Bench or use alternative
# Test login endpoint under load
ab -n 1000 -c 10 -p login.json -T application/json \
  http://localhost:3000/api/auth/login

# Test read endpoints
ab -n 5000 -c 50 -H "Authorization: Bearer $TOKEN" \
  http://localhost:3000/api/identities
```

---

## Security Testing

### 1. Authentication & Authorization Tests

```bash
# Test JWT validation
curl -H "Authorization: Bearer invalid_token" \
  http://localhost:3000/api/identities

# Test expired token
# (Create a token with 1s expiry, wait, then try to use it)

# Test role-based access control
curl -X POST -H "Authorization: Bearer $USER_TOKEN" \
  http://localhost:3000/api/integrations \
  -d '{"platform":"test","config":{}}' \
  # Should fail with 403 if user doesn't have admin role
```

### 2. Input Validation Tests

```bash
# Test SQL injection prevention
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com'\'' OR 1=1--","password":"test"}'

# Test XSS prevention
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"<script>alert(1)</script>@test.com","password":"test"}'

# Test command injection (should be sanitized)
curl -X POST -H "Authorization: Bearer $TOKEN" \
  http://localhost:3000/api/integrations \
  -d '{"platform":"github","name":"test; rm -rf /","config":{}}'
```

### 3. Encryption Testing

```bash
# Verify data is encrypted at rest
docker exec -it nhi-postgres psql -U nhiadmin -d nhishield -c \
  "SELECT credentials FROM integrations LIMIT 1;"
# Should show encrypted JSON, not plain text
```

### 4. Rate Limiting Tests

```bash
# Test authentication rate limit (should block after 5 attempts)
for i in {1..10}; do
  echo "Attempt $i"
  curl -w "\nHTTP Status: %{http_code}\n" \
    -X POST http://localhost:3000/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"test@test.com","password":"test"}'
  sleep 1
done
```

---

## Performance Testing

### 1. Response Time Testing

```bash
# Measure endpoint response times
curl -w "\nTime: %{time_total}s\n" \
  -H "Authorization: Bearer $TOKEN" \
  http://localhost:3000/api/dashboard/stats

# Benchmark multiple endpoints
for endpoint in "/api/identities" "/api/alerts" "/api/dashboard/stats"; do
  echo "Testing $endpoint"
  time curl -s -H "Authorization: Bearer $TOKEN" \
    "http://localhost:3000$endpoint" > /dev/null
done
```

### 2. Database Query Performance

```bash
# Check slow queries in PostgreSQL
docker exec -it nhi-postgres psql -U nhiadmin -d nhishield -c \
  "SELECT query, calls, total_time, mean_time FROM pg_stat_statements 
   ORDER BY mean_time DESC LIMIT 10;"

# Check Neo4j query performance
docker exec -it nhi-neo4j cypher-shell -u neo4j -p $NEO4J_PASSWORD \
  "CALL dbms.queryJmx('org.neo4j:*') YIELD name, attributes 
   WHERE name CONTAINS 'Queries' RETURN name, attributes;"
```

### 3. Memory & Resource Usage

```bash
# Monitor container resource usage
docker stats nhi-api nhi-postgres nhi-neo4j nhi-redis

# Check logs for memory issues
docker logs nhi-api 2>&1 | grep -i "memory\|oom"
```

---

## Debugging Guide

### 1. Common Issues & Solutions

#### Issue: Services won't start
```bash
# Check logs
docker-compose logs

# Check specific service
docker logs nhi-api

# Verify port availability
netstat -tulpn | grep -E ':(3000|5432|7687|6379|8086|6333)'

# Restart services
docker-compose down
docker-compose up -d
```

#### Issue: Database connection errors
```bash
# Check database is running
docker ps | grep postgres

# Test connection manually
docker exec -it nhi-postgres psql -U nhiadmin -d nhishield

# Check environment variables
docker exec nhi-api env | grep DATABASE_URL

# Reset database
docker-compose down -v  # WARNING: Deletes all data
docker-compose up -d
```

#### Issue: Authentication fails
```bash
# Verify JWT secret is set
docker exec nhi-api env | grep JWT_SECRET

# Check user exists in database
docker exec -it nhi-postgres psql -U nhiadmin -d nhishield -c \
  "SELECT * FROM users WHERE email='admin@example.com';"

# Reset admin password (if needed)
docker exec -it nhi-postgres psql -U nhiadmin -d nhishield -c \
  "UPDATE users SET password_hash='$2b$10$...' 
   WHERE email='admin@example.com';"
```

#### Issue: Discovery engine not finding identities
```bash
# Check integration configuration
docker exec -it nhi-postgres psql -U nhiadmin -d nhishield -c \
  "SELECT * FROM integrations WHERE is_active=true;"

# Verify API tokens are valid
docker exec nhi-discovery python -c "
import os
print('GITHUB_TOKEN:', os.getenv('GITHUB_TOKEN'))
"

# Test API connections manually
docker exec nhi-discovery curl -H "Authorization: Bearer $GITHUB_TOKEN" \
  https://api.github.com/user
```

### 2. Debug Mode

Enable verbose logging:
```bash
# Set log level
export LOG_LEVEL=debug

# Restart with debug logging
docker-compose down
LOG_LEVEL=debug docker-compose up
```

### 3. Interactive Debugging

```bash
# Access container shell
docker exec -it nhi-api sh

# Run Node.js REPL with app context
docker exec -it nhi-api node

# Access Python shell
docker exec -it nhi-discovery python
```

### 4. Database Debugging

```bash
# PostgreSQL: View all tables
docker exec -it nhi-postgres psql -U nhiadmin -d nhishield -c "\dt"

# PostgreSQL: View table schema
docker exec -it nhi-postgres psql -U nhiadmin -d nhishield -c \
  "\d+ identities"

# Neo4j: View all nodes
docker exec -it nhi-neo4j cypher-shell -u neo4j -p $NEO4J_PASSWORD \
  "MATCH (n) RETURN labels(n), count(n);"

# Redis: View all keys
docker exec -it nhi-redis redis-cli -a $REDIS_PASSWORD keys "*"
```

---

## Continuous Integration Testing

### GitHub Actions Workflow Example

```yaml
name: CI/CD

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '20'
      
      - name: Install dependencies
        run: |
          cd backend/api
          npm ci
      
      - name: Run tests
        run: |
          cd backend/api
          npm test
      
      - name: Run linter
        run: |
          cd backend/api
          npm run lint
```

---

## Test Checklist

Before deploying to production:

- [ ] All unit tests pass
- [ ] All integration tests pass
- [ ] Security tests show no vulnerabilities
- [ ] Load tests meet performance requirements
- [ ] All environment variables are properly set
- [ ] Encryption keys are strong and unique
- [ ] Database migrations run successfully
- [ ] Health checks return 200
- [ ] Logs show no errors
- [ ] Resource usage is within acceptable limits
- [ ] Backup strategy is in place
- [ ] Monitoring is configured

---

## Support

For issues during testing:
1. Check logs: `docker-compose logs [service-name]`
2. Review this debugging guide
3. Check GitHub issues: https://github.com/your-org/nhi-shield/issues
4. Contact support: support@nhi-shield.io
