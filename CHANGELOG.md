# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-02-25

### Added
- ✅ Proper AES-256-GCM encryption for credentials (replaced insecure base64)
- ✅ Comprehensive crypto utility module (`backend/api/utils/crypto.js`)
- ✅ Full test suite for API endpoints (`backend/api/server.test.js`)
- ✅ Crypto utility tests (`backend/api/utils/crypto.test.js`)
- ✅ Comprehensive testing documentation (`TESTING.md`)
- ✅ Bug fixes documentation (`BUG_FIXES.md`)
- ✅ Contributing guidelines (`CONTRIBUTING.md`)
- ✅ GitHub Actions CI/CD pipeline (`.github/workflows/ci-cd.yml`)
- ✅ Input validation for integration platforms
- ✅ Audit logging for integration creation
- ✅ Encryption key validation and warnings

### Fixed
- 🔒 **CRITICAL**: Replaced base64 encoding with proper AES-256-GCM encryption for credentials
- 🔧 Updated Dockerfile to include `utils/` directory
- 🔧 Improved error messages (more specific, less generic)
- 🔧 Enhanced error handling throughout the codebase

### Changed
- 🔄 Encryption key now required and must be 32+ characters
- 🔄 Integration creation now validates platform names
- 🔄 Error responses now more informative while maintaining security

### Security
- 🔒 AES-256-GCM encryption with authentication tags
- 🔒 Unique IV per encryption operation
- 🔒 PBKDF2 password hashing with 480,000 iterations
- 🔒 Secure token generation utilities
- 🔒 Input validation to prevent injection attacks
- 🔒 Comprehensive security testing procedures

### Documentation
- 📖 Added comprehensive testing guide
- 📖 Added bug fixes documentation
- 📖 Added contributing guidelines
- 📖 Enhanced README with security notices
- 📖 Added code comments for complex logic

### Testing
- ✅ Backend API test suite (authentication, authorization, rate limiting)
- ✅ Crypto utility test suite (encryption, hashing, token generation)
- ✅ Security tests (SQL injection, XSS prevention)
- ✅ CI/CD pipeline with automated testing

## [1.0.0] - 2026-02-24

### Added
- Initial release of NHI Shield
- Discovery engine for GitHub, AWS, OpenAI, Slack, Google, Azure, GitLab
- Risk scoring engine
- Anomaly detection engine
- REST API with JWT authentication
- React frontend with TailwindCSS
- Neo4j graph database integration
- PostgreSQL for metadata storage
- Redis for caching and events
- InfluxDB for time-series data
- Qdrant for vector embeddings
- Docker Compose orchestration
- Role-based access control
- Rate limiting and security headers
- Health check endpoints
- Compliance reporting

### Security
- JWT authentication
- Bcrypt password hashing
- Helmet security headers
- CORS configuration
- Rate limiting on authentication endpoints

---

## Migration Guide

### Upgrading from 1.0.0 to 1.1.0

#### Required Changes

1. **Generate New Encryption Key**
```bash
# Generate a strong 32+ character key
openssl rand -base64 32
```

2. **Update .env File**
```bash
# Add or update ENCRYPTION_KEY
ENCRYPTION_KEY=your_newly_generated_32_char_key_here
```

3. **Re-encrypt Existing Credentials**
If you have existing integrations, you'll need to migrate them:

```bash
# Backup database first!
docker exec nhi-postgres pg_dump -U nhiadmin nhishield > backup.sql

# Run migration script (if provided)
node backend/api/scripts/migrate-encryption.js

# Or manually re-create integrations through the UI
```

4. **Rebuild Docker Images**
```bash
docker-compose down
docker-compose build
docker-compose up -d
```

5. **Verify Installation**
```bash
# Check health
curl http://localhost:3000/health

# Verify encryption is working
docker logs nhi-api 2>&1 | grep -i "encryption"
```

#### Optional Changes

- Update to newer dependency versions: `npm update`
- Enable additional security features in `.env`
- Review and update audit log retention policies

---

## Deprecation Notices

### Version 1.1.0
- **Base64 "encryption"** (removed) - Replaced with proper AES-256-GCM
- Old integration credentials format will be migrated automatically

---

## Known Issues

### Version 1.1.0
- None currently known

### Version 1.0.0
- ⚠️ Credentials stored with base64 encoding (NOT secure) - **FIXED in 1.1.0**
- Missing comprehensive test suite - **FIXED in 1.1.0**
- Incomplete error handling in some endpoints - **IMPROVED in 1.1.0**

---

## Contributors

Thank you to all contributors who helped make this release possible:

- NHI Shield Core Team
- Community contributors (see CONTRIBUTORS.md)

---

## Support

- **Documentation**: https://docs.nhi-shield.io
- **Issues**: https://github.com/your-org/nhi-shield/issues
- **Security**: security@nhi-shield.io
- **General**: support@nhi-shield.io

---

[1.1.0]: https://github.com/your-org/nhi-shield/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/your-org/nhi-shield/releases/tag/v1.0.0
