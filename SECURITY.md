# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.x     | ✅ Yes    |
| 1.x     | ❌ No     |

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

Please report security vulnerabilities by emailing: **security@nhishield.com**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if known)

You will receive a response within **48 hours** and a fix will be prioritized.

## Security Best Practices for Deployment

### Before Going Live

1. **Change all default passwords** — every value marked `CHANGE_ME` in `.env.example`
2. **Generate strong secrets**:
   ```bash
   # JWT Secret (64 bytes)
   node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
   # Encryption Key (exactly 32 chars)
   node -e "console.log(require('crypto').randomBytes(16).toString('hex'))"
   ```
3. **Enable mTLS** for internal service-to-service communication (set `TLS_CERT`, `TLS_KEY`, `TLS_CA`)
4. **Restrict database access** — PostgreSQL and Neo4j should NOT be exposed on public ports in production
5. **Use a reverse proxy** (nginx/Caddy) with TLS termination in front of the API
6. **Set `NODE_ENV=production`** — disables verbose error messages

### Architecture Security

- All passwords use **bcrypt** with cost factor 12
- Credentials stored with **AES-256-GCM** + PBKDF2 (480,000 iterations)
- JWT tokens are blacklisted on logout via Redis
- All API endpoints require authentication (except `/health` and `/api/docs`)
- **Rate limiting** applied globally (200 req/15min) and on auth endpoints (10 req/15min)
- **Helmet.js** sets all security headers (CSP, HSTS, X-Frame-Options, etc.)
- **mTLS** available for production deployments requiring mutual certificate authentication

### Known Limitations

- The `certs/` directory is ignored by `.gitignore` — you must generate certificates locally
- Default secrets in `.env.example` are intentionally weak — must be replaced before production
- OAuth SSO requires configuring callback URLs in your identity provider

## Dependency Security

Run regularly:
```bash
npm audit --audit-level=moderate  # Node.js dependencies
pip-audit                          # Python dependencies
```
