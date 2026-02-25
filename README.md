# NHI Shield 🛡️

**Industrial-grade Non-Human Identity (NHI) Security Platform**

> Discover, monitor, and secure every AI agent, API key, service account, and bot across your entire infrastructure — in real time.

[![CI/CD](https://img.shields.io/badge/CI-GitHub_Actions-blue)](/.github/workflows/ci-cd.yml)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED)](docker/docker-compose.yml)
[![Security](https://img.shields.io/badge/Encryption-AES--256--GCM-red)](backend/security/vault.py)

---

## 🎯 What is NHI Shield?

Non-Human Identities — API keys, service accounts, OAuth tokens, AI agent credentials, deploy keys, bots — now outnumber human users **45:1** in enterprise environments. NHI Shield is the purpose-built security platform for this problem.

### Core Capabilities

| Feature | Status |
|---------|--------|
| Automatic discovery (13 platforms) | ✅ Production |
| ML anomaly detection (Isolation Forest + Qdrant) | ✅ Production |
| Zero Trust policy engine (5-layer) | ✅ Production |
| Automated secret rotation (blue-green) | ✅ Production |
| Shadow AI detection (GitHub scan + AWS) | ✅ Production |
| Compliance reports PDF (SOC2/GDPR/ISO27001/PCI/HIPAA) | ✅ Production |
| Permission analyzer with remediation scripts | ✅ Production |
| Predictive risk scoring (7-day forecast) | ✅ Production |
| Chain attack detection (Neo4j graph) | ✅ Production |
| Lifecycle manager (auto-offboarding) | ✅ Production |
| Versioned credential vault (AES-256-GCM) | ✅ Production |
| Real-time dashboard (React + D3.js + WebSocket) | ✅ Production |
| SSO (Google / Azure AD / Okta PKCE) | ✅ Production |
| Public REST API v1 with API keys | ✅ Production |
| Webhooks (HMAC-signed) | ✅ Production |
| mTLS between all services | ✅ Production |
| Kubernetes manifests | ✅ Production |
| Prometheus + Grafana monitoring | ✅ Production |
| Step-up MFA (TOTP) | ✅ Production |
| Quantum-safe crypto (X25519-HKDF hybrid) | ✅ Production |

---

## 🏗️ Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│                      NHI Shield Platform                           │
│                                                                    │
│  React Frontend  ←WebSocket→  Node.js API v2     Python Services  │
│  (Tailwind/D3)                (Express + JWT)     ┌─────────────┐ │
│       ↑                            │              │ML Anomaly   │ │
│  Nginx/TLS                   Zero Trust           │(IF + Qdrant)│ │
│                              Policy Engine         ├─────────────┤ │
│                                    │              │Predictive   │ │
│           ┌────────────────────────┼──────────────│Risk Scorer  │ │
│           │            │           │              ├─────────────┤ │
│       PostgreSQL     Neo4j       Redis            │Discovery    │ │
│       (core data)  (graph rels) (pub/sub)         │Engine       │ │
│                                                   ├─────────────┤ │
│       InfluxDB       Qdrant                       │Lifecycle    │ │
│       (timeseries)  (embeddings)                  │Shadow AI    │ │
│                                                   │Permissions  │ │
│       Prometheus + Grafana                        │Compliance   │ │
│       (observability)                             └─────────────┘ │
└────────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start (5 minutes)

### Prerequisites
- Docker & Docker Compose v2
- Git, OpenSSL

### Setup

```bash
# 1. Clone
git clone https://github.com/your-org/nhi-shield.git
cd nhi-shield

# 2. Configure environment
cp .env.example .env
# Edit .env — set JWT_SECRET, ENCRYPTION_KEY, DB_PASSWORD

# 3. Generate mTLS certificates
bash scripts/mtls/generate-certs.sh

# 4. Start all services
make up

# 5. Run migrations
make migrate

# 6. Health check
make health
```

**Dashboard:** http://localhost  
**Login:** `admin@testorg.com` / `Test1234!`

---

## 📦 Services

| Service | Port | Description |
|---------|------|-------------|
| Frontend | 80, 443 | React + Nginx |
| API | 3000 | Node.js Express + Socket.IO |
| PostgreSQL | 5432 | Primary data store |
| Neo4j | 7474, 7687 | Identity relationship graph |
| Redis | 6379 | Cache, pub/sub, dedup |
| InfluxDB | 8086 | Activity time-series |
| Qdrant | 6333 | ML behavioral embeddings |
| Prometheus | 9090 | Metrics scraping |
| Grafana | 3001 | Dashboards |

---

## 🛡️ Security Architecture

### Encryption
- AES-256-GCM with per-record IV and authentication tag
- PBKDF2 key derivation (480,000 iterations, OWASP 2024)
- Per-record salt in versioned credential vault
- X25519-HKDF hybrid scheme (post-quantum migration path)

### Zero Trust (5 Layers)
1. **Identity** — Active? Not offboarded?  
2. **Risk** — Score below threshold for this action class?  
3. **Permission** — Not on deny list? Not a sensitive action requiring MFA?  
4. **Context** — Impossible travel? IP change?  
5. **Time** — Weekend off-hours sensitive action?

### ML Detection
- **Isolation Forest** (200 estimators, 5% contamination) trained nightly
- **128-dimension** behavioral vectors per identity
- **Qdrant cosine similarity** drift detection vs. 30-day baseline
- **EMA updates** (α=0.1) — baselines evolve without catastrophic forgetting

---

## 🔌 Integrations

Configure in `.env` or via dashboard:

```
GitHub, AWS IAM, OpenAI, Slack, Anthropic, Okta, Google Cloud,
Azure AD, GitLab, Jira, Salesforce, HubSpot, Stripe, Twilio
```

---

## 📋 Compliance Reports

```bash
curl -X POST http://localhost:3000/api/reports/compliance/generate \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"report_type": "soc2"}' --output report.pdf

# Types: soc2 | gdpr | iso27001 | pci_dss | hipaa | summary
```

---

## 🔑 Public API

```bash
# List identities
GET /api/v1/identities
X-API-Key: nhi_xxxxx

# Trigger scan
POST /api/v1/scan
X-API-Key: nhi_xxxxx
```

---

## 🧪 Testing

```bash
make test                          # All tests
cd backend/api && npm test         # API + security tests
pytest backend/tests/ -v           # Python security tests
```

---

## 🏢 Kubernetes

```bash
kubectl apply -f k8s/
kubectl get pods -n nhi-shield
```

---

## 📁 Structure

```
nhi-shield/
├── backend/
│   ├── api/          Node.js API + utils (crypto, SSO, metrics)
│   ├── anomaly/      ML anomaly detection
│   ├── compliance/   PDF report generator
│   ├── discovery/    Platform connectors
│   ├── integrations/ Additional connectors (13 platforms)
│   ├── lifecycle/    Auto-offboarding manager
│   ├── permissions/  Least-privilege analyzer
│   ├── policy/       Zero Trust engine
│   ├── risk/         Predictive risk scorer
│   ├── security/     Vault, rotation, quantum crypto
│   └── shadow/       Shadow AI detector
├── database/migrations/  001 → 002 → 003
├── docker/           Compose + Nginx + Prometheus
├── frontend/src/     React app (11 pages, D3.js graph)
├── k8s/              Kubernetes manifests
└── scripts/mtls/     Certificate generation
```

---

## 🔐 Security Disclosure

Found a vulnerability? Email **security@nhi-shield.io** (not a public issue).  
We follow responsible disclosure with a 90-day remediation window.

---

## 📜 License

MIT — see [LICENSE](LICENSE)

---

## 📋 Installation

### Docker (Recommended)

```bash
git clone https://github.com/your-org/nhi-shield.git
cd nhi-shield
cp .env.example .env
# Edit .env — set JWT_SECRET, ENCRYPTION_KEY, DB_PASSWORD, NEO4J_PASSWORD
nano .env
docker compose -f docker/docker-compose.yml up -d
```

### Manual Setup

```bash
# Backend (Python)
cd backend
pip install -r requirements.txt

# API (Node.js)
cd backend/api
npm install
npm start

# Frontend
cd frontend
npm install
npm run build
```

---

## 🛠️ Usage

### Access the Dashboard
- Frontend: http://localhost:3001
- API: http://localhost:3000
- API Docs: http://localhost:3000/api/docs/ui
- Grafana: http://localhost:3003 (admin/admin)

### First Login
1. Open http://localhost:3001
2. Register your organization (onboarding wizard)
3. Add integrations (AWS, GitHub, Slack, etc.)
4. Run discovery scan
5. Review identity dashboard

### API Quick Start

```bash
# Login and get JWT
TOKEN=$(curl -s -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@yourorg.com","password":"yourpassword"}' | jq -r .token)

# Or create an API key
curl -X POST http://localhost:3000/api/v1/api-keys \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"ci-pipeline","role":"analyst"}'

# Use API key
curl http://localhost:3000/api/v1/identities \
  -H "X-API-Key: nhi_your_key_here"
```

