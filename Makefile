.PHONY: help build up down restart logs test clean install dev migrate seed health certs

help:
	@echo ""; echo "  NHI Shield Commands"; echo "  ==================="; echo ""
	@echo "  make up        Start all services"
	@echo "  make down      Stop all services"
	@echo "  make migrate   Run database migrations"
	@echo "  make seed      Load test data"
	@echo "  make health    Check API health"
	@echo "  make certs     Generate mTLS certificates"
	@echo "  make test      Run all tests"
	@echo "  make dev       Start databases for local dev"
	@echo "  make clean     Remove all data (DESTRUCTIVE)"
	@echo ""

build:
	cd docker && docker-compose build --parallel

up:
	cd docker && docker-compose up -d
	@echo ""; echo "  NHI Shield starting up..."; echo ""
	@echo "  Dashboard:  http://localhost"; echo "  API: http://localhost:3000"
	@echo "  Grafana:    http://localhost:3001"; echo ""

down:
	cd docker && docker-compose down

restart:
	cd docker && docker-compose restart

logs:
	cd docker && docker-compose logs -f --tail=100

health:
	@curl -sf http://localhost:3000/health | python3 -m json.tool 2>/dev/null || echo "API not responding"

certs:
	bash scripts/mtls/generate-certs.sh

clean:
	@echo "WARNING: deletes ALL data. Ctrl+C to cancel..."; sleep 5
	cd docker && docker-compose down -v; docker system prune -f

migrate:
	@for f in 001_initial 002_enterprise_upgrade 003_complete_enterprise; do \
	  echo "Running $$f..."; \
	  cd docker && docker-compose exec postgres psql -U nhiadmin -d nhishield \
	    -f /docker-entrypoint-initdb.d/$$f.sql 2>/dev/null || true; \
	done; echo "Migrations complete"

seed:
	cd docker && docker-compose exec postgres psql -U nhiadmin -d nhishield < ../database/seeds/test_data.sql

install:
	cd backend/api && npm install
	cd frontend && npm install
	pip install --break-system-packages asyncpg redis[hiredis] scikit-learn numpy \
	    qdrant-client httpx boto3 tenacity asyncpg reportlab cryptography

dev:
	cd docker && docker-compose up -d postgres neo4j redis influxdb qdrant
	@echo "Databases ready. Run 'make dev-api' and 'make dev-fe' in separate terminals."

dev-api:
	cd backend/api && JWT_SECRET=dev_secret ENCRYPTION_KEY=dev_encryption_key_32chars \
	DATABASE_URL=postgresql://nhiadmin:nhi_secure_password_2026@localhost:5432/nhishield npm run dev

dev-fe:
	cd frontend && REACT_APP_API_URL=http://localhost:3000/api npm start

test:
	cd backend/api && npm test -- --coverage --forceExit
	cd backend && pytest tests/test_security.py -v --tb=short
