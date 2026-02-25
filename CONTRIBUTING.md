# Contributing to NHI Shield

Thank you for your interest in contributing to NHI Shield! This document provides guidelines and instructions for contributing.

## Table of Contents
1. [Code of Conduct](#code-of-conduct)
2. [Getting Started](#getting-started)
3. [Development Setup](#development-setup)
4. [Making Changes](#making-changes)
5. [Testing](#testing)
6. [Submitting Changes](#submitting-changes)
7. [Code Style](#code-style)
8. [Security](#security)

---

## Code of Conduct

### Our Pledge
We are committed to providing a welcoming and inspiring community for all.

### Our Standards
- **Be respectful** - Value diverse opinions and experiences
- **Be collaborative** - Work together towards common goals
- **Be professional** - Focus on what is best for the community
- **Be responsible** - Take ownership of your contributions

### Unacceptable Behavior
- Harassment, discrimination, or trolling
- Personal attacks or inflammatory comments
- Publishing others' private information
- Other conduct inappropriate in a professional setting

---

## Getting Started

### Prerequisites
- Docker & Docker Compose
- Git
- Node.js 20+ (for local development)
- Python 3.11+ (for local development)
- 8GB RAM minimum
- 20GB disk space

### Fork and Clone
```bash
# Fork the repository on GitHub first, then:
git clone https://github.com/YOUR_USERNAME/nhi-shield.git
cd nhi-shield

# Add upstream remote
git remote add upstream https://github.com/original-org/nhi-shield.git
```

---

## Development Setup

### 1. Environment Configuration
```bash
# Copy example environment file
cp .env.example .env

# Generate secure values
# Encryption key (must be 32+ characters)
openssl rand -base64 32

# JWT secret
openssl rand -base64 48

# Edit .env and update with secure values
nano .env
```

### 2. Start Development Environment
```bash
# Start all services
docker-compose up -d

# Check service health
docker-compose ps
docker-compose logs -f

# Access services:
# - Frontend: http://localhost
# - API: http://localhost:3000
# - Neo4j Browser: http://localhost:7474
# - InfluxDB: http://localhost:8086
```

### 3. Development Workflow

#### Backend API Development
```bash
cd backend/api

# Install dependencies
npm install

# Run in development mode (with hot reload)
npm run dev

# Run tests
npm test

# Run tests in watch mode
npm test -- --watch
```

#### Frontend Development
```bash
cd frontend

# Install dependencies
npm install

# Start development server
npm start

# Run tests
npm test

# Build for production
npm run build
```

#### Python Services Development
```bash
cd backend/discovery  # or anomaly, risk, security

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run service
python main.py

# Run tests
pytest
```

---

## Making Changes

### Branch Naming Convention
- `feature/description` - New features
- `fix/description` - Bug fixes
- `docs/description` - Documentation changes
- `refactor/description` - Code refactoring
- `test/description` - Test additions or fixes

Example:
```bash
git checkout -b feature/add-slack-integration
```

### Commit Messages
Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>(<scope>): <subject>

<body>

<footer>
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

Examples:
```bash
feat(api): add Slack integration endpoint
fix(discovery): correct GitHub API pagination
docs(readme): update installation instructions
test(api): add integration creation tests
```

---

## Testing

### Run All Tests
```bash
# Backend API tests
cd backend/api && npm test

# Frontend tests
cd frontend && npm test

# Python service tests
cd backend/discovery && pytest
```

### Write Tests
Every new feature should include tests:

#### API Endpoint Tests
```javascript
describe('POST /api/integrations', () => {
    test('should create integration with valid data', async () => {
        const response = await request(app)
            .post('/api/integrations')
            .set('Authorization', `Bearer ${authToken}`)
            .send({
                platform: 'github',
                name: 'Test Integration',
                config: { token: 'test_token' }
            })
            .expect(201);
        
        expect(response.body.integration).toBeDefined();
    });
});
```

#### Python Tests
```python
import pytest

async def test_discover_github():
    engine = DiscoveryEngine()
    await engine.initialize()
    
    config = {'token': 'test_token', 'org': 'test_org'}
    identities = await engine.discover_github(config)
    
    assert len(identities) > 0
    assert all(i.platform == 'github' for i in identities)
```

### Test Coverage
Aim for:
- **Statements**: >80%
- **Branches**: >75%
- **Functions**: >80%
- **Lines**: >80%

```bash
# Generate coverage report
npm test -- --coverage
pytest --cov=. --cov-report=html
```

---

## Submitting Changes

### Pre-submission Checklist
- [ ] Code follows project style guidelines
- [ ] All tests pass locally
- [ ] New tests cover changes
- [ ] Documentation updated
- [ ] Commit messages follow convention
- [ ] No sensitive data in commits

### Pull Request Process

1. **Update Your Branch**
```bash
git fetch upstream
git rebase upstream/main
```

2. **Push Changes**
```bash
git push origin feature/your-feature
```

3. **Create Pull Request**
- Go to GitHub and create a pull request
- Fill in the PR template
- Link related issues
- Request reviews

4. **PR Template**
```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] All tests pass
- [ ] New tests added

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-reviewed code
- [ ] Commented complex code
- [ ] Updated documentation
- [ ] No new warnings
```

5. **Code Review**
- Address reviewer feedback
- Make requested changes
- Push updates (they'll appear in PR)

6. **Merge**
- Once approved, maintainers will merge
- Delete your branch after merge

---

## Code Style

### JavaScript/Node.js
```javascript
// Use modern ES6+ syntax
const { encrypt } = require('./utils/crypto');

// Async/await over promises
async function createIntegration(data) {
    try {
        const result = await db.query(sql, params);
        return result.rows[0];
    } catch (error) {
        logger.error('Failed to create integration', error);
        throw new Error('Database error');
    }
}

// Descriptive variable names
const userToken = generateToken();
const encryptedCredentials = encrypt(credentials);

// Comments for complex logic
// Calculate risk score based on multiple factors
// See: https://docs.nhi-shield.io/risk-scoring
const riskScore = calculateRisk(identity);
```

### Python
```python
# Follow PEP 8
from typing import List, Dict, Optional
import logging

# Type hints
async def discover_github(config: Dict) -> List[NHIdentity]:
    """
    Discover GitHub identities.
    
    Args:
        config: Configuration containing token and org
        
    Returns:
        List of discovered identities
    """
    identities: List[NHIdentity] = []
    # Implementation
    return identities

# Use f-strings
logger.info(f"Discovered {len(identities)} identities")

# Descriptive names
api_token = config.get('token')
organization_name = config.get('org')
```

### SQL
```sql
-- Use uppercase for SQL keywords
-- Indent for readability
SELECT 
    id,
    name,
    platform,
    created_at
FROM identities
WHERE 
    org_id = $1 
    AND is_active = true
ORDER BY created_at DESC
LIMIT 100;
```

---

## Security

### Reporting Security Issues
**DO NOT** create public issues for security vulnerabilities.

Instead:
1. Email: security@nhi-shield.io
2. Include:
   - Description of vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We aim to respond within 48 hours.

### Security Best Practices

#### Never Commit Secrets
```bash
# Check before committing
git diff

# Use .gitignore
.env
*.key
*.pem
secrets/
```

#### Use Environment Variables
```javascript
// ❌ Bad
const apiKey = 'sk-abc123';

// ✅ Good
const apiKey = process.env.API_KEY;
```

#### Sanitize Inputs
```javascript
// Always validate and sanitize user input
const email = validator.isEmail(req.body.email) 
    ? req.body.email 
    : null;
```

#### Use Prepared Statements
```javascript
// ❌ Bad (SQL injection risk)
const query = `SELECT * FROM users WHERE email = '${email}'`;

// ✅ Good (parameterized query)
const query = 'SELECT * FROM users WHERE email = $1';
await db.query(query, [email]);
```

---

## Issue Guidelines

### Bug Reports
Include:
- Clear title
- Steps to reproduce
- Expected behavior
- Actual behavior
- Environment (OS, browser, versions)
- Logs/screenshots
- Possible fix (if known)

### Feature Requests
Include:
- Clear title
- Use case description
- Proposed solution
- Alternatives considered
- Additional context

---

## Getting Help

- **Documentation**: https://docs.nhi-shield.io
- **GitHub Issues**: https://github.com/your-org/nhi-shield/issues
- **Discussions**: https://github.com/your-org/nhi-shield/discussions
- **Email**: support@nhi-shield.io

---

## Recognition

Contributors are recognized in:
- CONTRIBUTORS.md file
- Release notes
- Project website (if applicable)

---

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to NHI Shield! 🚀
