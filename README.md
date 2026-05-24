# Toasty 🤖

The smart, context-aware AI code reviewer from OWASP BLT.

## Overview

Toasty is an AI-powered code review service designed to help developers improve code quality through automated analysis and intelligent suggestions. It consists of a Django application for the main service, a Cloudflare Worker for serverless globally distributed API endpoints, and a GitHub webhook bot for automated code reviews and project management.

## Project Structure

- **Django Application** (`/aibot`, `/toasty`) - Main Django-based application
- **Cloudflare Worker** (root directory) - Serverless Python backend using Cloudflare Workers
  - `worker.py` - Main worker handler
  - `wrangler.toml` - Cloudflare Workers configuration
  - `test_worker.py` - Worker tests
- **GitHub Webhook Bot** (`/bot`) - FastAPI-based bot for automated PR reviews and issue triage

## Components

### Django Application

The main Django application provides the core functionality for Toasty.

**Setup:**
```bash
# Install dependencies
poetry install

# Run migrations
python manage.py migrate

# Start the development server
python manage.py runserver
```

### Cloudflare Worker Backend

A serverless backend built with Cloudflare Workers and Python for globally distributed, low-latency API endpoints.

**Features:**
- Health monitoring endpoints
- Code review API
- Status monitoring
- CORS support with preflight handling
- Comprehensive error handling and validation

**Quick Start:**
```bash
# Install Node dependencies (including Wrangler CLI)
npm install

# Run locally
npm run dev

# Deploy
npm run deploy
```

### GitHub Webhook Bot

A FastAPI-based bot that handles GitHub webhook events and provides automated code reviews using Google Gemini AI.

**Features:**
- 🔍 **AI Code Reviews**: Security-focused PR analysis using Google Gemini
- 📋 **Issue Triage**: Automated categorization, label suggestions, and priority assessment
- 💬 **Interactive Assistance**: Responds to @mentions with contextual help
- 🛡️ **Security Analysis**: Identifies vulnerabilities and enforces best practices

**Quick Start:**
```bash
pip install -r requirements.txt
cp .env.example .env
# Fill in GITHUB_TOKEN, GEMINI_API_KEY, GITHUB_WEBHOOK_SECRET
python -m bot.main
```

## Architecture Overview (Cloudflare Native)

### Core Flow

1. GitHub sends webhook → Cloudflare Worker / Bot
2. Worker validates HMAC signature
3. Worker fetches PR data from GitHub API
4. Worker sends structured context to AI agent
5. Worker stores results in Cloudflare storage
6. Worker posts AI review back to GitHub
7. Dashboard reads data from Cloudflare storage

## Development

### Prerequisites

- Python >=3.13,<4.0.0
- Poetry (for Django app)
- Node.js and npm (for Cloudflare Worker)
- Docker and Docker Compose (for running PostgreSQL, Redis, Qdrant locally)

### Installation

1. Clone the repository
2. Install Django dependencies: `poetry install`
3. Install Worker dependencies: `npm install`
4. Copy and fill in environment variables: `cp .env.example .env`

## API Endpoints

The Cloudflare Worker provides these REST endpoints:

- `GET /` - Service information
- `GET /health` - Health check
- `POST /api/review` - Submit code for review
- `GET /api/status` - Service status

The webhook bot exposes:

- `GET /health` - Health check
- `POST /webhook` - GitHub webhook handler

## Feature Roadmap

### Core Webhook System
- [x] Configure GitHub webhook endpoint
- [x] Implement HMAC SHA256 signature validation
- [x] Implement event type router (pull_request, issue_comment)
- [x] Add error handling & retry logic
- [ ] Add structured logging
- [ ] Implement rate limiting
- [ ] Add webhook replay protection

### GitHub API Integration
- [x] Fetch PR metadata, changed files, and diffs
- [x] Post PR comments
- [ ] Fetch CI/test results and review history
- [ ] Reply to specific comment threads
- [ ] Tag maintainers for critical alerts

### AI Agent Capabilities
- [x] Automated code review with Gemini AI
- [x] Issue triage and categorization
- [x] Security-focused analysis
- [ ] Smart prioritization scoring
- [ ] Multi-turn conversation support
- [ ] OWASP Top 10 detection
- [ ] CWE category mapping

### Data Storage
- [ ] D1 schema for PRs, priority scores, security findings
- [ ] Durable Objects for PR conversation state
- [ ] KV for caching and rate limiting

### Dashboard
- [ ] PR overview with priority scores
- [ ] Security findings visualization
- [ ] Trend analysis and filtering

### DevOps & Deployment
- [x] Docker and Docker Compose setup
- [x] GitHub Actions CI pipeline
- [ ] Cloudflare Workers deployment via Wrangler
- [ ] Staging/production environments

## Security

- Webhook signatures verified via HMAC-SHA256
- All secrets managed through environment variables
- JSON schema validation for all webhook payloads
- See [SECURITY.md](SECURITY.md) for responsible disclosure

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup instructions and contribution guidelines.

## License

This project is licensed under the GNU Affero General Public License v3. See [LICENSE](LICENSE) for details.
