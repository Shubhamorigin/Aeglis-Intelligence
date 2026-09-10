# Aeglis Backend

Aeglis Backend is a Python FastAPI-based cybersecurity and risk-analysis service for detecting suspicious URLs, text-based scam content, malicious files, malware patterns, and risky Android APKs. It combines local detection logic, third-party threat intelligence, and AI-based analysis to produce risk scores and explanations for user-facing security workflows.

The project supports both consumer and developer use cases:

- Consumer scanning for text, URLs, and uploaded files
- Developer API with API-key protection and quotas
- Billing and subscription flows
- Support ticket handling
- Webhook-based result delivery
- Supabase-backed auth, profiles, logs, and scan history

## Table of Contents

- Overview
- System architecture
- Project structure
- Requirements
- Environment setup
- Installation
- Running the application
- Configuration
- API overview
- Developer workflow
- Database and storage requirements
- Security notes
- Troubleshooting
- License

## Overview

The backend is built around a central FastAPI application in `main.py`. It coordinates multiple analysis modules:

- `core_engine.py` handles domain intelligence, whitelist checks, Redis cache access, and high-level risk assessment.
- `scanner_engine.py` performs deep file analysis for Office documents, ZIP archives, scripts, JavaScript, SVG, PDFs, APKs, and images.
- `scan_url.py` runs browser-based URL detonation and phishing checks.
- `input_classifier.py` identifies and classifies suspicious user input, including UPI/VPA-style scam patterns.
- `security_engine.py` manages API key creation and hashing.
- `webhook_engine.py` sends real-time scan results to client webhooks.
- `utils/supabase_db.py` initializes the Supabase client for auth and admin access.

The application is designed for production-style workflows, but it can also be run locally for development and testing.

## System Architecture

The application combines the following layers:

1. API layer
   - FastAPI endpoints for authentication, scanning, developer APIs, billing, and dashboard actions.
   - SlowAPI-based rate limiting for public and authenticated routes.
   - CORS protections and origin validation.

2. Detection layer
   - Text and URL classification logic
   - Domain reputation and RDAP checks
   - Static and dynamic file inspection
   - AI-driven risk scoring supported by Groq
   - Local threat heuristics for common malware and phishing patterns

3. Data and storage layer
   - Supabase for auth, profiles, API logs, scan history, support tickets, and billing events
   - Redis cache for fast lookups and reduced API usage
   - Local temporary files in `temp_uploads/` for one-off file scans

4. Integration layer
   - VirusTotal and AlienVault lookups for hash reputation
   - WebRisk checks for malicious URLs
   - Webhook dispatch for developer integrations

## Project Structure

```text
Aeglis-Backend/
├── .env
├── LICENSE
├── README.md
├── requirements.txt
├── main.py
├── core_engine.py
├── input_classifier.py
├── scan_url.py
├── scanner_engine.py
├── security_engine.py
├── webhook_engine.py
├── white_listed.csv
├── temp_uploads/              # created at runtime for uploads
├── utils/
│   └── supabase_db.py
└── __pycache__/              # optional generated files
```

## Requirements

The project uses Python and several external libraries. The main dependencies are listed in `requirements.txt`.

Required runtime tools:

- Python 3.10+
- pip
- Redis (recommended for cache and speed)
- Supabase project
- Groq API key
- VirusTotal API key
- WebRisk API key
- AlienVault API key

Optional but important:

- Playwright browsers for URL detonation and browser automation
- System packages for `python-magic` depending on your operating system

## Environment Setup

Create a root `.env` file based on the required variables used by the app.

Example:

```env
ALIENVAULT_API_KEY=your_alienvault_api_key
GROQ_API_KEY=your_groq_api_key
SB_ANON_KEY=your_supabase_anon_key
SB_API_URL=your_supabase_api_url
SB_SECRET_KEY=your_supabase_secret_key
VIRUSTOTAL_API_KEY=your_virustotal_api_key
WEB_RISK_API_KEY=your_web_risk_api_key
REDIS_URL=your_redis_url
```

Notes:

- `SB_API_URL`, `SB_ANON_KEY`, and `SB_SECRET_KEY` are required for Supabase initialization.
- `GROQ_API_KEY` is used for AI classification and verdict generation.
- `REDIS_URL` is optional if Redis is unavailable; the app will log a warning and continue with fallback logic.
- Keep `.env` outside of source control in production.

## Installation

1. Open a terminal in the project root.
2. Create and activate a Python virtual environment if you want local isolation.
3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Install Playwright browser dependencies if using URL scanning or browser automation:

```bash
python -m playwright install
```

5. Confirm that your `.env` file is populated before starting the app.

## Running the application

Run the server with either of the following commands:

```bash
python main.py
```

or:

```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

The server starts the FastAPI app and initializes the background scheduler, Supabase clients, and engine services.

## Configuration

### Supabase

The app relies on a Supabase project for:

- authentication and JWT verification
- user profile data
- API keys and plan usage
- scan history and logs
- developer webhook configuration
- support tickets
- billing ledger entries

The client is initialized in `utils/supabase_db.py`.

### Redis

The project uses Redis in `core_engine.py` for cached domain results and scan information when available. If Redis is not reachable, the app logs the error and continues with local or Supabase-based fallback logic.

### Security and rate limit behavior

The main app uses:

- SlowAPI rate limits
- JWT validation for authenticated consumer actions
- API key validation for developer endpoints
- origin checks for official frontend access
- temporary file size limits

## API Overview

The project exposes a combination of public, authenticated, and developer endpoints.

### Public health and support endpoints

- `GET /` - health check
- `POST /support/ticket` - public support ticket submission

### Consumer auth endpoints

- `POST /auth/signup`
- `POST /auth/login`
- `POST /auth/google`
- `GET /auth/callback`
- `POST /auth/native-google`

### Consumer protected endpoints

- `POST /scan` - analyze text input
- `POST /scan/intercept` - scan a downloaded URL or file through a browser fetch flow
- `POST /deep-scan` - upload and analyze a file
- `POST /get/history` - fetch user scan history
- `POST /delete/history` - delete one history record
- `POST /delete/all-history` - delete all history records
- `GET /profile/me` - fetch profile data

### Billing endpoints

- `POST /api/v1/billing/generate-intent`
- `POST /api/v1/billing/submit-utr`

### Developer / B2B endpoints

- `POST /v3/api/scan`
- `POST /v3/api/deep-scan`
- `POST /v3/dashboard/generate-key`
- `POST /v3/dashboard/webhook`
- `GET /v3/dashboard/api-logs`
- `GET /v3/dashboard/api-data`
- `GET /v3/dashboard/reports`

These endpoints are protected by developer API keys and usage quotas.

## Developer Workflow

### 1. Register a developer account

Use the signup flow and then fetch profile information with the authenticated JWT.

### 2. Generate a developer API key

Call the dashboard key generation endpoint after authentication. The backend will create a fresh API key, store a hash, and return the live key once.

### 3. Use the API key in requests

Send the key in the `Authorization` header using the format:

```http
Authorization: Bearer sk_live_xxx
```

### 4. Scan text or files

Example request for text scan:

```http
POST /v3/api/scan
Content-Type: application/json
Authorization: Bearer sk_live_xxx
```

```json
{
  "input_text": "Check this suspicious link: https://example.com",
  "end_user_id": "customer-123"
}
```

### 5. Add webhook delivery

Configure a webhook through the dashboard route. The backend stores the URL and a secret and then dispatches events after scan completion.

## Database and Storage Requirements

The application expects these Supabase tables or equivalent schema support:

- `profiles`
- `api_keys`
- `api_logs`
- `scans`
- `support_tickets`
- `billing_ledger`

Additionally, the project references a storage bucket named `cold-storage` for exported reports and archival files.

For file-based operations, the app creates and uses the `temp_uploads/` directory at runtime.

## Security Notes

This project is designed for security analysis, but production deployments still require careful configuration:

- Store secrets in `.env` or a secure secret manager.
- Restrict CORS origins in production.
- Do not expose production API keys or secrets in frontend code.
- Use HTTPS for all public endpoints.
- Keep Redis, Supabase, and third-party services protected behind private networking where possible.
- Review the rate limits and access controls before production deployment.
- Validate uploaded file sizes and sanitise file storage before exposing services externally.

## Troubleshooting

### Missing dependency errors

If the app cannot import a package, install the project requirements again:

```bash
pip install -r requirements.txt
```

### Playwright browser errors

If browser-based URL scanning fails:

```bash
python -m playwright install
```

### Redis unavailable

Redis is not strictly required. The app logs a warning and often continues using fallback paths. For better performance, configure Redis properly.

### Supabase initialization failures

Check that:

- your `.env` file contains valid credentials
- the Supabase URL is correct
- the service key and anon key are both valid
- the project is active and accessible

### File upload issues

The app has a 50 MB limit for uploaded files. If a file exceeds that limit, requests will return a 413 error.

## License

This project is licensed under the MIT License.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

## Summary

Aeglis Backend is a full-stack security analysis application for detecting risky content across text, URLs, files, and endpoints. It is designed for both consumer apps and developer integrations and includes API protection, billing, webhook delivery, and secure storage workflows.

For local development, the main tasks are:

1. Install dependencies
2. Populate `.env`
3. Run the FastAPI app
4. Verify the health check on `/`
5. Start using the scan endpoints and secure the project keys before deployment
