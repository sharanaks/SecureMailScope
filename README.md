# SecureMailScope

SecureMailScope is a web-based platform that assesses the **public, passive**
email security posture of a domain you own or are authorized to assess. It
checks SPF, DKIM, DMARC, MX, and TLS/certificate configuration, scores the
result with a deterministic rule engine, explains the findings in plain
language (via an LLM or a built-in offline fallback), generates a report,
computes a SHA-256 integrity hash of that report, and can anchor that hash on
a local blockchain so the report's integrity can be independently verified
later.

This was built as a 12-hour hackathon MVP. It prioritizes a working,
honest end-to-end demo over polish or completeness.

> **Authorized use only.** Only scan domains you own or have explicit
> permission to assess. The scanner performs only safe, passive DNS
> lookups and standard TLS/STARTTLS handshakes — it never reads private
> email, never collects passwords, and never attempts exploitation.

---

## Table of contents

- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installation & running (Windows-friendly)](#installation--running-windows-friendly)
  - [1. Backend setup](#1-backend-setup)
  - [2. Blockchain setup](#2-blockchain-setup)
  - [3. Frontend setup](#3-frontend-setup)
  - [4. Full demo walkthrough](#4-full-demo-walkthrough)
- [Environment variables](#environment-variables)
- [Scoring formula](#scoring-formula)
- [AI explanation layer](#ai-explanation-layer)
- [Blockchain anchoring](#blockchain-anchoring)
- [API reference](#api-reference)
- [How to test](#how-to-test)
- [Troubleshooting](#troubleshooting)
- [Security limitations](#security-limitations)

---

## Architecture

```
Browser (React/Vite)
      │  HTTP/JSON
      ▼
FastAPI backend  ──────►  SQLite (assessments, users)
      │
      ├──► DNS resolver (SPF/DMARC/DKIM/MX lookups)
      ├──► TLS/STARTTLS socket to mail servers (certificate inspection)
      ├──► Rule-based scoring engine (deterministic)
      ├──► AI explainer (Anthropic API, or offline template fallback)
      ├──► SHA-256 report hashing/verification
      └──► web3.py  ──────►  Local Hardhat blockchain
                                   └── AuditRegistry.sol
```

Folder layout:

```
SecureMailScope/
├── frontend/     React + Vite SPA
├── backend/      FastAPI app, SQLite DB, scanner, AI, blockchain client
├── blockchain/   Hardhat project: AuditRegistry.sol, tests, deploy script
└── README.md
```

---

## Requirements

- **Python** 3.11+ (3.12 recommended)
- **Node.js** 18+ and npm (for both `frontend/` and `blockchain/`)
- Windows, macOS, or Linux — instructions below are Windows-friendly
  (PowerShell/CMD), with equivalent notes for macOS/Linux

You will need **three terminals** running at once during a demo:
1. Local blockchain node (Hardhat)
2. Backend (FastAPI/Uvicorn)
3. Frontend (Vite dev server)

---

## Installation & running (Windows-friendly)

### 1. Backend setup

```powershell
cd backend
python -m venv venv
venv\Scripts\activate          # macOS/Linux: source venv/bin/activate
pip install -r requirements.txt
copy .env.example .env         # macOS/Linux: cp .env.example .env
```

Open `.env` and at minimum set a random `JWT_SECRET`:

```powershell
python -c "import secrets; print(secrets.token_hex(32))"
```

Paste the output into `JWT_SECRET=` in `.env`.

You can leave `ANTHROPIC_API_KEY` blank — the app will automatically use the
deterministic template-based explanation fallback (see
[AI explanation layer](#ai-explanation-layer)).

Start the backend:

```powershell
uvicorn app.main:app --reload --port 8000
```

The API is now live at `http://localhost:8000` (interactive docs at
`http://localhost:8000/docs`). SQLite will auto-create
`backend/securemailscope.db` on first run.

### 2. Blockchain setup

In a **new terminal**:

```powershell
cd blockchain
npm install
npx hardhat compile
npx hardhat node
```

Leave this terminal running — it's your local Ethereum-compatible chain
(`http://127.0.0.1:8545`), preloaded with funded test accounts.

In **another new terminal**, deploy the contract:

```powershell
cd blockchain
npx hardhat run scripts/deploy.js --network localhost
```

This prints a deployed contract address, e.g.:

```
AuditRegistry deployed to: 0x5FbDB2315678afecb367f032d93F642f64180aa
```

Copy that address into `backend/.env`:

```
CONTRACT_ADDRESS=0x5FbDB2315678afecb367f032d93F642f64180aa
```

The `DEPLOYER_PRIVATE_KEY` in `.env.example` is already set to Hardhat's
well-known default test account #0 private key, which is automatically
funded on the local Hardhat node — no changes needed for local demo use.
**Never use this key on a real network.**

Restart the backend (Ctrl+C, then re-run `uvicorn ...`) so it picks up the
new `CONTRACT_ADDRESS`.

> If you skip this step, the app still works end-to-end — scanning,
> scoring, AI explanation, reporting, and SHA-256 hashing all function
> normally. Only the "Anchor on Blockchain" button will report a clear
> "not configured" error instead of faking success.

### 3. Frontend setup

In a **new terminal**:

```powershell
cd frontend
npm install
npm run dev
```

Open the printed URL (default `http://localhost:5173`).

### 4. Full demo walkthrough

1. Open `http://localhost:5173` → Landing page → **Get started** → register
   an account (email + password, 8+ characters).
2. You land on the **Dashboard**. Click **+ New Scan**.
3. Enter a domain you own or are authorized to test (e.g. your own company
   domain). Optionally provide a DKIM selector if you know it.
4. Click **Start Security Scan** — this runs real DNS/TLS checks live.
5. View **Scan Results**: score gauge, per-check PASS/WARNING/FAIL, severity
   badges.
6. Click **AI Recommendations** to see plain-language explanations (LLM or
   template fallback, clearly labeled).
7. Click **View Full Report** for the complete report and its SHA-256 hash.
8. Click **Blockchain Verification** → **Anchor Report Hash on Blockchain**
   (requires steps in [Blockchain setup](#2-blockchain-setup) to be done).
9. Click **Run Verification** to recompute the hash and confirm
   `INTEGRITY VERIFIED`.
10. Visit **Scan History** to see all past assessments and reopen any of
    them.

---

## Environment variables

All backend configuration lives in `backend/.env` (copy from
`backend/.env.example`):

| Variable | Purpose | Required? |
|---|---|---|
| `JWT_SECRET` | Signs auth tokens | Yes — set to a random value |
| `JWT_EXPIRE_MINUTES` | Token lifetime | No (default 480) |
| `DATABASE_PATH` | SQLite file path | No (default `./securemailscope.db`) |
| `ANTHROPIC_API_KEY` | Enables LLM-based explanations | No — falls back to templates if blank |
| `ANTHROPIC_MODEL` | Model name for the API | No |
| `WEB3_PROVIDER_URI` | Local Hardhat RPC URL | No (default `http://127.0.0.1:8545`) |
| `CONTRACT_ADDRESS` | Deployed `AuditRegistry` address | No — anchoring disabled until set |
| `DEPLOYER_PRIVATE_KEY` | Account used to send anchor transactions | No — defaults to a Hardhat test key |
| `DKIM_COMMON_SELECTORS` | Selectors tried when none is supplied | No |
| `FRONTEND_ORIGIN` | CORS allow-list origin | No (default `http://localhost:5173`) |

The frontend reads one optional variable, `VITE_API_BASE` (defaults to
`http://localhost:8000`), if you need to point it at a different backend
host — create `frontend/.env` with `VITE_API_BASE=http://your-host:8000`.

---

## Scoring formula

**The AI never decides severity or score.** All scoring is handled by
`backend/app/scanner/scoring.py`, a pure, deterministic rule engine. The
same scan inputs always produce the same score.

Start at **100 points**. For each of the 6 checks, apply a deduction based
on its status:

| Check | WARNING deduction | FAIL deduction |
|---|---|---|
| SPF | 5 | 15 |
| DKIM | 5 | 10 (inconclusive DKIM is always WARNING, never FAIL) |
| DMARC | 8 | 20 |
| MX | — (no WARNING state) | 25 |
| TLS | 8 | 20 |
| Certificate | 6 | 15 |

`Final score = max(0, min(100, 100 - total_deductions))`

Per-finding severity labels (Critical/High/Medium/Low) shown on the
dashboard are assigned from a fixed lookup table (`SEVERITY_MAP` in
`scoring.py`) based on which check failed/warned — also fully
deterministic.

---

## AI explanation layer

`backend/app/ai/explainer.py` implements:

- **With `ANTHROPIC_API_KEY` set**: calls the Anthropic Messages API with a
  system prompt that explicitly forbids the model from inventing findings,
  changing severity, or making absolute security claims ("100% secure").
  The model only produces `simple_explanation`, `why_it_matters`, and
  `recommendation` text per finding, plus an `overall_summary`.
- **Without an API key** (or if the API call fails for any reason): a
  deterministic, template-based explanation generator produces equivalent
  output offline, so the full demo works with zero external dependencies.

Every report and API response includes an `ai_explanation.source` field
(`"llm"` or `"fallback_template"`) so it's always transparent which path
generated the text — the UI displays this clearly on the Recommendations
and Report pages.

---

## Blockchain anchoring

`blockchain/contracts/AuditRegistry.sol` stores, per assessment:

- Assessment ID (UUID string)
- SHA-256 report hash (hex string)
- Registration timestamp
- The address that registered it

**The full report content is never written on-chain** — only the hash,
ID, and timestamp. Functions: `registerAssessment()`, `getAssessment()`,
`verifyHash()`; an `AssessmentRegistered` event fires on registration.

The backend's `app/blockchain/client.py` wraps this with `web3.py`. If the
Hardhat node isn't running or `CONTRACT_ADDRESS` isn't set, anchoring
requests fail with a clear, honest error — the app never fakes a
successful anchor.

---

## API reference

| Method | Path | Description |
|---|---|---|
| GET | `/api/health` | Health check |
| POST | `/api/auth/register` | Create an account |
| POST | `/api/auth/login` | Log in, get a JWT |
| POST | `/api/scan` | Run a full passive scan of a domain |
| GET | `/api/assessments` | List past assessments |
| GET | `/api/assessments/{id}` | Full assessment detail |
| GET | `/api/reports/{id}` | Get the stored report + hash |
| POST | `/api/reports/{id}/verify` | Recompute & compare SHA-256 hash |
| POST | `/api/blockchain/anchor/{id}` | Anchor the report hash on-chain |
| GET | `/api/blockchain/status/{id}` | Blockchain anchoring status |

Interactive Swagger docs: `http://localhost:8000/docs`.

---

## How to test

**Backend (manual):**
```powershell
cd backend
venv\Scripts\activate
uvicorn app.main:app --reload --port 8000
```
Then visit `http://localhost:8000/docs` and try `POST /api/scan` with a
real domain you're authorized to test.

**Blockchain contract tests:**
```powershell
cd blockchain
npx hardhat test
```
Runs the Mocha/Chai test suite in `blockchain/test/AuditRegistry.test.js`
covering registration, retrieval, hash verification (match/mismatch), and
duplicate-registration rejection — against Hardhat's in-memory network.

---

## Troubleshooting

- **`CORS error` in the browser console**: confirm the backend's
  `FRONTEND_ORIGIN` in `.env` matches the URL Vite is actually running on
  (check the terminal output from `npm run dev`).
- **DKIM shows "WARNING" / inconclusive**: this is expected and documented
  behavior — DKIM selectors aren't discoverable via a single generic DNS
  query. Supply the correct selector in the New Scan form if you know it.
- **TLS/Certificate checks show FAIL with a connection error**: some
  networks block outbound SMTP ports (25/587), which the TLS check uses to
  reach mail servers. This is a network/firewall limitation, not a bug —
  try from an unrestricted network.
- **"Blockchain not configured or unreachable"**: make sure `npx hardhat
  node` is still running in its terminal, and that `CONTRACT_ADDRESS` in
  `backend/.env` is set to the address printed by the deploy script, then
  restart the backend.
- **`ModuleNotFoundError` on backend start**: make sure the virtual
  environment is activated before `pip install -r requirements.txt`.
- **Windows PowerShell execution policy blocks `venv\Scripts\activate`**:
  run PowerShell as Administrator once and execute
  `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`, then retry.

---

## Security limitations

This is a hackathon MVP and has known, intentional limitations:

- Authentication is minimal (no email verification, password reset, rate
  limiting, or MFA) — adequate for a demo, not for production.
- DKIM discovery is best-effort: without the true selector, results are
  explicitly marked inconclusive rather than guessed.
- TLS checks connect once to a mail server's SMTP port; they check
  protocol version and certificate metadata but do not perform a
  comprehensive TLS configuration audit (cipher suite enumeration,
  downgrade-attack testing, etc.).
- The AI explanation layer can occasionally phrase things imperfectly;
  it never determines severity or score, but always verify recommendations
  against current best practices before acting on them at scale.
- The local Hardhat blockchain is for demonstration only — it resets
  every time the node restarts and has no relationship to any public
  Ethereum network.
- This tool assesses what is **passively observable from the public
  internet only**. A clean scan is not a guarantee of overall security;
  it does not test infrastructure, credentials, or internal systems.
