# AUTHENTIX / EduVerify-AI (`SIH26261`)

**Evidence-Linked Regulatory Scrutiny, Document Integrity & Source Verification Workbench for AICTE Approval Workflows**

> **Core Regulatory Safety Invariant:** AUTHENTIX is an **officer decision-support system**, not an autonomous regulator. No Advisory Trust Score, rule finding, heuristic anomaly signal, OCR failure, or external verification unavailability ever automatically rejects an institution or issues a final regulatory decision. Authorised human officers inspect linked evidence, correct extraction errors when warranted, record rationale, and retain exclusive final decision authority.

---

## 1. Architecture Overview

AUTHENTIX runs as a cohesive, auditable full-stack system with zero fabricated metrics or hidden mock fallbacks:

1. **Frontend (`src/`, React 19 + TypeScript + Tailwind CSS v4)**
   - Institutional scrutiny workbench served on port `3000` with persisted scoped **In-App Alerts (`IN_APP_ONLY`)** drawer in the header.
   - Screens: Role-aware Login, Live Scrutiny Queue & Operational Metrics Dashboard (lifecycle stage grid, officer intervention counters, category breakdown), Filterable Applications Register with Admin Category Variant creation, New Application Intake Modal with dynamic mandatory checklist preview, Split-Pane Evidence-Linked Application Detail Workbench (Document Upload & Retry OCR, OCR Field Extraction & Officer Correction, 5-Way Epistemic Rule & Heuristic Findings + Prior Cycle History, Regulatory & Infrastructure Compliance Checklist with deterministic visual metadata inspector, 8-Method Source Verification Adapter, Rectification & Resubmission Panel, Officer Review & Final Decision Panel, Structured Report Export), Configurable Rules Governance (`ADMIN` / `SENIOR_AUDITOR`) with pre-publication schema validation and effective-date windows, and Hash-Chained Audit Trail Verification (`verifyAuditChain`).
2. **Backend API (`server.ts`, `src/server/`, Node.js 22 + Express 4 + Zod)**
   - Runs on port `3000` (`http://localhost:3000/api/*`).
   - Session authentication using Node `crypto.scrypt` (`N=16384, r=8, p=1`, constant-time `timingSafeEqual`), `HttpOnly` + `SameSite=Lax` cookies, Bearer token support, and `X-CSRF-Token` validation on state-mutating cookie requests.
   - Strict Role-Based Access Control (`ADMIN`, `REVIEW_OFFICER`, `SENIOR_AUDITOR`, `INSTITUTION_USER`), state-transition guards, and row-level institution isolation (`INSTITUTION_USER` accounts can only view/create/upload/resubmit records and receive in-app alerts belonging to their own `institution_id`).
3. **Database (`src/server/db.ts`, `db/migrations/001_initial_schema.sql` – `003_complete_regulatory_lifecycle.sql`)**
   - Active runtime database adapter uses built-in Node.js 22 `node:sqlite` (`DatabaseSync`) persistent file database at `./data/authentix.sqlite` with `PRAGMA journal_mode = WAL` and `PRAGMA foreign_keys = ON`.
   - Versioned SQL migrations tracked in `schema_migrations`, persisting `application_categories`, `applications` (with lifecycle stages, submission cycles, and physical-inspection flags), `documents`, `extracted_fields`, `validation_rules` (with effective dates and illustrative flags), `validation_findings` (with 5-way epistemic classification and prior-cycle retention), `compliance_requirements`, `application_compliance_items`, `source_verifications` (8 verification methods), `officer_reviews` (14 action types), `in_app_notifications`, and hash-chained `audit_logs` across server restarts.
   - `db/postgres-schema.sql` (and the optional `postgres-db` Docker Compose profile) is provided strictly as **PostgreSQL 16 reference DDL** for future multi-node adapter work; `DB_ENGINE=sqlite` is the sole active runtime adapter.

4. **OCR, Classification & Deterministic Visual Inspection (`services/ocr_service/server.py`, Port `8001` & `src/server/ocrPipeline.ts`)**
   - Standalone Python 3.10+ HTTP service listening on `http://127.0.0.1:8001` (`GET /health`, `POST /analyze`).
   - Parses digital PDF text streams (`FlateDecode`), text coordinates, `/Info` metadata (`Producer`, `Creator`, `CreationDate`, `ModDate`), `/Type /Sig` + `/ByteRange` digital signature container markers, incremental `%%EOF` revisions, PNG/JPEG SOF pixel dimensions, and heuristic anomaly signals (grid block-hash clone checks, regional luminance entropy variance).
   - Performs keyword-weighted document classification (`classificationConfidence`) against declared document types, extracts normalized fields (`certificate_number`, `institution_name`, `issuing_authority`, `issue_date`, `expiry_date`, `approved_intake`, `land_area_acres`, `built_up_area_sqm`, `address`, `architect_registration_no`, `total_faculty_count`), and runs `LocalDeterministicVisualInspector` (`VisualInspectionAdapter`) on facility photographs/drawings.
   - Automatically invokes `tesseract` (`eng+hin` for English/Hindi) and `pdftotext` when installed on the host or inside Docker (`services/ocr_service/Dockerfile`). When `tesseract` is not installed on a bare host and a raster-only scan without text chunks is uploaded, it honestly reports `UNAVAILABLE` (`MANUAL_REVIEW_REQUIRED`) instead of inventing OCR text, and supports explicit officer/institution `POST /api/applications/:id/documents/:docId/reprocess` retries.
   - If the Python service on port `8001` is stopped or unreachable, `src/server/ocrPipeline.ts` falls back cleanly to a deterministic Node PDF/image parser for digital PDFs while surfacing microservice connectivity status on `/api/health`.
5. **Document Storage (`./data/uploads/` & `./data/sample_docs/`)**
   - Magic-byte file signature verification (`%PDF-`, PNG, JPEG), configurable file size limit (`MAX_UPLOAD_MB=15`), UUID storage filenames (preventing path traversal), and `Content-Disposition` protected downloads behind RBAC and demo-isolation checks.

---

## 2. Prerequisites

| Dependency | Supported Version | Notes |
| :--- | :--- | :--- |
| **Node.js** | **>= 22.5.0 LTS** (tested on `v22.x`) | Required for built-in `node:sqlite` persistent database engine |
| **npm** | **>= 10.x** | Dependency installation and scripts |
| **Python** | **>= 3.10** (optional on host, recommended) | Runs `services/ocr_service/server.py` on port `8001` (zero `pip` packages required) |
| **Tesseract OCR** | Optional (`tesseract-ocr`, `tesseract-ocr-hin`) | Installed automatically in Docker; needed on host only for raw raster scan OCR |
| **Docker & Compose** | Optional (Docker Engine 24+ / Desktop) | Full containerized deployment (`Dockerfile` + `services/ocr_service/Dockerfile`) |

---

## 3. Clean-Checkout Local Setup (Standard Mode vs. Development Demo Mode)

### Step 1: Install dependencies & create `.env`

```bash
cp .env.example .env
npm install
```

*(On Windows PowerShell: `Copy-Item .env.example .env`)*

By default, `.env.example` sets **`ENABLE_DEMO_MODE=false`** and **`AUTO_SEED_DEMO_DATA=false`** so synthetic demo accounts and sample institutions are disabled out of the box.

### Step 2A: Initialize for Development / SIH Evaluation Demo (`ENABLE_DEMO_MODE=true`)

Set `ENABLE_DEMO_MODE=true` and `AUTO_SEED_DEMO_DATA=true` in `.env`, then initialize migrations and synthetic sample records:

```bash
ENABLE_DEMO_MODE=true AUTO_SEED_DEMO_DATA=true npm run db:seed
```

To wipe and regenerate a clean synthetic demo state (including sample PDFs/PNGs in `./data/sample_docs/`) at any time:

```bash
ENABLE_DEMO_MODE=true npm run db:reset
```

### Step 2B: Initialize for Standard Non-Demo Mode (`ENABLE_DEMO_MODE=false`)

Keep `ENABLE_DEMO_MODE=false` in `.env`, apply schema migrations + baseline validation rules, and provision an initial non-demo `ADMIN` account:

```bash
npm run db:migrate
BOOTSTRAP_ADMIN_EMAIL="admin@institution.ac.in" \
BOOTSTRAP_ADMIN_PASSWORD="StrongAdminPassword#2026" \
BOOTSTRAP_ADMIN_NAME="Chief Scrutiny Administrator" \
npm run db:create-admin
```

### Step 3: Start Services

#### Option A — Single-command launch script

- **Linux / macOS:**
  ```bash
  bash scripts/start-dev.sh
  ```
- **Windows (PowerShell):**
  ```powershell
  powershell -ExecutionPolicy Bypass -File .\scripts\start-windows.ps1
  ```

#### Option B — Start services in separate terminals

1. **Terminal 1 — Python OCR & Forensics Service (Port `8001`):**
   ```bash
   npm run ocr:service
   ```
2. **Terminal 2 — Full-Stack Express + React Server (Port `3000`):**
   ```bash
   npm run dev
   ```
3. Open **`http://localhost:3000`**.

### Local Production Build & Start

Generate strong secrets (>= 32 characters) before starting in `NODE_ENV=production`:

```bash
npm run build
SESSION_SECRET="$(openssl rand -hex 32)" \
QR_SIGNING_SECRET="$(openssl rand -hex 32)" \
NODE_ENV=production ./node_modules/.bin/tsx server.ts
```

---

## 4. Environment Variable Reference

| Variable | Default | Required in Prod? | Description |
| :--- | :--- | :--- | :--- |
| `PORT` | `3000` | No | HTTP port for Express API and frontend SPA |
| `NODE_ENV` | `development` | Yes (`production`) | Enforces production secret validation and static `dist/` serving |
| `ENABLE_DEMO_MODE` | `false` | Keep `false` | Server-side gate for `*.demo` synthetic accounts, demo login drawer, sample fixtures, and synthetic records |
| `AUTO_SEED_DEMO_DATA` | `false` | Keep `false` | Auto-seeds synthetic data on startup **only** when `ENABLE_DEMO_MODE=true` |
| `SESSION_SECRET` | *(empty in dev)* | **Yes (>= 32 chars)** | Strong random secret; weak/placeholder values are rejected in `NODE_ENV=production` |
| `QR_SIGNING_SECRET` | *(ephemeral in dev)* | **Yes (>= 32 chars)** | HMAC-SHA256 secret for QR verification; missing secret in production fails safely to `SOURCE_UNAVAILABLE` |
| `SESSION_TTL_HOURS` | `12` | No | Authenticated session lifetime before re-authentication is required |
| `CORS_ORIGIN` | `http://localhost:3000` | Recommended | Explicit origin permitted for cross-origin credentialed requests |
| `DB_ENGINE` | `sqlite` | No | Active runtime adapter (`sqlite` only; `postgres` rejects placeholder passwords and reports adapter status) |
| `SQLITE_DB_PATH` | `./data/authentix.sqlite` | No | File path for persistent SQLite WAL database |
| `UPLOAD_DIR` | `./data/uploads` | No | Directory for stored original application documents |
| `SAMPLE_DOCS_DIR` | `./data/sample_docs` | No | Directory for generated synthetic test PDFs/PNGs in demo mode |
| `MAX_UPLOAD_MB` | `15` | No | Maximum upload file size in megabytes |
| `OCR_MODE` | `auto` | No | `auto` \| `local-only` (safe demo without external OCR daemon) \| `unavailable` \| `timeout` |
| `OCR_SERVICE_URL` | `http://127.0.0.1:8001` | No | URL of the Python OCR & Forensics microservice |
| `OCR_TIMEOUT_MS` | `8000` | No | Timeout in ms before falling back from Python OCR microservice |

---

## 5. Docker Compose Deployment & SQLite Backup / Restore

### Containerized Deployment (`Dockerfile` & `services/ocr_service/Dockerfile`)

`docker-compose.yml` builds both `authentix-app` (`./Dockerfile`, port `3000`) and `ocr-service` (`./services/ocr_service/Dockerfile`, port `8001`, pre-equipped with `tesseract-ocr`, `tesseract-ocr-eng`, `tesseract-ocr-hin`, and `poppler-utils`) with persistent named volume `authentix_data` and zero hard-coded fallback secrets:

```bash
export SESSION_SECRET="$(openssl rand -hex 32)"
export QR_SIGNING_SECRET="$(openssl rand -hex 32)"
docker compose up --build -d
```

- Web UI & API: `http://localhost:3000`
- App Health Check: `curl http://127.0.0.1:3000/api/health`
- Optional PostgreSQL 16 reference DDL validation container (`db/postgres-schema.sql` only):
  ```bash
  POSTGRES_PASSWORD="$(openssl rand -hex 24)" docker compose --profile postgres-db up -d
  ```

### Backup & Restore Guidance (SQLite WAL + Uploaded Evidence)

Because SQLite runs in Write-Ahead Logging (`WAL`) mode alongside stored original files in `UPLOAD_DIR`, **always back up both the database and `./data/uploads/` together**:

1. **Online Consistent Backup (Recommended while server is running):**
   ```bash
   mkdir -p backups/$(date +%Y%m%d)
   sqlite3 ./data/authentix.sqlite ".backup 'backups/$(date +%Y%m%d)/authentix.sqlite'"
   tar -czf "backups/$(date +%Y%m%d)/uploads.tar.gz" -C ./data uploads
   ```
   *(If `sqlite3` CLI is unavailable, stop the server cleanly with `SIGTERM`/`Ctrl+C` so WAL checkpoints into `authentix.sqlite`, then copy `authentix.sqlite` and `./data/uploads/`.)*
2. **Restore Procedure & Post-Restore Integrity Verification:**
   ```bash
   # 1. Stop the running AUTHENTIX server
   # 2. Remove any stale -wal / -shm files before copying the backup database
   rm -f ./data/authentix.sqlite-wal ./data/authentix.sqlite-shm
   cp backups/YYYYMMDD/authentix.sqlite ./data/authentix.sqlite
   tar -xzf backups/YYYYMMDD/uploads.tar.gz -C ./data
   # 3. Start the server and verify cryptographic audit chain integrity via GET /api/audit-logs/verify
   ```

---

## 6. Seeded Synthetic Demo Accounts & Roles (`ENABLE_DEMO_MODE=true` Only)

> **Safety Notice:** All seeded `*.demo` accounts, institutions (`INST-*`), applications (`APP-2026-0101` to `APP-2026-0105`), and certificates are **synthetic demonstration fixtures** (`is_synthetic_demo = 1`) created for `SIH26261` evaluation. They are strictly blocked (`403`/`404`) whenever `ENABLE_DEMO_MODE=false`.

**Default Synthetic Demo Passphrase (configurable via `DEMO_SEED_PASSWORD`, stored as `scrypt$16384$8$1` hash):** `Authentix@SIH2026!`

| Email | Role | Institution Scope | Authorised Capabilities |
| :--- | :--- | :--- | :--- |
| `officer@authentix.demo` | `REVIEW_OFFICER` | All institutions | Inspect queue, upload documents, run source checks, correct OCR fields, resolve findings, record manual verification & final officer decisions, export evidence reports |
| `auditor@authentix.demo` | `SENIOR_AUDITOR` | All institutions | Read/audit scrutiny queue (cannot upload files or issue final approve/reject), reopen finalized applications, verify cryptographic audit hash chain |
| `admin@authentix.demo` | `ADMIN` | All institutions | Full scrutiny, rule activation/deactivation & version publishing, sample dataset reset (in demo mode), and audit verification |
| `registrar@kaveritech.demo` | `INSTITUTION_USER` | `INST-KVTC-02` (*Kaveri Valley Technical Campus*) only | View own institution's applications (`APP-2026-0102`), submit new applications for own institution, upload supporting documents, and export own reports. Strictly blocked (`403`) from other institutions, officer decisions, rule editing, and global audit logs. |

---

## 7. Seeded Evaluation Scenarios (`SIH26261`)

| Application No. | Synthetic Institution | Pre-Seeded Scrutiny Scenario |
| :--- | :--- | :--- |
| **`APP-2026-0101`** | Indraprastha Institute of Engineering & Technology (`INST-IIET-01`) | Complete digital documentation (Fire Safety with HMAC-signed QR payload, Intake Affidavit, AICTE Fee Receipt) with clean metadata |
| **`APP-2026-0102`** | Kaveri Valley Technical Campus (`INST-KVTC-02`) | **Expired** Fire Safety Certificate + **Intake Mismatch** between Affidavit (`240`) and requested intake (`360`) + missing University NOC + **Facility Lab Photo** (`DOC-0102-4`) routed to `MANUAL_REVIEW_REQUIRED` compliance review |
| **`APP-2026-0103`** | Shivalik Hills Polytechnic (`INST-SHP-03`) | **Missing 4 mandatory documents** for `NEW_INSTITUTION` + **Built-up area shortfall** (`680 sqm` below configured threshold) |
| **`APP-2026-0104`** | Deccan Metro College of Engineering (`INST-DMCE-04`) | **Exact SHA-256 cross-application duplicate** (reuses `APP-2026-0101` Fire Safety PDF hash, triggering institution cross-check mismatch) + **Edited PDF Metadata** (`Adobe Photoshop` / post-creation `ModDate`) heuristic anomaly signal |
| **`APP-2026-0105`** | Nalanda Vishwakarma Sansthan (`INST-NVS-05`) | **Low-confidence bilingual scan** + **External Issuer Unavailability** (`SOURCE_UNAVAILABLE` in sandbox registry) demonstrating safe manual officer verification fallback without auto-rejection |

Downloadable sample test files generated in `./data/sample_docs/` when demo mode is seeded:
- `sample_valid_fire_safety.pdf`
- `sample_expired_fire_safety.pdf`
- `sample_tampered_metadata_affidavit.pdf`
- `sample_bilingual_low_conf_scan.png`
- `sample_unreadable_raster_only.png`
- `sample_facility_lab_photo.png`

---

## 8. Ports & Health-Check Endpoints

| Service | Default Port | Health Endpoint | Expected Response |
| :--- | :--- | :--- | :--- |
| **AUTHENTIX Web + API** | `3000` | `GET http://127.0.0.1:3000/api/health` | `200 OK` JSON with `status: "healthy"`, `database.connected: true`, `security.qrSigningConfigured`, `ocrService.pythonMicroserviceOnline` |
| **Python OCR & Forensics** | `8001` | `GET http://127.0.0.1:8001/health` | `200 OK` JSON with `status: "ok"`, `port: 8001`, `capabilities.tesseract_cli`, `capabilities.pdftotext_cli` |

---

## 9. Running Automated Tests & Build Verification

All tests execute against isolated temporary SQLite databases and temporary upload directories (never mutating `./data/authentix.sqlite`):

```bash
# Run complete test suite (Backend + Frontend + End-to-End Integration)
npm test

# Run individual suites
npm run test:backend
npm run test:frontend
npm run test:e2e

# Run TypeScript static type check & production frontend build
npm run lint
npm run build
```

---

## 10. Troubleshooting Common Startup Issues

- **Demo accounts are not shown on the login page:**
  Demo accounts and credentials are hidden by default (`ENABLE_DEMO_MODE=false`). Set `ENABLE_DEMO_MODE=true` and `AUTO_SEED_DEMO_DATA=true` in `.env` (or run `ENABLE_DEMO_MODE=true npm run db:seed`) and restart the server.
- **Windows `python3` opens Microsoft Store or exits with code `9009`:**
  Use `scripts\start-windows.ps1` or `py -3 services/ocr_service/server.py` instead of `python3`.
- **`ERR_UNKNOWN_BUILTIN_MODULE: node:sqlite`:**
  Your active Node version is older than `22.5.0`. Run `node -v` and switch to Node 22 LTS (`nvm use 22`).
- **`Port 3000 / 8001 already in use`:**
  Stop existing Node/Python processes or override `PORT` and `OCR_SERVICE_PORT` + `OCR_SERVICE_URL` in `.env`.
- **Production startup error on `SESSION_SECRET` or `QR_SIGNING_SECRET`:**
  In `NODE_ENV=production`, placeholder or short secrets (< 32 chars) are rejected. Generate random 32-byte hex values via `openssl rand -hex 32`.

---

## 11. Privacy, Data Retention & Honest Known Limitations

1. **No Live Government / AICTE Production API Connection:**
   Official AICTE, State Fire Directorate, Revenue Land Registry, PKI/CCA Certificate Revocation Lists, and NAD/DigiLocker production APIs require government VPN/empaneled credentials not present in public evaluation environments. `src/server/sourceVerification.ts` implements an 8-method provider-adapter boundary: `SANDBOX_ISSUER_API`, `DIGITAL_REPOSITORY`, and `REFERENCE_LOOKUP` query `sandbox_issuer_registry` (`isSandboxDemo: true`), whereas `OFFICIAL_API` and `OFFICIAL_PORTAL` honestly return `SOURCE_UNAVAILABLE` (`isSandboxDemo: false`) until live government endpoints are configured, and `DIGITAL_SIGNATURE` / bare QR payloads require manual PKI/issuer verification rather than claiming `VERIFIED` from container syntax alone.
2. **Facility Photographs & Infrastructure Norms Are Decision Support, Not Physical Proof:**
   `LocalDeterministicVisualInspector` inspects PNG/JPEG pixel dimensions, aspect ratios, file legibility, and metadata, and maps uploaded facility photos/floor plans to `application_compliance_items` (`MANUAL_REVIEW_REQUIRED`). An uploaded photograph cannot verify real-world room dimensions, equipment functionality, or physical site conditions; officers can flag applications for physical EVC (Expert Visit Committee) inspection (`physicalInspectionRequired`). Default numeric thresholds (`isIllustrative: true`) are configurable baselines and must be aligned by authorized administrators against the active AICTE Approval Process Handbook (APH) schedule for each academic year.
3. **Raster Image OCR Host Dependency:**
   Digital PDFs extract text, coordinates, and metadata natively in both Python and Node. Raw scanned PNG/JPEG images without embedded text chunks require the `tesseract` binary (`tesseract-ocr` + `tesseract-ocr-hin`), which is pre-installed in `services/ocr_service/Dockerfile` (`docker compose up`) but may be absent on a bare host. When absent, AUTHENTIX sets `ocrStatus: "UNAVAILABLE"` and flags the document for manual officer review rather than fabricating OCR output.
4. **Forensic Anomaly Signals Are Heuristic Indicators, Not Proof of Forgery:**
   Every finding carries a 5-way `epistemicClassification` (`MISSING_INFORMATION`, `ORDINARY_INCONSISTENCY`, `TECHNICAL_PROCESSING_FAILURE`, `SUSPECTED_ANOMALY`, or `CONFIRMED_SOURCE_MISMATCH`). PDF `/Info` editing tool signatures (`GIMP`, `Photoshop`), post-issuance `ModDate` deltas, incremental `%%EOF` revisions, and image block-clone/entropy checks produce `SUSPECTED_ANOMALY` signals (`isHeuristicSignal: true`). Legitimate institutional scanners and PDF compression tools can trigger them; human officers must inspect the original document.
5. **In-App Notifications Only (`IN_APP_ONLY`):**
   Workflow alerts (checklist deficiencies, source mismatches, resubmissions, additional evidence requests, and final decisions) are persisted in `in_app_notifications` and scoped by role/institution inside the web workbench. External email (SMTP/SES) and SMS gateways are not connected and are never simulated as delivered.
6. **Hash-Chained Audit Log Threat Model & Demo Retention Policy:**
   Each `audit_logs` row hashes `event_id | event_timestamp | actor_user_id | actor_role | action | resource_type | resource_id | canonical_json(metadata) | prev_hash` with SHA-256 (`verifyAuditChain`). Single-row SQL tampering is detected immediately, though a privileged OS/root attacker with write access to `./data/authentix.sqlite` could rewrite the chain from genesis unless anchored to external append-only WORM storage in production. Uploaded files are stored locally under `./data/uploads/` (gitignored) and purged on `npm run db:reset`; do **not** upload real unredacted PII into a demo instance.
