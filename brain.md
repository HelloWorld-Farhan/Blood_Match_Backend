# BloodMatch Backend Architecture & Operational Brain (`brain.md`)

> [!CAUTION]
> **CRITICAL SECURITY DIRECTIVE**:
> **NEVER COMMIT `.env` FILES, API KEYS, OR PRODUCTION CREDENTIALS TO GITHUB.**
> All sensitive configuration must be managed strictly through host environment dashboards (e.g., Render Environment Variables, Cloudflare Secrets, or local un-tracked `.env` files). All `.env*` files are strictly excluded via `.gitignore`.

---

## 1. Architectural Topology & Systems Overview

```mermaid
flowchart TD
    subgraph Clients ["Clinical Clients"]
        CF[Cloudflare SPA Frontend]
        Mobile[Mobile & Workstation Terminals]
    end

    subgraph Backend ["Render Production Web Service (FastAPI)"]
        API[FastAPI Gateway :10000]
        Auth[JWT Session & Adaptive 2FA Engine]
        R2Service[Cloudflare R2 Storage Controller]
        StateSync[Master Cloud State Sync Engine]
    end

    subgraph Storage ["Persistent Multi-Tier Storage"]
        PG[(Supabase PostgreSQL Primary)]
        SQLite[(Local SQLite Fallback - Zero Crash)]
        R2[(Cloudflare R2 Object Storage S3)]
    end

    subgraph Notifications ["Email & Security Node"]
        GAS[Google Apps Script Webhook Code.gs]
        SMTP[SMTP Transport Fallback]
    end

    CF -->|HTTPS REST| API
    Mobile -->|HTTPS REST| API
    API --> Auth
    API --> R2Service
    API --> StateSync

    Auth -->|Primary DB| PG
    Auth -.->|Fallback on Disconnect| SQLite
    R2Service -->|S3 Upload/Avatar| R2
    StateSync -->|Master JSON Mirror| R2
    API -->|Email Webhook| GAS
    API -.->|SMTP Fallback| SMTP
```

---

## 2. Environment Variables Reference (Render Dashboard)

All variables below must be supplied in your **Render Web Service Dashboard** under **Environment**:

| Environment Variable | Sample Production Value | Purpose & Operational Function |
| :--- | :--- | :--- |
| **`PORT`** | `10000` | Render default container port. FastAPI binds dynamically via `uvicorn main:app --host 0.0.0.0 --port $PORT`. |
| **`CORS_ORIGINS`** | `https://your-frontend.workers.dev,http://localhost:5173` | Comma-separated list of allowed origins. Also backed by an automated regex permitting `*.workers.dev`, `*.pages.dev`, and `localhost`. |
| **`DATABASE_URL`** | `postgresql://postgres:Password%403042@db.your-id.supabase.co:5432/postgres` | Primary PostgreSQL database connection string. *Special characters (such as `@`) in the password must be URL-encoded (e.g., `%40`).* |
| **`SUPABASE_URL`** | `https://your-project-id.supabase.co` | Supabase project API gateway endpoint. |
| **`SUPABASE_KEY`** | `eyJhbGciOi...` | Supabase administrative `service_role` secret key. |
| **`R2_ACCOUNT_ID`** | `d4210ca572e...` | Cloudflare account identifier for R2 object storage. |
| **`R2_ENDPOINT`** | `https://<account_id>.r2.cloudflarestorage.com` | S3-compatible API endpoint for Cloudflare R2 uploads and deletes. |
| **`R2_BUCKET_NAME`** | `bloodmatch-storage` | Target storage bucket for user assets, avatars, and state sync JSON. |
| **`R2_ACCESS_KEY_ID`** | `3a61a4e29...` | Cloudflare R2 API token identifier. |
| **`R2_SECRET_ACCESS_KEY`** | `577e6bed8...` | Cloudflare R2 API token secret key. |
| **`R2_PUBLIC_URL`** | `https://pub-5a4ed1cf142043998d5af2e9b797e868.r2.dev` | Public CDN URL for serving avatars, documents, and medical assets. |
| **`GOOGLE_APP_SCRIPT_URL`** | `https://script.google.com/macros/s/<ID>/exec` | Autonomous zero-cost email delivery webhook powered by `Code.gs`. |
| **`JWT_SECRET`** | `bloodmatch_jwt_super_secret_production_key_2026` | Cryptographic secret for signing clinician access and session tokens. |

---

## 3. Core Architectural Subsystems

### A. Zero Hardcoded URLs Directive
* No API URLs, external hostnames, or credentials are hardcoded in the codebase.
* All endpoints, origins, and S3 paths dynamically resolve through `os.getenv()`.
* Missing credentials safely fall back to local offline simulation or relative paths without raising unhandled runtime exceptions.

### B. Resilient Multi-Tier Database Layer (`database.py`)
* **Primary**: Attempts connection to cloud PostgreSQL (`DATABASE_URL`) with a 3-second timeout (`connect_timeout=3`).
* **Automated URL Sanitization**: Automatically detects unescaped `@` symbols in the database password and URL-encodes them to `%40` to protect against connection string parser failures.
* **Persistent SQLite Fallback**: If PostgreSQL times out or DNS fails, the system automatically activates `bloodmatch_fallback.db` with `StaticPool` and `check_same_thread=False` to prevent crashes and ensure 100% operational uptime.
* **Auto-Schema Migration**: Application startup verifies tables and seeds the 8 baseline ABO/Rh blood groups (`O-`, `O+`, `A-`, `A+`, `B-`, `B+`, `AB-`, `AB+`) if the inventory table is empty.

### C. Cloudflare R2 Storage & Disaster-Proof State Sync (`storage_service.py`, `main.py`)
* **Tenant Isolation**: Uploads and downloads are partitioned strictly under `users/{sanitized_user_email}/`. Cross-tenant asset access attempts are rejected with `HTTP 403 Forbidden`.
* **Avatar WebP Optimization**: Avatars are cropped on-the-fly via Pillow, compressed to WebP at quality 88, bounded to a maximum of 1024x1024px, and validated under the 5MB payload ceiling.
* **Disaster Recovery Cloud Mirror**: Whenever records are created, updated, or deleted, the user's complete state is serialized to `users/{user_email}/clinical_sync_data.json` in Cloudflare R2. Upon startup or container wipe, `GET /api/v1/sync/all` automatically re-hydrates the local database.

### D. Google Apps Script Webhook Engine (`google_apps_script/Code.gs`)
* Provides an autonomous, zero-cost email delivery infrastructure with 7 distinct clinical email templates:
  1. `otp_verification`: Registration 6-digit OTP code.
  2. `2fa_login`: Step-up two-factor code with workstation and origin IP telemetry.
  3. `new_login_session`: Instant advisory when an account is accessed on a new workstation.
  4. `password_reset`: 6-digit recovery code.
  5. `password_changed`: Security audit confirmation with workstation metadata.
  6. `account_lockout`: Threat mitigation unlock token after 3 failed login attempts.
  7. `welcome_thankyou`: Verified clearance and welcome notification upon registration completion.
* **Spam-Resistant Minimal UI**: Designed without action buttons, using crimson `#D72638` brand pills, clean white cards on `#F5F1EF` canvas, and monospace token containers.

---

## 4. Local Development & Deployment Commands

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run local FastAPI dev server
uvicorn main:app --host 0.0.0.0 --port 8000 --reload

# 3. Execute integration test suite
python test_google_apps_script_engine.py

# 4. Clean database reset (wipes test data and seeds pristine inventory)
python reset_database.py
```
