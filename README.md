# 🩸 BloodMatch Clinical Backend Service

Production-ready FastAPI backend microservice powering the BloodMatch emergency transfusion network.

## 🌟 Key Architecture & Capabilities

- **Production-Grade Database Abstraction**: Powered by SQLAlchemy ORM with multi-tier failover.
- **Resilient Fallback**: Automatically connects to PostgreSQL (Supabase). In the event of network disruption, DNS resolution issues, or server downtime, it seamlessly falls back to a persistent local SQLite engine with connection pooling (`StaticPool`).
- **Auto-Schema Migration & Seeding**: Auto-inspects database metadata on startup and pre-seeds ABO & RhD clinical inventory units without crashing.
- **Clean Session Lifecycle**: Dependency-injected sessions (`get_db`) with automatic commit on success, transaction rollback on failure, and clean closure.
- **Zero Hardcoded URLs & Credentials**: All sensitive configurations are strictly read via runtime environment variables.

## 🚀 Quick Start (Local Development)

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run service
uvicorn main:app --reload --port 8000
```

- API Base: `http://localhost:8000`
- Interactive Swagger UI: `http://localhost:8000/docs`
- Health Check: `http://localhost:8000/health`

## ☁️ Environment Configuration (Render / Production)

Set the following environment variables in your Render Web Service dashboard:

| Variable | Description |
|---|---|
| `DATABASE_URL` | PostgreSQL connection string (e.g. Supabase pooler or direct URI) |
| `PORT` | Application listening port (defaults to `8000`) |
| `CORS_ORIGINS` | Comma-separated allowed frontend domains |

## 📦 Deployment Specification

- **Environment**: Python 3.11+
- **Build Command**: `pip install -r requirements.txt`
- **Start Command**: `uvicorn main:app --host 0.0.0.0 --port $PORT`
