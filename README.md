# 🩸 BloodMatch Clinical Backend Service

Production-ready Python API microservice powering the BloodMatch emergency transfusion network.

## 🚀 Quick Start (Local Development)

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run locally
uvicorn main:app --reload --port 8000
```

- Local API: `http://localhost:8000`
- Interactive OpenAPI Docs: `http://localhost:8000/docs`

## ☁️ Deployment on Render

- **Runtime**: Python 3.11+
- **Build Command**: `pip install -r requirements.txt`
- **Start Command**: `uvicorn main:app --host 0.0.0.0 --port $PORT`
