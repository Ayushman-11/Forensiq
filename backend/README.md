# Forensiq Backend Service

> Production-grade, SIEM-agnostic FastAPI backend for the Forensiq AI Security Operations Platform.

---

## Architecture Overview

Forensiq Backend strictly follows **Clean Architecture**:

- **Presentation Layer**: FastAPI Routers (`app/api/v1/endpoints/`)
- **Application Layer**: Business Logic Services (`app/services/`)
- **Domain Layer**: Normalized Pydantic Schemas (`app/schemas/normalized_event.py`)
- **Infrastructure Layer**: SIEM Adapters (`app/infrastructure/siem/`) & ORM (`app/models/`)

### SIEM Abstraction Protocol
Services communicate with telemetry providers through the abstract `SIEMProvider` protocol:

```
FastAPI / Services → SIEMProvider Interface → SplunkClient / ElasticClient / SentinelClient
```

---

## Getting Started

### Prerequisites
- Python 3.13+
- Docker & Docker Compose
- PostgreSQL (or Docker container)
- Splunk Enterprise with REST API enabled (`https://localhost:8089`)

### Running Locally

```bash
# 1. Navigate to backend
cd backend

# 2. Configure environment
cp .env.example .env

# 3. Install dependencies using uv
uv pip install -e .

# 4. Run server
uvicorn app.main:app --reload --port 8000
```

### Running via Docker Compose

```bash
docker-compose -f docker/docker-compose.yml up --build
```

---

## Interactive API Documentation

Once the server is running, interactive Swagger API docs are available at:
- **Swagger UI**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **ReDoc**: [http://localhost:8000/redoc](http://localhost:8000/redoc)

---

## API Endpoints (`/api/v1`)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/health` | Service and SIEM provider health check |
| `POST` | `/api/v1/search` | Search normalized security telemetry |
| `GET` | `/api/v1/alerts` | List triggered SIEM alerts |

---

## Running Tests

```bash
python -m pytest tests/ -v
```
