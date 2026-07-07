# ZK-XDR Graph - Quick Start

## Prerequisites

- Docker & Docker Compose
- Node.js 18+ (for frontend dev)
- Go 1.22+ (for Go services dev)
- Python 3.12+ (for Python services dev)

## 1. Start the Stack

```bash
# Clone and setup
git clone <repo-url>
cd ZK-XDR-Graph-Agentless-XDR-ZK-Device-Trust-Federated-CTI-Lakehouse
cp .env.example .env

# Start all services
make up

# Or start core services only (faster)
make up-core
```

## 2. Verify Services

```bash
# Check all health endpoints
make health

# Or manually
curl http://localhost:8080/api/v1/health    # API Gateway
curl http://localhost:8095/api/v1/health    # CTI Lakehouse
curl http://localhost:8090/api/v1/health    # Analyst Copilot
curl http://localhost:8085/api/v1/health    # IoC Parsers
curl http://localhost:8086/api/v1/health    # Anomaly Detection
```

## 3. Access the UI

- **XDR Console**: http://localhost:3000
- **Grafana**: http://localhost:3001 (admin/admin)
- **Neo4j Browser**: http://localhost:7474 (neo4j/changeme)
- **MinIO Console**: http://localhost:9001 (minioadmin/minioadmin)

## 4. Run the Demo

```bash
# Install Python Redis client
pip install redis

# Run end-to-end attack demo
make demo-e2e

# Watch the events flow through the system
make logs
```

## 5. Development

### Frontend
```bash
cd apps/console-web
npm install
npm run dev    # http://localhost:3000
```

### Go Services
```bash
cd apps/api-gateway
go run ./cmd/server
```

### Python Services
```bash
cd services/cti-lakehouse
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8095
```

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full architecture diagram and service descriptions.

## API Reference

### API Gateway (port 8080)
```
POST   /api/v1/auth/login          # Login
POST   /api/v1/auth/register       # Register
GET    /api/v1/assets              # List assets
GET    /api/v1/incidents           # List incidents
POST   /api/v1/events/ingest       # Ingest event
GET    /api/v1/cti/lookup          # IoC lookup
POST   /api/v1/playbooks/dry-run   # Dry run playbook
POST   /api/v1/playbooks/execute   # Execute playbook
```

### CTI Lakehouse (port 8095)
```
GET    /api/v1/iocs                # List IoCs
POST   /api/v1/iocs                # Create IoC
POST   /api/v1/iocs/search         # Search IoCs
POST   /api/v1/iocs/match          # Match values against IoCs
```

### Analyst Copilot (port 8090)
```
POST   /api/v1/copilot/query       # Ask threat question
POST   /api/v1/copilot/enrich      # Enrich indicator
POST   /api/v1/copilot/summarize   # Summarize incident
```

### IoC Parsers (port 8085)
```
POST   /api/v1/parse               # Extract IoCs from text
```

### Anomaly Detection (port 8086)
```
POST   /api/v1/detect              # Detect anomalies in events
```
