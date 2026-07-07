# ZK-XDR Graph Platform

> **Zero-Knowledge Extended Detection & Response** with Device Trust, Federated CTI, and SOAR Playbooks

[![CI](https://github.com/quantumworld-dpdns-io/zk-xdr-graph/actions/workflows/ci.yml/badge.svg)](https://github.com/quantumworld-dpdns-io/zk-xdr-graph/actions)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.23-00ADD8?logo=go)](https://golang.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.4-3178C6?logo=typescript)](https://www.typescriptlang.org/)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python)](https://www.python.org/)
[![Rust](https://img.shields.io/badge/Rust-1.77-000000?logo=rust)](https://www.rust-lang.org/)
[![Julia](https://img.shields.io/badge/Julia-1.10-9558B2?logo=julia)](https://julialang.org/)
[![Noir](https://img.shields.io/badge/Noir-0.23-000000)](https://noir-lang.org/)
[![C/eBPF](https://img.shields.io/badge/C-eBPF-A4935F)](https://ebpf.io/)

## Overview

ZK-XDR Graph is a full-stack security operations platform that unifies:
- **Agentless XDR** - Multi-source threat detection across DDI, WAF, Mail, and Endpoints
- **Zero-Knowledge Device Trust** - Cryptographic device attestation using Noir ZK circuits
- **Federated CTI Lakehouse** - IoC matching with Redis Streams-based threat intelligence
- **SOAR Playbooks** - Automated incident response with approval workflows
- **Asset Risk Graph** - Neo4j-based relationship mapping with MITRE ATT&CK mapping
- **AI Analyst Copilot** - RAG-powered threat analysis and investigation assistance

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        ZK-XDR Graph Platform                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐          │
│  │   DDI    │  │   WAF    │  │   Mail   │  │ Endpoint │  Sources  │
│  │Connector │  │Connector │  │Connector │  │Collector │          │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘          │
│       │              │              │              │                │
│       └──────────────┴──────┬───────┴──────────────┘                │
│                             │                                       │
│                    ┌────────▼────────┐                              │
│                    │  Event Stream   │  Redis Streams                │
│                    │  (xdr:events)   │                              │
│                    └────────┬────────┘                              │
│                             │                                       │
│       ┌─────────────────────┼─────────────────────┐                │
│       │                     │                     │                │
│  ┌────▼─────┐  ┌────────────▼──────────┐  ┌──────▼─────┐         │
│  │   Risk   │  │  Correlation Engine   │  │   Asset    │         │
│  │ Scoring  │  │  (5 rules, MITRE)     │  │   Graph    │         │
│  └────┬─────┘  └──────────┬────────────┘  └──────┬─────┘         │
│       │                   │                      │                 │
│       └───────────────────┼──────────────────────┘                 │
│                           │                                        │
│                    ┌──────▼──────┐                                 │
│                    │ClickHouse DB│  5 tables, 30+ columns         │
│                    └──────┬──────┘                                 │
│                           │                                        │
│              ┌────────────┼────────────┐                           │
│              │            │            │                            │
│         ┌────▼────┐  ┌────▼────┐  ┌────▼────┐                    │
│         │CTI Lake │  │ SOAR    │  │ Analyst │                     │
│         │house    │  │Playbook │  │ Copilot │                     │
│         └─────────┘  └─────────┘  └─────────┘                     │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    API Gateway (Go/Chi)                     │   │
│  │  JWT Auth │ Rate Limiting │ Audit Logging │ /metrics        │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                  Console Web (Next.js)                      │   │
│  │  Dashboard │ Assets │ Incidents │ Graph │ CTI │ Playbooks   │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                Observability Stack                           │   │
│  │  Prometheus (14 scrape targets) │ Grafana (14 panels)      │   │
│  │  Alert Rules (8 alerts) │ Loki │ Health Checks             │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │              ZK Device Trust (Noir Circuits)                 │   │
│  │  device_identity │ compliance_proof │ attestation_proof     │   │
│  │  trust_score │ main_selector │ 4 test suites                │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

## Tech Stack (7 Languages)

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Core Services** | Go 1.23 + Chi + GORM | API Gateway, Risk Scoring, Asset Graph, Correlation Engine, SOAR, Connectors |
| **Frontend** | Next.js 14 + TypeScript + Tailwind | SOC Console (14 routes, real-time dashboard) |
| **CTI & AI** | Python 3.12 + FastAPI | CTI Lakehouse, IoC Matching, Analyst Copilot (RAG) |
| **IoC Parsers** | Rust + Axum | High-performance IoC extraction (IP, domain, hash, CVE) |
| **Anomaly Detection** | Julia | Statistical Z-score anomaly detection |
| **ZK Circuits** | Noir | Device identity, compliance, attestation, trust scoring |
| **eBPF Collectors** | C | Process and network telemetry collection |
| **Databases** | Neo4j, ClickHouse, PostgreSQL, Redis, Qdrant, MinIO | Graph, Analytics, Relational, Cache, Vector, Object Storage |
| **Observability** | Prometheus + Grafana + Loki | Metrics (14 targets), Dashboards (14 panels), Logs |

## Services (20+ Docker Containers)

| Service | Port | Description |
|---------|------|-------------|
| API Gateway | 8080 | REST API with JWT auth, rate limiting, audit |
| Console Web | 3000 | Next.js SOC console |
| Event Normalizer | - | Normalizes raw events to XDR envelope |
| Risk Scoring | 9091 | Computes asset trust scores |
| Asset Graph | 9092 | Builds Neo4j graph from events |
| Correlation Engine | 9093 | Multi-signal incident correlation (5 rules) |
| SOAR Playbook | 9094 | Automated response engine (5 playbooks) |
| DDI Connector | 9095 | DNS security events (suspicious TLD, DGA) |
| WAF Connector | 9096 | Web application firewall events |
| Mail Connector | 9097 | Email security events (phishing, attachments) |
| CTI Lakehouse | 8095 | Federated threat intelligence API |
| IoC Parsers | 8085 | Rust-based IoC extraction |
| Analyst Copilot | 8090 | AI-powered threat analysis |
| Anomaly Detection | 8086 | Statistical anomaly detection |
| Prometheus | 9090 | Metrics collection (14 targets) |
| Grafana | 3001 | Dashboards (14 panels, 8 alert rules) |
| Neo4j | 7474/7687 | Asset graph database |
| ClickHouse | 8123/9000 | Event analytics |
| Redis | 6379 | Event streaming |
| PostgreSQL | 5432 | Relational storage |

## MITRE ATT&CK Coverage

| Tactic | Technique | Implementation |
|--------|-----------|----------------|
| Initial Access | T1566 (Phishing) | Mail Connector |
| Initial Access | T1190 (Exploit Public App) | WAF Connector |
| Execution | T1059 (Command and Scripting) | Process Collector (eBPF) |
| Persistence | T1547 (Boot/Logon Autostart) | ZK Device Trust |
| Credential Access | T1110 (Brute Force) | WAF Connector + Correlation |
| Discovery | T1046 (Network Service Scan) | Network Collector (eBPF) |
| C2 | T1071.004 (DNS) | DDI Connector + Correlation |
| C2 | T1568.002 (DGA) | DDI Connector + Correlation |
| Impact | T1499 (DDoS) | WAF Connector + Correlation |

## Quick Start

```bash
# Prerequisites: Docker, Docker Compose, Go 1.23+, Node.js 20+, Python 3.12+

# Clone and setup
git clone https://github.com/quantumworld-dpdns-io/zk-xdr-graph.git
cd zk-xdr-graph
make setup          # Install all dependencies

# Start infrastructure
make up             # Start Docker stack (20+ services)

# Run demo attack scenario
make demo-attack    # 6-phase coordinated attack simulation

# Access the platform
open http://localhost:3000    # SOC Console
open http://localhost:3001    # Grafana Dashboard
open http://localhost:8080    # API Gateway
```

## API Reference

Full OpenAPI 3.0 specification: [`docs/openapi.yaml`](docs/openapi.yaml) (25+ endpoints)

```bash
# Authentication
POST /api/v1/auth/login              # Get JWT token
POST /api/v1/auth/register           # Create account

# Assets (5 endpoints)
GET  /api/v1/assets                  # List assets
POST /api/v1/assets                  # Create asset
GET  /api/v1/assets/:id              # Get asset
PUT  /api/v1/assets/:id              # Update asset
DELETE /api/v1/assets/:id            # Soft-delete asset

# Events (3 endpoints)
POST /api/v1/events/ingest           # Ingest XDR event
GET  /api/v1/events                  # List events
GET  /api/v1/events/:id              # Get event

# Incidents (5 endpoints)
GET  /api/v1/incidents               # List incidents
POST /api/v1/incidents               # Create incident
GET  /api/v1/incidents/:id           # Get incident
POST /api/v1/incidents/:id/assign    # Assign analyst
POST /api/v1/incidents/:id/close     # Mark resolved

# CTI (3 endpoints)
GET  /api/v1/cti/indicators          # List IoC indicators
POST /api/v1/cti/indicators          # Create IoC indicator
POST /api/v1/cti/lookup              # Search indicators

# Playbooks (3 endpoints)
GET  /api/v1/playbooks               # List playbooks
POST /api/v1/playbooks/:id/dry-run   # Preview actions
POST /api/v1/playbooks/:id/execute   # Execute playbook

# ZK Proofs (2 endpoints)
POST /api/v1/proofs/generate         # Generate attestation proof
POST /api/v1/proofs/verify           # Verify ZK proof

# AI Copilot (2 endpoints)
POST /api/v1/copilot/summarize-incident   # LLM incident summary
POST /api/v1/copilot/recommend-playbook   # LLM playbook recommendation

# Observability
GET  /api/v1/health                  # Health check
GET  /api/v1/metrics                 # Prometheus metrics
```

## ZK Circuits

```bash
# Noir circuits for device trust
circuits/
├── src/
│   ├── device_identity.nr    # Device fingerprint attestation
│   ├── compliance_proof.nr   # Security compliance verification
│   ├── attestation_proof.nr  # Remote attestation proof
│   ├── trust_score.nr        # Trust score computation
│   └── main.nr               # Circuit selector
└── tests/
    ├── device_identity_test.nr
    ├── compliance_test.nr
    ├── attestation_test.nr
    └── trust_score_test.nr
```

## eBPF Collectors

```c
// Process Collector - traces execve, fork, exit
// Network Collector - traces TCP/UDP connections
// Demo mode with simulated events for testing
```

## Monitoring

- **Prometheus**: 14 scrape targets across all services
- **Grafana**: 14-panel XDR overview dashboard
- **Alert Rules**: 8 alerts (incident rate, trust score, phishing, DGA, service health)
- **Loki**: Centralized log aggregation

## Development

```bash
make test           # Run all tests
make test-go        # Go unit tests only
make test-robot-smoke  # Robot Framework smoke tests
make test-robot-e2e    # Robot Framework E2E tests
make test-rust      # Rust unit tests
make lint           # Run linters
make build          # Build all services
make build-all      # Build including eBPF and ZK circuits
make health         # Check all service health
make status         # Docker Compose status
make logs           # Tail all service logs
```

## Testing

| Test Type | Framework | Count | Description |
|-----------|-----------|-------|-------------|
| Go Unit Tests | `testing` | 18 | Scoring, correlation rules, detection functions |
| Rust Unit Tests | `cargo test` | 5 | IoC regex extraction (IP, domain, CVE, hash) |
| Integration | Robot Framework | 7 suites | API health, CRUD, pipeline, auth, negative, E2E demo |
| E2E Demo | Shell script | 10 steps | Full attack simulation verification |

## Project Structure

```
zk-xdr-graph/
├── apps/
│   ├── api-gateway/          # Go API (Chi, GORM, JWT)
│   └── console-web/          # Next.js SOC console
├── services/
│   ├── event-normalizer/     # Event normalization
│   ├── risk-scoring/         # Trust score computation
│   ├── asset-graph/          # Neo4j graph builder
│   ├── correlation-engine/   # Incident correlation
│   ├── soar-playbook/        # SOAR execution
│   ├── connectors/           # DDI, WAF, Mail connectors + detection logic
│   ├── cti-lakehouse/        # CTI API + Matcher
│   ├── analyst-copilot/      # AI RAG service
│   ├── ioc-parsers/          # Rust IoC extraction
│   ├── anomaly-detection/    # Julia anomaly detection
│   └── ebpf-collectors/      # C eBPF probes
├── circuits/                 # Noir ZK circuits (4 proof types)
├── infra/                    # Docker, Grafana, Prometheus
├── schemas/                  # JSON schemas (6 schemas)
├── detections/
│   └── sigma/                # Sigma detection rules (5 MITRE techniques)
├── playbooks/                # SOAR playbook YAMLs (5 playbooks)
├── tests/robot/              # Robot Framework integration tests
└── docs/
    ├── ARCHITECTURE.md       # System architecture
    ├── QUICKSTART.md         # Setup guide
    ├── CASE_STUDY.md         # Technical case study
    └── openapi.yaml          # OpenAPI 3.0 specification (25+ endpoints)
```

## Technical Deep Dive

See [docs/CASE_STUDY.md](docs/CASE_STUDY.md) for architecture decisions, trade-offs, and lessons learned.

## Detection Rules

Sigma-format detection rules for MITRE ATT&CK techniques in `detections/sigma/`:
- `phishing_t1566.yml` - Email phishing detection
- `brute_force_t1110.yml` - Credential stuffing attacks
- `ddos_t1499.yml` - DDoS attack patterns
- `dga_t1568.yml` - DGA domain generation
- `dns_beacon_t1071.yml` - DNS beaconing C2

## SOAR Playbooks

Formal playbook definitions in `playbooks/`:
- `device_quarantine.yml` - ZK attestation failure response
- `dns_response.yml` - Suspicious DNS blocking
- `api_abuse.yml` - API rate limiting
- `ddos_mitigation.yml` - DDoS response
- `phishing_response.yml` - Phishing email quarantine

## License

Apache-2.0
