# ZK-XDR Graph Platform - Architecture

## Overview

ZK-XDR Graph is an identity-aware Extended Detection and Response (XDR) platform that combines zero-knowledge device trust, asset-risk graphing, federated CTI, and SOAR playbooks for SOC operations.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            DATA COLLECTION LAYER                            │
├─────────────┬─────────────┬─────────────┬─────────────┬─────────────────────┤
│  DDI        │  WAF        │  Mail       │  eBPF       │  ZK Prover          │
│  Connector  │  Connector  │  Connector  │  Collectors │  (Noir Circuits)    │
└──────┬──────┴──────┬──────┴──────┬──────┴──────┬──────┴──────────┬──────────┘
       │             │             │             │                  │
       └─────────────┴─────────────┴─────────────┴──────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          EVENT PROCESSING LAYER                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                         Redis Streams (xdr:events)                          │
├─────────────┬─────────────┬─────────────┬─────────────┬─────────────────────┤
│  Event      │  Risk       │  Asset      │  CTI        │  Anomaly            │
│  Normalizer │  Scoring    │  Graph      │  Matcher    │  Detection          │
│  (Go)       │  (Go)       │  (Go+Neo4j) │  (Python)   │  (Julia)            │
└──────┬──────┴──────┬──────┴──────┬──────┴──────┬──────┴──────────┬──────────┘
       │             │             │             │                  │
       └─────────────┴─────────────┴─────────────┴──────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          STORAGE LAYER                                      │
├─────────────────┬─────────────────┬─────────────────┬───────────────────────┤
│  ClickHouse     │  Neo4j          │  Qdrant         │  MinIO                │
│  (Events)       │  (Graph)        │  (Vectors)      │  (Evidence)           │
└─────────────────┴─────────────────┴─────────────────┴───────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                      INTELLIGENCE & RESPONSE LAYER                          │
├─────────────────┬─────────────────┬─────────────────┬───────────────────────┤
│  Correlation    │  SOAR           │  CTI Lakehouse  │  Analyst              │
│  Engine (Go)    │  Playbook (Go)  │  (Python)       │  Copilot (Python)     │
└─────────────────┴─────────────────┴─────────────────┴───────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                            API & UI LAYER                                   │
├─────────────────┬─────────────────┬─────────────────────────────────────────┤
│  Go API Gateway │  Next.js        │  Grafana / Prometheus                   │
│  (Chi router)   │  XDR Console    │  (Observability)                        │
└─────────────────┴─────────────────┴─────────────────────────────────────────┘
```

## Services

### Collection (7 languages)

| Service | Language | Port | Purpose |
|---------|----------|------|---------|
| API Gateway | Go | 8080 | REST API, JWT auth, RBAC |
| Event Normalizer | Go | - | Redis Streams consumer, normalizes raw events |
| DDI Connector | Go | - | DNS security event collection |
| WAF Connector | Go | - | Web application firewall events |
| Mail Connector | Go | - | Email security event collection |
| IoC Parsers | Rust | 8085 | Regex-based IoC extraction from text |
| Anomaly Detection | Julia | 8086 | Statistical anomaly detection (Z-score) |

### Processing

| Service | Language | Port | Purpose |
|---------|----------|------|---------|
| Risk Scoring | Go | - | Computes asset trust scores |
| Asset Graph | Go | - | Builds Neo4j graph relationships |
| CTI Matcher | Python | - | Matches events against IoCs |
| Correlation Engine | Go | - | Multi-signal incident correlation |

### Intelligence

| Service | Language | Port | Purpose |
|---------|----------|------|---------|
| CTI Lakehouse | Python | 8095 | Federated IoC management API |
| Analyst Copilot | Python | 8090 | RAG-powered threat analysis |
| SOAR Playbook | Go | - | Automated response execution |

### Storage

| Service | Port | Purpose |
|---------|------|---------|
| PostgreSQL | 5432 | Relational data (users, tenants, assets) |
| Redis | 6379 | Event streams, cache, rate limiting |
| Neo4j | 7474/7687 | Asset risk graph |
| ClickHouse | 8123/9000 | Event analytics, time-series |
| MinIO | 9001/9002 | Object storage (evidence, CTI bundles) |
| Qdrant | 6333/6334 | Vector database (CTI embeddings) |

### Frontend

| Service | Port | Purpose |
|---------|------|---------|
| Next.js Console | 3000 | XDR SOC dashboard |
| Grafana | 3001 | Observability dashboards |
| Prometheus | 9090 | Metrics collection |

## Data Flow

### 1. Event Ingestion
```
Connectors → Redis Streams (xdr:events)
```
Each connector normalizes raw telemetry into the XDR event envelope format.

### 2. Event Processing (parallel)
```
xdr:events → Event Normalizer → Normalized Events
xdr:events → Risk Scoring → Updated Trust Scores
xdr:events → Asset Graph → Neo4j Relationships
xdr:events → CTI Matcher → IoC Matches
xdr:events → Anomaly Detection → Anomaly Alerts
```

### 3. Incident Creation
```
Correlation Engine → ClickHouse (xdr_incidents) → Redis (xdr:incidents)
```

### 4. Automated Response
```
xdr:incidents → SOAR Playbook Engine → Playbook Executions
```

### 5. Frontend Display
```
API Gateway → Next.js Console (real-time updates)
```

## ZK Device Trust

The platform uses zero-knowledge proofs for device identity attestation:

1. **Device Identity Proof** - Proves device knows its secret key
2. **Compliance Proof** - Proves compliance without revealing data
3. **Attestation Proof** - Proves trusted authority attestation
4. **Trust Score Proof** - Proves trust score computation correctness

Circuits are implemented in Noir and can be verified on-chain or off-chain.

## MITRE ATT&CK Coverage

| Tactic | Technique | Detection |
|--------|-----------|-----------|
| Initial Access | T1566 (Phishing) | Mail connector, CTI matching |
| Initial Access | T1190 (Exploit Public App) | WAF rules |
| Execution | T1059 (Command Line) | eBPF process collector |
| Persistence | T1542 (Pre-OS Boot) | ZK attestation failure |
| Credential Access | T1110 (Brute Force) | WAF rate limiting |
| C2 | T1071 (Application Layer) | DDI connector, anomaly detection |
| C2 | T1568 (Dynamic Resolution) | DGA detection |
| Exfiltration | T1048 (Exfil Over Alt Protocol) | Network anomaly detection |
| Impact | T1499 (Endpoint DoS) | Rate limiting, correlation |
