# ZK-XDR Graph Platform

> Agentless XDR + ZK Device Trust + Federated CTI Lakehouse + SOAR Playbooks

## Quick Start

```bash
# Setup
make setup

# Start local stack
make up

# Seed demo data
make seed-demo

# Generate demo attack
make demo-attack
```

## Architecture

See [docs/architecture.md](docs/architecture.md)

## Tech Stack

| Layer | Stack |
|---|---|
| Web Console | Next.js, React, TypeScript, Tailwind CSS |
| API Gateway | Go, Chi, GORM |
| Event Stream | Redis Streams |
| Graph DB | Neo4j |
| Analytics | ClickHouse |
| Object Storage | MinIO |
| Vector DB | Qdrant |
| Relational DB | PostgreSQL |
| ZK Proofs | Noir, RISC Zero |
| AI/Copilot | Python, FastAPI, LangChain |
| Anomaly Detection | Julia |
| eBPF Collectors | C |

## License

Apache-2.0
