# ZK-XDR Graph Platform - Technical Case Study

## Problem Statement

Modern security operations centers (SOCs) face three critical challenges:

1. **Fragmented Tooling** - Security teams use 10+ disconnected tools, creating blind spots between network, endpoint, email, and identity domains
2. **Alert Fatigue** - Without correlation, hundreds of daily alerts overwhelm analysts, hiding real threats
3. **Slow Response** - Manual incident response takes hours or days, allowing attackers to persist

**ZK-XDR Graph** addresses these challenges by unifying detection, correlation, and automated response in a single platform with cryptographic device trust.

## Architecture Decisions

### Why Redis Streams (not Kafka)?

**Trade-off**: Kafka offers durability and replay at scale, but Redis Streams provides:
- Sub-millisecond latency for real-time event correlation
- Consumer groups for parallel processing without partition management
- Simpler operational model for a 15-service architecture
- Sufficient throughput for 10K+ events/second on modest hardware

**Decision**: Redis Streams for the event backbone. Kafka can replace it at scale without changing service interfaces.

### Why Neo4j (not Elasticsearch) for Asset Graph?

**Trade-off**: Elasticsearch excels at full-text search and time-series data, but Neo4j provides:
- Native graph traversal for relationship queries ("which assets communicate with this C2 domain?")
- MITRE ATT&CK technique linkage via graph edges
- Path analysis for lateral movement detection
- Visual graph exploration in the SOC console

**Decision**: Neo4j for relationship graph, ClickHouse for time-series analytics. Each optimized for its query pattern.

### Why 7 Languages?

| Language | Purpose | Why Not X? |
|----------|---------|------------|
| Go | Core services (API, scoring, correlation) | Performance, concurrency, strong typing |
| TypeScript | SOC console frontend | React ecosystem, type safety |
| Python | CTI, Copilot, testing | ML/AI ecosystem, fast prototyping |
| Rust | IoC extraction | Memory safety, regex performance |
| Julia | Anomaly detection | Numerical computing, statistical libraries |
| Noir | ZK proofs | Domain-specific for zero-knowledge circuits |
| C | eBPF collectors | Kernel-level access, minimal overhead |

**Decision**: Each language used where it has the strongest ecosystem advantage. The monorepo isolates build systems per language.

### Why ZK Proofs for Device Trust?

Traditional device trust relies on centralized CAs or MDM servers. ZK proofs enable:
- **Privacy-preserving attestation** - Device proves compliance without revealing firmware details
- **Decentralized verification** - Any service can verify without calling a central authority
- **Cryptographic guarantees** - Mathematical proof of device state, not trust in a server

## Data Flow

```
Telemetry Source → Connector → Event Normalizer → Redis Stream
                                                    ↓
                              ┌─────────────────────┼─────────────────────┐
                              ↓                     ↓                     ↓
                        Risk Scoring          Correlation          Asset Graph
                        (ClickHouse)          Engine               (Neo4j)
                              ↓                     ↓
                        Asset Trust          Incident Created
                        Scores                    ↓
                              ↓              SOAR Playbook
                              ↓                   ↓
                         SOC Console ←──── Automated Response
```

### Event Processing Pipeline

1. **Ingestion** - Connectors normalize raw events (DDI/WAF/Mail/ZK) into XDR event envelope
2. **Enrichment** - CTI matcher enriches events with threat intelligence IoCs
3. **Risk Scoring** - Trust score computed per-asset based on event frequency, severity, CTI matches
4. **Correlation** - 5 correlation rules detect patterns across event streams
5. **Incident Creation** - Correlated events become incidents with MITRE ATT&CK mapping
6. **Automated Response** - SOAR playbooks execute containment actions with approval workflows

## MITRE ATT&CK Coverage

| Tactic | Technique | Detection Source | Response |
|--------|-----------|-----------------|----------|
| Initial Access | T1566 (Phishing) | Mail Connector | Quarantine email, block sender |
| Initial Access | T1190 (Exploit Public App) | WAF Connector | Rate limit, IP block |
| Credential Access | T1110 (Brute Force) | WAF + Correlation | IP block, account lockout |
| C2 | T1071.004 (DNS) | DDI + Correlation | DNS sinkhole |
| C2 | T1568.002 (DGA) | DDI + Correlation | Block domain family |
| Impact | T1499 (DDoS) | WAF + Correlation | Rate limit, geo-block |
| Persistence | T1547 (Autostart) | ZK Device Trust | Device quarantine |

## Key Metrics

| Metric | Value |
|--------|-------|
| Source Languages | 7 (Go, TypeScript, Python, Rust, Julia, Noir, C) |
| Docker Services | 15+ containers |
| API Endpoints | 20+ REST endpoints |
| Correlation Rules | 5 (credential stuffing, DDoS, phishing, DGA, beaconing) |
| SOAR Playbooks | 5 (quarantine, DNS block, rate limit, DDoS, phishing) |
| Sigma Rules | 5 (T1566, T1110, T1499, T1568, T1071) |
| ZK Circuit Types | 4 (device identity, compliance, attestation, trust score) |
| Test Coverage | 18 Go unit tests + 7 Robot Framework suites |
| CI/CD Jobs | 9 GitHub Actions workflows |

## What I Learned

### Technical
- **Graph databases** (Neo4j) are transformative for security relationship analysis
- **Redis Streams** consumer groups provide excellent at-least-once event processing
- **Noir ZK circuits** require thinking about computation differently - constraints, not instructions
- **eBPF** gives kernel-level visibility without kernel modules, but the learning curve is steep
- **Julia** is genuinely excellent for statistical computing but has a smaller ecosystem

### Architectural
- **Event-driven architecture** naturally decouples services and enables independent scaling
- **Schema-first design** (JSON schemas) prevented integration bugs between 7 language ecosystems
- **Health checks** and **Prometheus metrics** are not optional - they're what makes a multi-service system operable
- **Consumer groups** in Redis solve the "exactly one worker processes each event" problem elegantly

### Product
- **MITRE ATT&CK mapping** forces you to think about detection coverage gaps
- **SOAR playbooks with approval workflows** balance automation with human oversight
- **Trust scores** need to be explainable - "why is this device at 45/100?" matters more than the number

## Future Work

1. **Federated CTI** - Connect multiple organizations' CTI lakehouses with privacy-preserving sharing
2. **ML Anomaly Detection** - Replace Z-score with LSTM autoencoders for sequence anomalies
3. **Rust Reverse Proxy** - Build a high-performance API gateway alternative in Rust
4. **SOAR Marketplace** - Allow analysts to create and share playbook templates
5. **Real-time Graph Updates** - WebSocket-based live graph visualization in the SOC console
