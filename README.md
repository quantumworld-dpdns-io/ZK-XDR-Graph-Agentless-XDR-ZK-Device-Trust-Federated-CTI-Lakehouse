# ZK-XDR-Graph-Agentless-XDR-ZK-Device-Trust-Federated-CTI-Lakehouse
ZK-XDR Graph：Agentless XDR + ZK Device Trust + Federated CTI Lakehouse

一句話：

用 ZK device identity 當 endpoint / IoT / VDI / OT asset 的 trust root，再把 DNS、WAF、Email、AD、CVE、CTI telemetry 匯入 graph + lakehouse，最後由 SOAR copilot 做 triage、correlation、response。

這樣比單純說「我做 EDR」更強，因為你的 repo 組合本質上比較像：

EDR-compatible XDR / MDR platform
+ Agentless asset-risk graph
+ ZK device identity
+ CTI lakehouse
+ SOAR automation
+ DNS/API/Email security telemetry

agentless-security-compliance-graph 的定位已經是 mapping devices、AD accounts、CVEs、policy gaps，而且標明 agentless、eBPF、OTel、DuckDB、LangGraph；這很適合當 asset-risk graph 的核心。
federated-threat-intel-lakehouse 則明確包含 Iceberg/Trino、Vector DB、Redis/cache、MinIO/S3、FastAPI、Next.js、Flower federated learning，適合當 CTI/data plane。
zk-device-identity-saas 已經有 Next.js frontend、Rust Axum proxy、Go Chi backend、Noir ZK circuits、RISC Zero compliance、agent service 等結構，適合升級成 device trust layer。

1. 最終產品架構
┌────────────────────────────────────────────────────────────────────┐
│                        ZK-XDR Graph Platform                       │
├────────────────────────────────────────────────────────────────────┤
│  Console / SOC UI                                                  │
│  ├─ Asset Trust Graph                                               │
│  ├─ Alert Timeline                                                  │
│  ├─ CTI Intel Search                                                │
│  ├─ SOAR Playbook Builder                                           │
│  └─ Evidence / Compliance Reports                                   │
├────────────────────────────────────────────────────────────────────┤
│  Detection / Reasoning Layer                                        │
│  ├─ Correlation Engine                                              │
│  ├─ Risk Scoring Engine                                             │
│  ├─ Sigma / IOC / STIX Enrichment                                   │
│  ├─ LLM / RAG Analyst Copilot                                       │
│  └─ SOAR Decision Engine                                            │
├────────────────────────────────────────────────────────────────────┤
│  Identity + Asset Graph                                             │
│  ├─ ZK Device Identity                                               │
│  ├─ AD / IAM Identity                                                │
│  ├─ DNS / DHCP / IPAM Mapping                                        │
│  ├─ CVE / Exposure Mapping                                           │
│  └─ Device Trust Score                                               │
├────────────────────────────────────────────────────────────────────┤
│  Data Plane                                                         │
│  ├─ Lakehouse: Iceberg / Trino / MinIO                               │
│  ├─ Stream: Kafka / Redis Streams                                    │
│  ├─ Graph DB: Neo4j / ArangoDB / Postgres AGE                        │
│  ├─ Vector DB: Milvus / Chroma                                       │
│  └─ Hot Store: ClickHouse / DuckDB                                   │
├────────────────────────────────────────────────────────────────────┤
│  Collectors / Sensors                                               │
│  ├─ DNS / DHCP / IPAM telemetry                                      │
│  ├─ WAF / API / DDoS logs                                            │
│  ├─ Email / BEC / Quishing events                                    │
│  ├─ AD / Device / CVE / Compliance inventory                         │
│  ├─ ZK device attestation events                                     │
│  └─ CTI feeds / signed reports                                       │
└────────────────────────────────────────────────────────────────────┘
2. 6 個 repo 的角色分工
Repo	新角色	在平台中的位置	建議改名 / 子系統名
zk-device-identity-saas	Device trust root	Identity Layer	zk-device-trust-service
agentless-security-compliance-graph	Asset + identity + CVE graph	Graph Layer	asset-risk-graph
federated-threat-intel-lakehouse	CTI + event lakehouse	Data Plane	cti-lakehouse
api-ddos-mitigation-copilot	WAF/API/DDoS SOAR playbooks	Response Layer	api-defense-soar
ddi-security-graph	DNS/DHCP/IPAM telemetry	Network Identity Layer	ddi-telemetry-connector
quishing-bec-mail-threat-lab	Email threat simulation + triage	Email Security Layer	mail-threat-simulator

api-ddos-mitigation-copilot 的 README 定位是 correlating API abuse、volumetric DDoS、WAF logs 的 AI-assisted runbook engine，適合做 SOAR response 模組。
ddi-security-graph 定位是 DNS/DHCP/IPAM layer，用來偵測 shadow assets、stale DNS、suspicious name-resolution behavior，適合補 XDR 裡常缺的 network identity。
quishing-bec-mail-threat-lab 是 phishing、QR-phishing、BEC simulation 與 security controls correlation，很適合做 email threat simulation + SOC triage。

3. 核心設計：ZK Device Trust 如何接進 XDR

不要把 ZK 做成噱頭。它應該只負責一件事：

證明 device identity / device compliance / manufacturing provenance，而不暴露完整裝置秘密或製造商內部資料。

Device Trust Score

每個 endpoint / IoT / VDI / OT device 都有一個 trust score：

device_trust_score =
  identity_attestation_score
+ certificate_validity_score
+ firmware_integrity_score
+ network_behavior_score
+ vulnerability_exposure_score
+ identity_context_score
- suspicious_activity_penalty
ZK identity event schema
{
  "event_type": "zk.device.attestation.verified",
  "device_id": "dev_01HX...",
  "tenant_id": "tenant_acme",
  "proof_id": "proof_20260706_001",
  "proof_system": "risc0",
  "device_class": "iot_camera",
  "manufacturer": "example-vendor",
  "matter_dac_hash": "sha256:...",
  "pai_hash": "sha256:...",
  "paa_root_hash": "sha256:...",
  "firmware_hash": "sha256:...",
  "attestation_result": "verified",
  "trust_score_delta": 18,
  "timestamp": "2026-07-06T13:00:00Z"
}
XDR correlation example
Case: Suspicious IoT camera beaconing to new domain

1. DDI sees new DNS query:
   device cam-042 -> strange-domain.example

2. Asset graph checks:
   device belongs to Finance floor
   device has no recent ZK attestation
   firmware hash is unknown
   stale DHCP lease observed

3. CTI lakehouse checks:
   domain appears in SME-shared IOC cluster

4. XDR risk engine calculates:
   identity trust low
   DNS behavior suspicious
   firmware provenance unknown
   CTI match positive

5. SOAR action:
   isolate VLAN / push firewall rule / open SOC case / request re-attestation
4. MVP 切法
MVP 0：統一事件格式

先不要急著整合全部 repo。第一步是定義共通 event schema。

建議統一成：

ZK-XDR Event Envelope
{
  "event_id": "evt_01HX...",
  "tenant_id": "tenant_demo",
  "source": "ddi|waf|mail|zk|asset|cti|ad|cve",
  "event_type": "dns.query.suspicious",
  "severity": "medium",
  "asset_id": "asset_123",
  "identity_id": "user_456",
  "device_id": "dev_789",
  "observed_at": "2026-07-06T13:00:00Z",
  "raw": {},
  "normalized": {},
  "risk": {
    "score": 72,
    "factors": ["new_domain", "low_device_trust", "cti_match"]
  },
  "trace": {
    "collector": "ddi-telemetry-connector",
    "pipeline": "kafka.main",
    "schema_version": "xdr-event-v0.1"
  }
}

這一步是整個平台的地基。

MVP 1：Asset Trust Graph

先串三個來源：

zk-device-identity-saas
+ agentless-security-compliance-graph
+ ddi-security-graph

目標：

Device
  ├─ has identity proof
  ├─ has IP
  ├─ has DNS behavior
  ├─ has CVE exposure
  ├─ belongs to user / AD group
  └─ has trust score

Graph schema：

(:Device)-[:HAS_IP]->(:IPAddress)
(:Device)-[:QUERIED]->(:Domain)
(:Device)-[:HAS_CVE]->(:CVE)
(:Device)-[:OWNED_BY]->(:User)
(:User)-[:MEMBER_OF]->(:ADGroup)
(:Device)-[:HAS_ZK_PROOF]->(:ZKProof)
(:Domain)-[:MATCHES_IOC]->(:ThreatIntel)

Demo dashboard 要有 4 個畫面：

Page	功能
Asset Inventory	所有裝置、IP、trust score
Device Detail	ZK proof、DNS、CVE、AD owner
Risk Graph	裝置與 domain、CVE、user 的關聯
Alert Timeline	suspicious DNS / stale DNS / low trust events
MVP 2：CTI Lakehouse + RAG Analyst

加入：

federated-threat-intel-lakehouse

功能：

1. IOC ingestion
2. STIX-like object import
3. Domain/IP/hash reputation lookup
4. Similar incident search
5. LLM analyst summary

CTI object schema：

{
  "indicator_id": "ioc_001",
  "type": "domain",
  "value": "strange-domain.example",
  "confidence": 82,
  "source": "federated_sme_cluster",
  "tlp": "amber",
  "first_seen": "2026-07-01T00:00:00Z",
  "last_seen": "2026-07-06T00:00:00Z",
  "tags": ["quishing", "c2", "iot"],
  "embedding_ref": "vec_001"
}

LLM copilot 不要讓它直接下指令。它只做：

- explain alert
- summarize evidence
- map to MITRE ATT&CK
- recommend playbook
- generate SOC report
MVP 3：SOAR Playbook

加入：

api-ddos-mitigation-copilot
+ quishing-bec-mail-threat-lab

先做 5 個 playbook：

Playbook	Trigger	Action
Suspicious DNS	new domain + CTI match	block domain / create case
Low-trust Device	failed ZK attestation	quarantine VLAN / request re-attestation
API Abuse	WAF anomaly + rate spike	rate-limit / block IP / notify Slack
DDoS	volumetric anomaly	Cloudflare rule / WAF mode / incident ticket
Quishing/BEC	email simulation or report	mailbox search / domain block / awareness report

Playbook DSL：

id: pb_low_trust_device_quarantine
name: Low Trust Device Quarantine
trigger:
  event_type: zk.device.attestation.failed
  risk_score_gte: 75
conditions:
  - asset.criticality in ["high", "critical"]
  - device.type in ["iot", "vdi", "server"]
actions:
  - type: create_case
    queue: soc-l2
  - type: request_reattestation
    target: "{{ device_id }}"
  - type: firewall_tag
    tag: quarantine
approval:
  required: true
  approver_role: soc_manager
5. 推薦技術棧

依你的背景，建議用 Golang + Next.js + Rust optional，不要一開始把技術堆疊炸太大。

Layer	建議
Frontend	Next.js / React / Tailwind / shadcn
API gateway	Go Chi 或 FastAPI
Event stream	Kafka / Redpanda；小型 demo 可用 Redis Streams
Hot analytics	ClickHouse
Local analytic cache	DuckDB
Lakehouse	MinIO + Iceberg + Trino，MVP 可先 MinIO + Parquet
Graph DB	Neo4j 最快展示；正式可研究 ArangoDB / Postgres AGE
Vector DB	Chroma for MVP；Milvus for scale
ZK	RISC Zero / Noir，先 mock proof verification，再替換真 verifier
SOAR engine	Temporal / Windmill / custom YAML runner
Auth	Keycloak / Ory Kratos / Zitadel
Observability	OpenTelemetry + Prometheus + Grafana + Loki
6. Monorepo 建議結構

建議新開一個整合 repo：

zk-xdr-graph-platform/
├── apps/
│   ├── console-web/                 # Next.js SOC console
│   ├── api-gateway/                 # Go/FastAPI API gateway
│   └── analyst-copilot/             # RAG + LLM service
├── services/
│   ├── event-normalizer/
│   ├── asset-risk-graph/
│   ├── zk-device-trust/
│   ├── cti-lakehouse/
│   ├── ddi-connector/
│   ├── waf-api-connector/
│   ├── mail-threat-connector/
│   ├── correlation-engine/
│   └── soar-playbook-engine/
├── schemas/
│   ├── xdr-event.schema.json
│   ├── asset.schema.json
│   ├── zk-proof.schema.json
│   ├── cti.schema.json
│   └── case.schema.json
├── detections/
│   ├── sigma/
│   ├── yara/
│   └── correlation-rules/
├── playbooks/
│   ├── low-trust-device.yml
│   ├── suspicious-dns.yml
│   ├── api-abuse.yml
│   ├── ddos-mitigation.yml
│   └── quishing-response.yml
├── infra/
│   ├── docker-compose.local.yml
│   ├── k8s/
│   └── terraform/
├── examples/
│   ├── demo-events/
│   ├── demo-iocs/
│   └── attack-scenarios/
└── docs/
    ├── architecture.md
    ├── threat-model.md
    ├── data-model.md
    ├── api-spec.md
    ├── soc-runbook.md
    └── resume-case-study.md
7. Demo 場景設計

做一個完整展示比做很多半成品更有價值。

Demo Attack Story
場景：SME 公司部署 IoT camera、VDI、cloud API、email security。

攻擊鏈：
1. 攻擊者寄出 QR phishing email。
2. 使用者掃 QR code 後進入 fake login page。
3. 某台 IoT camera 開始查詢可疑 DNS domain。
4. 同時間 API gateway 出現 credential stuffing。
5. 該 IoT device 的 ZK attestation 過期。
6. CTI lakehouse 發現該 domain 與近期 SME cluster IOC 相似。
7. XDR correlation engine 建立 high-risk incident。
8. SOAR 建議隔離 device、封鎖 domain、啟用 WAF rule、通知 SOC。
最後 dashboard 要顯示
Incident: Coordinated Quishing + IoT Beaconing + API Abuse

Risk score: 91 / 100

Evidence:
- QR phishing simulation triggered
- DNS query to suspicious domain
- Device ZK attestation expired
- CTI match confidence 82%
- API abuse from related ASN
- Asset belongs to Finance network segment

Recommended actions:
- Block domain
- Quarantine IoT device
- Rotate affected account credentials
- Enable WAF rate limit
- Open L2 SOC case
8. 開發 Roadmap
Phase 1：2 週，可展示骨架

目標：讓人看得懂你在做什麼。

- 建 monorepo
- 定義 xdr-event schema
- 寫 3 個 fake collectors：
  - zk attestation event generator
  - dns event generator
  - waf event generator
- 建 Next.js dashboard
- 建 asset graph mock API
- 做 incident timeline

產出：

- README
- architecture diagram
- docker-compose
- demo screenshots
- 1 條完整 demo incident
Phase 2：4 週，做出可跑 MVP

目標：真的可以 ingest、correlate、score。

- Redis Streams / Kafka event bus
- event-normalizer service
- Neo4j graph model
- ClickHouse event table
- MinIO parquet archive
- risk scoring engine
- 3 條 correlation rules
- 3 條 SOAR playbooks

MVP rules：

Rule 1:
low device trust + suspicious DNS = high-risk endpoint case

Rule 2:
quishing event + new login location = identity compromise case

Rule 3:
WAF anomaly + CTI IP match = API abuse case
Phase 3：8 週，變成履歷級專案

目標：像真產品。

- ZK proof verifier interface
- CTI RAG search
- Sigma-like detection import
- STIX/TAXII-like IOC import/export
- SOAR approval workflow
- Slack / Gmail / webhook integration
- multi-tenant RBAC
- audit log / evidence chain
- SOC report generator

產出：

- technical whitepaper
- demo video
- threat model
- system design document
- API docs
- sample SOC report
- performance benchmark
9. 優先級排序
必做
1. Unified XDR event schema
2. Asset/device graph
3. ZK device trust score
4. DNS + WAF + Mail sample telemetry
5. Correlation engine
6. SOAR playbook engine
7. Dashboard
後做
1. 真正 federated learning
2. 真正 ZK production proof
3. Iceberg/Trino full lakehouse
4. Quantum module
5. 完整 MDR multi-tenant billing
暫時不要做
1. Kernel-level EDR driver
2. 真實 malware analysis sandbox
3. 自動 offensive exploitation
4. 太複雜的 blockchain tokenization
5. 過度依賴 LLM 自動封鎖

原因很簡單：你現在最該做的是 XDR/SOC platform integration story，不是把每個 buzzword 都實作到底。

10. 可寫在履歷上的版本
中文版
設計並實作 ZK-XDR Graph，一套結合零知識裝置身分、agentless asset graph、DNS/WAF/Email telemetry、CTI lakehouse 與 SOAR playbook 的 XDR/SOC 自動化平台。系統以 Go/Next.js/Redis Streams/Neo4j/ClickHouse/MinIO 建構事件匯流與風險關聯管線，將 IoT/endpoint 身分證明、DNS 行為、API abuse、quishing/BEC 模擬與威脅情資整合成可視化 incident timeline，支援自動化 triage、risk scoring、playbook 建議與 evidence chain。
English version
Designed and implemented ZK-XDR Graph, an XDR/SOC automation platform integrating zero-knowledge device identity, agentless asset-risk graphing, DNS/WAF/email telemetry, CTI lakehouse enrichment, and SOAR playbooks. Built an event-driven pipeline with Go, Next.js, Redis Streams, Neo4j, ClickHouse, and MinIO to correlate IoT/endpoint attestation, DNS behavior, API abuse, quishing/BEC simulations, and threat intelligence into incident timelines with risk scoring, analyst triage, response recommendations, and evidence tracking.
11. 最佳 repo strategy

我不建議把 6 個 repo 直接硬 merge。建議做：

zk-xdr-graph-platform       # 新主 repo，展示整合產品
├── imports from:
│   ├── zk-device-identity-saas
│   ├── agentless-security-compliance-graph
│   ├── federated-threat-intel-lakehouse
│   ├── api-ddos-mitigation-copilot
│   ├── ddi-security-graph
│   └── quishing-bec-mail-threat-lab

然後原本 6 個 repo 的 README 加上：

This module is part of the ZK-XDR Graph Platform.

這樣履歷、GitHub、面試講述會比較集中，不會讓 reviewer 覺得是很多發散 repo。

12. 最小可行實作順序

最推薦的第一版順序：

Day 1-2:
  建 monorepo + docker-compose + schema

Day 3-5:
  event generator:
    - zk attestation
    - dns query
    - waf anomaly
    - phishing simulation

Day 6-8:
  event normalizer + Redis Streams

Day 9-12:
  graph model + risk scoring

Day 13-15:
  dashboard:
    - asset list
    - incident timeline
    - graph view
    - playbook recommendation

Day 16-20:
  CTI enrichment + RAG summary

Day 21-28:
  polish README, diagrams, demo video, benchmark, resume case study
結論

這個組合最有價值的地方是：

ZK device identity
不是單獨賣點；
它是 XDR 裡的 device trust root。

Agentless graph
不是單獨 dashboard；
它是 SOC correlation 的 context layer。

CTI lakehouse
不是資料倉儲；
它是 alert enrichment 和 MDR 知識層。

SOAR copilot
不是 chatbot；
它是 analyst decision support + controlled response engine。

最後產品定位可以定成：

ZK-XDR Graph: an agentless, identity-aware XDR platform for IoT, SME, and hybrid-cloud SOC operations.

---

建議 Tech Stack 摘要
Layer	建議
Web Console	Next.js + React + TypeScript + Tailwind + shadcn/ui
API Gateway	Go + Chi/Fiber + OpenAPI
Worker / Collector	Go
Analyst Copilot / RAG	Python + FastAPI + LlamaIndex/LangChain
Event Stream	Redis Streams first；之後可升 Redpanda/Kafka
Relational DB	PostgreSQL
Graph DB	Neo4j
Hot Analytics	ClickHouse
Object Storage	MinIO
Vector DB	Qdrant / Chroma
Cache / Queue	Redis
Observability	OpenTelemetry + Prometheus + Grafana + Loki
Security Scan	Semgrep + Trivy + Syft + Grype
Dockerfile 限制設計

README 內已固定成 最多 4 個 custom Dockerfiles：

docker/Dockerfile.web       # Next.js SOC console
docker/Dockerfile.api       # Go API gateway
docker/Dockerfile.worker    # Go collectors / normalizer / correlation / SOAR worker
docker/Dockerfile.ai        # Python analyst copilot / RAG service

其他全部用官方 image，不再寫 Dockerfile：

postgres
redis
neo4j
clickhouse
minio
qdrant
redpanda/kafka
grafana
prometheus
loki
keycloak

這個切法最適合後續生成 repo，因為架構清楚、面試好講，也不會變成 Dockerfile 地獄。


---
# ZK-XDR Graph Platform

> Agentless XDR + ZK Device Trust + Federated CTI Lakehouse + SOAR Playbooks

`ZK-XDR Graph` is an identity-aware XDR/SOC automation platform that combines zero-knowledge device identity, agentless asset-risk graphing, DNS/WAF/email telemetry, CTI lakehouse enrichment, and SOAR playbooks into a unified incident investigation workflow.

The goal is not to replace a full kernel-level EDR agent. The goal is to provide an **EDR-compatible XDR context layer** that helps SOC/MDR teams correlate endpoint, IoT, identity, network, API, email, vulnerability, and threat-intelligence signals.

---

## 1. Product Thesis

Modern SOC teams usually have too many alerts and not enough trustworthy asset context. A suspicious DNS query, WAF anomaly, phishing report, stale certificate, or vulnerable IoT camera is often investigated in isolation.

`ZK-XDR Graph` treats **device trust** as a first-class security primitive.

Instead of asking only:

```text
What happened?
```

The platform asks:

```text
Which asset did it happen on?
Is that asset trusted?
Can its identity be verified?
What user, IP, DNS behavior, CVE exposure, and CTI context are connected to it?
What response action is safe and auditable?
```

---

## 2. Core Concept

```text
ZK Device Identity
  -> Asset Trust Graph
  -> Telemetry Correlation
  -> CTI Enrichment
  -> Risk Scoring
  -> SOAR Recommendation
  -> Evidence Chain
```

### Key Capabilities

- Zero-knowledge device identity and compliance proof verification
- Agentless device, user, AD/IAM, CVE, DNS, DHCP, and IPAM mapping
- DNS / DHCP / IPAM telemetry analysis
- WAF / API / DDoS log correlation
- Email / BEC / quishing simulation and triage
- Federated CTI ingestion and enrichment
- XDR event normalization
- Asset-risk graph visualization
- SOAR playbook recommendation and approval workflow
- SOC analyst copilot for explanation, summarization, and report generation

---

## 3. Integrated Modules

This platform is designed as a productized integration layer for the following module families:

| Module | Platform Role | Description |
|---|---|---|
| `zk-device-identity-saas` | Device Trust Root | Verifies endpoint, IoT, Matter, or OT device identity using ZK proof and attestation metadata. |
| `agentless-security-compliance-graph` | Asset-Risk Graph | Maps devices, users, AD groups, CVEs, policy gaps, and compliance signals. |
| `federated-threat-intel-lakehouse` | CTI + Event Lakehouse | Stores IOC, telemetry, incident history, vector embeddings, and long-term evidence. |
| `api-ddos-mitigation-copilot` | API/WAF SOAR | Correlates API abuse, DDoS behavior, WAF events, and response actions. |
| `ddi-security-graph` | Network Identity | Ingests DNS, DHCP, and IPAM telemetry to detect shadow assets and suspicious name resolution. |
| `quishing-bec-mail-threat-lab` | Email Threat Layer | Generates and analyzes phishing, QR phishing, BEC, and awareness telemetry. |

---

## 4. High-Level Architecture

```text
┌────────────────────────────────────────────────────────────────────┐
│                         SOC Console / Web UI                        │
│  Asset Inventory | Incident Timeline | Graph View | CTI Search      │
│  SOAR Playbooks | Evidence Chain | Analyst Copilot                 │
└────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌────────────────────────────────────────────────────────────────────┐
│                            API Gateway                              │
│  Auth | RBAC | Tenant Routing | REST API | WebSocket | Audit Logs   │
└────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌────────────────────────────────────────────────────────────────────┐
│                    Detection / Reasoning Layer                      │
│  Correlation Engine | Risk Scoring | CTI Enrichment | RAG Copilot   │
│  Sigma-like Rules | SOAR Recommendation | Case Management          │
└────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌────────────────────────────────────────────────────────────────────┐
│                     Identity + Asset Graph Layer                    │
│  Device | User | AD Group | IP | Domain | CVE | ZK Proof | IOC      │
└────────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌────────────────────────────────────────────────────────────────────┐
│                             Data Plane                              │
│  Redis Streams / Kafka | ClickHouse | Neo4j | MinIO | Vector DB     │
└────────────────────────────────────────────────────────────────────┘
                                  ▲
                                  │
┌────────────────────────────────────────────────────────────────────┐
│                       Collectors / Connectors                       │
│  ZK Attestation | DNS/DHCP/IPAM | WAF/API | Email | AD | CVE | CTI  │
└────────────────────────────────────────────────────────────────────┘
```

---

## 5. Suggested Tech Stack

The stack is optimized for a serious portfolio-grade MVP while keeping deployment complexity controlled.

### Application Layer

| Layer | Recommended Stack | Reason |
|---|---|---|
| Web Console | Next.js, React, TypeScript, Tailwind CSS, shadcn/ui | Fast SOC dashboard development with strong UI ecosystem. |
| Graph Visualization | React Flow, Cytoscape.js, or Sigma.js | Asset graph, attack path, device-domain-user-CVE relation view. |
| API Gateway | Go, Chi/Fiber, OpenAPI | Good fit for security backend, event APIs, RBAC, and high-throughput services. |
| Worker Services | Go | Collectors, normalizers, correlation, scoring, and playbook execution. |
| AI/Copilot Service | Python, FastAPI, LlamaIndex or LangChain | RAG, CTI summarization, analyst report generation. |
| ZK Verification | RISC Zero / Noir / mock verifier first | Start with verifier interface; replace mock with real proof verifier later. |

### Data Plane

| Purpose | Recommended Stack | MVP Choice |
|---|---|---|
| Event Stream | Redis Streams or Redpanda/Kafka | Redis Streams first; Redpanda/Kafka later. |
| Relational Store | PostgreSQL | Tenants, users, cases, playbooks, audit logs. |
| Graph Store | Neo4j | Fastest path for graph demo and Cypher queries. |
| Hot Analytics | ClickHouse | High-volume security events and timeline queries. |
| Object Store | MinIO | Raw logs, Parquet, CTI bundles, evidence files. |
| Vector Store | Qdrant or Chroma | CTI RAG and similar incident search. |
| Cache | Redis | Session cache, queues, rate limits, stream buffer. |

### Security / SOC Standards

| Area | Recommended Format / Tool |
|---|---|
| Event Normalization | Elastic Common Schema inspired schema, custom XDR event envelope |
| SIEM Export | JSONL, CEF, LEEF, ECS-compatible JSON |
| Detection Rules | Sigma-like YAML rules |
| Malware / Hash IOC | STIX-like objects, YARA-compatible metadata |
| CTI Sharing | STIX/TAXII-compatible export, signed threat reports |
| SBOM | Syft |
| Vulnerability Scan | Grype, Trivy |
| SAST | Semgrep |
| Observability | OpenTelemetry, Prometheus, Grafana, Loki |
| Auth / IAM | Keycloak for enterprise mode; simple JWT for MVP |

---

## 6. Dockerfile Constraint

This project intentionally uses **no more than 4 custom Dockerfiles**.

### Custom Dockerfiles

```text
docker/Dockerfile.web       # Next.js SOC console
docker/Dockerfile.api       # Go API gateway
docker/Dockerfile.worker    # Go collectors, normalizer, correlation, SOAR worker
docker/Dockerfile.ai        # Python FastAPI analyst copilot / RAG service
```

### Official Images Only

The following services should use official or trusted upstream images directly in `docker-compose.local.yml`:

```text
postgres
redis
neo4j
clickhouse
minio
qdrant
redpanda or kafka
grafana
prometheus
loki
keycloak
```

Do **not** create extra Dockerfiles for databases, queues, observability tools, or object storage.

---

## 7. Repository Layout

```text
zk-xdr-graph-platform/
├── apps/
│   ├── console-web/                    # Next.js SOC console
│   ├── api-gateway/                    # Go API gateway
│   └── analyst-copilot/                # Python RAG / LLM service
│
├── services/
│   ├── event-normalizer/               # Normalize telemetry into XDR event schema
│   ├── asset-risk-graph/               # Asset graph writer and query service
│   ├── zk-device-trust/                # ZK attestation verifier interface
│   ├── cti-lakehouse/                  # IOC ingestion and enrichment
│   ├── ddi-connector/                  # DNS/DHCP/IPAM telemetry connector
│   ├── waf-api-connector/              # WAF/API/DDoS connector
│   ├── mail-threat-connector/          # Quishing/BEC/email telemetry connector
│   ├── correlation-engine/             # Multi-signal alert correlation
│   └── soar-playbook-engine/           # Playbook runner and approval workflow
│
├── schemas/
│   ├── xdr-event.schema.json
│   ├── asset.schema.json
│   ├── zk-proof.schema.json
│   ├── cti-indicator.schema.json
│   ├── incident.schema.json
│   └── playbook.schema.json
│
├── detections/
│   ├── sigma/
│   ├── yara/
│   └── correlation-rules/
│
├── playbooks/
│   ├── low-trust-device-quarantine.yml
│   ├── suspicious-dns-response.yml
│   ├── api-abuse-rate-limit.yml
│   ├── ddos-mitigation.yml
│   └── quishing-bec-response.yml
│
├── examples/
│   ├── demo-events/
│   ├── demo-iocs/
│   ├── demo-assets/
│   └── attack-scenarios/
│
├── infra/
│   ├── docker-compose.local.yml
│   ├── docker-compose.observability.yml
│   ├── k8s/
│   └── terraform/
│
├── docker/
│   ├── Dockerfile.web
│   ├── Dockerfile.api
│   ├── Dockerfile.worker
│   └── Dockerfile.ai
│
├── docs/
│   ├── architecture.md
│   ├── threat-model.md
│   ├── data-model.md
│   ├── api-spec.md
│   ├── soc-runbook.md
│   └── resume-case-study.md
│
├── .github/
│   └── workflows/
│       ├── ci.yml
│       ├── security-scan.yml
│       └── docker-build.yml
│
├── Makefile
├── README.md
└── LICENSE
```

---

## 8. XDR Event Envelope

All telemetry should be normalized into a shared event envelope before detection and correlation.

```json
{
  "event_id": "evt_01HX0000000000000000000000",
  "tenant_id": "tenant_demo",
  "source": "ddi",
  "event_type": "dns.query.suspicious",
  "severity": "medium",
  "asset_id": "asset_iot_camera_042",
  "device_id": "dev_iot_camera_042",
  "identity_id": "user_finance_001",
  "observed_at": "2026-07-06T13:00:00Z",
  "raw": {
    "query": "strange-domain.example",
    "src_ip": "10.10.20.42"
  },
  "normalized": {
    "domain": "strange-domain.example",
    "src_ip": "10.10.20.42",
    "network_segment": "finance-iot"
  },
  "risk": {
    "score": 72,
    "factors": [
      "new_domain",
      "low_device_trust",
      "cti_match"
    ]
  },
  "trace": {
    "collector": "ddi-connector",
    "pipeline": "redis-streams:xdr.events",
    "schema_version": "xdr-event-v0.1"
  }
}
```

---

## 9. Asset Graph Model

Recommended initial graph model:

```cypher
(:Device)-[:HAS_IP]->(:IPAddress)
(:Device)-[:QUERIED]->(:Domain)
(:Device)-[:HAS_CVE]->(:CVE)
(:Device)-[:OWNED_BY]->(:User)
(:User)-[:MEMBER_OF]->(:ADGroup)
(:Device)-[:HAS_ZK_PROOF]->(:ZKProof)
(:Domain)-[:MATCHES_IOC]->(:ThreatIntel)
(:Device)-[:GENERATED]->(:SecurityEvent)
(:SecurityEvent)-[:PART_OF]->(:Incident)
(:Incident)-[:TRIGGERED]->(:Playbook)
```

Example query:

```cypher
MATCH (d:Device)-[:QUERIED]->(domain:Domain)-[:MATCHES_IOC]->(ioc:ThreatIntel)
WHERE d.trust_score < 60
RETURN d.device_id, d.hostname, d.trust_score, domain.name, ioc.confidence
ORDER BY ioc.confidence DESC;
```

---

## 10. Device Trust Score

A device trust score should not be a vague AI score. It should be explainable.

```text
device_trust_score =
  identity_attestation_score
+ certificate_validity_score
+ firmware_integrity_score
+ network_behavior_score
+ vulnerability_exposure_score
+ identity_context_score
- suspicious_activity_penalty
```

Example factors:

| Factor | Signal |
|---|---|
| Identity Attestation | ZK proof verified or failed |
| Certificate Validity | Matter DAC / PAI / PAA chain status |
| Firmware Integrity | Firmware hash known or unknown |
| Network Behavior | New domain, rare ASN, unusual DNS query pattern |
| Vulnerability Exposure | CVE severity and exploitability |
| Identity Context | Owner, AD group, privilege level |
| Suspicious Penalty | CTI hit, phishing link, WAF anomaly, stale DHCP lease |

---

## 11. SOAR Playbook Example

```yaml
id: pb_low_trust_device_quarantine
name: Low Trust Device Quarantine
version: 0.1.0
trigger:
  event_type: zk.device.attestation.failed
  risk_score_gte: 75
conditions:
  - field: asset.criticality
    operator: in
    value: ["high", "critical"]
  - field: device.type
    operator: in
    value: ["iot", "vdi", "server"]
actions:
  - type: create_case
    queue: soc-l2
    title: "Low-trust device requires investigation"
  - type: request_reattestation
    target: "{{ device_id }}"
  - type: firewall_tag
    tag: quarantine
approval:
  required: true
  approver_role: soc_manager
```

---

## 12. Demo Scenario

### Scenario Name

```text
Coordinated Quishing + IoT Beaconing + API Abuse
```

### Attack Story

1. A user scans a QR phishing email.
2. The phishing domain is later observed in DNS telemetry.
3. An IoT camera in the finance network starts querying a suspicious domain.
4. The same environment shows API credential stuffing attempts at the WAF layer.
5. The IoT camera has an expired ZK attestation.
6. CTI lakehouse enrichment finds a related IOC cluster.
7. The correlation engine creates a high-risk incident.
8. The SOAR engine recommends quarantine, domain block, WAF rate limit, and credential rotation.

### Expected Incident Output

```text
Incident: Coordinated Quishing + IoT Beaconing + API Abuse
Risk Score: 91 / 100

Evidence:
- QR phishing simulation triggered
- DNS query to suspicious domain
- Device ZK attestation expired
- CTI match confidence: 82%
- API abuse from related ASN
- Asset belongs to finance network segment

Recommended Actions:
- Block suspicious domain
- Quarantine IoT device
- Rotate affected credentials
- Enable WAF rate limit
- Open SOC L2 case
```

---

## 13. Local Development

### Requirements

```text
Docker
Docker Compose
Node.js LTS
Go stable release
Python stable release
Make
```

### Start Local Stack

```bash
make up
```

Equivalent command:

```bash
docker compose -f infra/docker-compose.local.yml up --build
```

### Seed Demo Data

```bash
make seed-demo
```

### Generate Demo Incident

```bash
make demo-attack
```

### Stop Local Stack

```bash
make down
```

---

## 14. Proposed Services

| Service | Port | Description |
|---|---:|---|
| `console-web` | `3000` | SOC dashboard |
| `api-gateway` | `8080` | Main API and auth gateway |
| `analyst-copilot` | `8090` | RAG and LLM analyst service |
| `event-normalizer` | internal | Normalizes raw telemetry |
| `correlation-engine` | internal | Creates incidents from correlated events |
| `soar-playbook-engine` | internal | Runs playbooks with approval guardrails |
| `postgres` | `5432` | Cases, tenants, playbooks, audit logs |
| `redis` | `6379` | Streams, queue, cache |
| `neo4j` | `7474/7687` | Asset graph |
| `clickhouse` | `8123/9000` | Hot event analytics |
| `minio` | `9000/9001` | Raw log and evidence storage |
| `qdrant` | `6333` | Vector search for CTI and incident memory |

---

## 15. API Surface

Initial API design:

```text
GET    /healthz
GET    /api/v1/assets
GET    /api/v1/assets/{asset_id}
GET    /api/v1/devices/{device_id}/trust
POST   /api/v1/events/ingest
GET    /api/v1/incidents
GET    /api/v1/incidents/{incident_id}
POST   /api/v1/incidents/{incident_id}/assign
POST   /api/v1/incidents/{incident_id}/close
GET    /api/v1/cti/indicators
POST   /api/v1/cti/lookup
GET    /api/v1/playbooks
POST   /api/v1/playbooks/{playbook_id}/dry-run
POST   /api/v1/playbooks/{playbook_id}/execute
POST   /api/v1/copilot/summarize-incident
POST   /api/v1/copilot/recommend-playbook
```

---

## 16. Detection Rules

Example correlation rule:

```yaml
id: rule_low_trust_device_suspicious_dns
name: Low Trust Device With Suspicious DNS
severity: high
window: 15m
conditions:
  all:
    - event_type: dns.query.suspicious
    - device.trust_score_lt: 60
    - cti.domain_match: true
output:
  incident_type: suspicious_iot_beaconing
  risk_score: 88
  recommended_playbook: pb_low_trust_device_quarantine
```

---

## 17. Development Roadmap

### Phase 1: Skeleton Demo

- Create monorepo structure
- Implement shared XDR event schema
- Build fake event generators
- Build Next.js dashboard shell
- Implement API gateway health and event ingestion endpoints
- Show one incident timeline from seeded data

### Phase 2: Working MVP

- Redis Streams event bus
- Event normalizer
- Neo4j asset graph writer
- ClickHouse event table
- Basic risk scoring
- Three correlation rules
- Three SOAR playbooks
- CTI lookup using Qdrant or local vector store

### Phase 3: Portfolio-Grade Platform

- ZK verifier interface
- CTI RAG analyst copilot
- STIX/TAXII-compatible import/export
- Sigma-like rule import
- SOAR approval workflow
- Slack/webhook integration
- Evidence chain and audit log
- Multi-tenant RBAC
- Demo video, architecture docs, and technical whitepaper

---

## 18. Security Guardrails

The platform should avoid unsafe automation patterns.

Recommended guardrails:

- LLM cannot directly execute destructive actions.
- Quarantine, block, and credential-reset playbooks require approval by default.
- Every playbook execution must create an audit log.
- Raw evidence must be stored immutably or append-only where possible.
- CTI confidence should be visible and explainable.
- Risk scoring must expose contributing factors.
- All integrations should support dry-run mode.

---

## 19. What This Project Is Not

This project is not:

- A kernel-level EDR driver
- A malware detonation sandbox
- An offensive exploitation framework
- A fully managed MDR service out of the box
- A blockchain-first security product
- An LLM-only SOC assistant

This project is:

- An XDR context and correlation layer
- A ZK-backed device trust platform
- An agentless asset-risk graph
- A SOC automation and triage system
- A portfolio-grade security architecture project

---

## 20. Resume Summary

### English

Designed and implemented `ZK-XDR Graph`, an XDR/SOC automation platform integrating zero-knowledge device identity, agentless asset-risk graphing, DNS/WAF/email telemetry, CTI lakehouse enrichment, and SOAR playbooks. Built an event-driven architecture with Go, Next.js, Redis Streams, Neo4j, ClickHouse, MinIO, and Python-based RAG services to correlate IoT/endpoint attestation, DNS behavior, API abuse, quishing/BEC events, and threat intelligence into risk-scored incident timelines with analyst recommendations and evidence tracking.

### 中文

設計並實作 `ZK-XDR Graph`，一套結合零知識裝置身分、agentless asset-risk graph、DNS/WAF/Email telemetry、CTI lakehouse 與 SOAR playbook 的 XDR/SOC 自動化平台。系統以 Go、Next.js、Redis Streams、Neo4j、ClickHouse、MinIO 與 Python RAG service 建構事件驅動管線，將 IoT/endpoint attestation、DNS 行為、API abuse、quishing/BEC 事件與威脅情資整合為具備 risk score、incident timeline、analyst recommendation 與 evidence tracking 的安全營運平台。

---

## 21. License

Recommended license for portfolio and open-source collaboration:

```text
Apache-2.0
```

If the project later includes commercial SOC/MDR components, consider dual licensing.

---

## 22. Maintainer Notes

Recommended first milestone:

```text
Milestone 0.1.0: Demo-Driven MVP

Deliverables:
- Docker Compose local stack
- 4 custom Dockerfiles only
- Seeded demo attack scenario
- Asset graph page
- Incident timeline page
- Device trust score page
- SOAR recommendation page
- README screenshots
- 3-minute demo video
```

