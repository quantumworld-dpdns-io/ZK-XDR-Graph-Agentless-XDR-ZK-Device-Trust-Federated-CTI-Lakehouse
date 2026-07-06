-- XDR Events table in ClickHouse
-- Optimized for time-series queries, aggregation, and threat hunting

CREATE TABLE IF NOT EXISTS xdr_events
(
    -- Core fields
    event_id        String,
    tenant_id       LowCardinality(String),
    timestamp       DateTime64(3, 'UTC'),
    received_at     DateTime64(3, 'UTC') DEFAULT now64(3, 'UTC'),

    -- Source identification
    source          LowCardinality(String),  -- ddi, waf, mail, zk, endpoint, connector
    event_type      String,                   -- dns.query.suspicious, waf.anomaly.detected, etc.
    category        LowCardinality(String),   -- network, endpoint, identity, email, cloud

    -- Severity and classification
    severity        Enum8('info' = 0, 'low' = 1, 'medium' = 2, 'high' = 3, 'critical' = 4),
    confidence      UInt8,                    -- 0-100 confidence score
    risk_score      UInt16,                   -- 0-1000 computed risk score

    -- MITRE ATT&CK mapping
    mitre_tactic    LowCardinality(String),   -- initial-access, execution, persistence, etc.
    mitre_technique LowCardinality(String),   -- T1078, T1190, T1566, etc.
    mitre_subtechnique LowCardinality(Nullable(String)),

    -- Asset context
    asset_id        Nullable(String),
    asset_name      Nullable(String),
    asset_type      LowCardinality(Nullable(String)),
    network_segment LowCardinality(Nullable(String)),

    -- Actor / identity
    source_ip       Nullable(IPv4),
    source_port     Nullable(UInt16),
    dest_ip         Nullable(IPv4),
    dest_port       Nullable(UInt16),
    user_agent      Nullable(String),
    username        Nullable(String),

    -- Indicators
    domain          Nullable(String),
    url             Nullable(String),
    file_hash       Nullable(String),
    process_name    Nullable(String),

    -- Raw event data (JSON blob)
    raw_event       String,                   -- original normalized event JSON

    -- Enrichment
    geo_country     LowCardinality(Nullable(String)),
    geo_city        Nullable(String),
    asn             Nullable(UInt32),
    is_internal     Bool DEFAULT false,

    -- Computed fields
    hour_of_day     UInt8 DEFAULT toHour(timestamp),
    day_of_week     UInt8 DEFAULT toDayOfWeek(timestamp),

    -- TTL and partitioning
    ttl_days        UInt16 DEFAULT 90
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (tenant_id, source, severity, timestamp, event_id)
TTL timestamp + toIntervalDay(ttl_days)
SETTINGS index_granularity = 8192;

-- Materialized view for incident correlation (aggregates by asset + time window)
CREATE TABLE IF NOT EXISTS xdr_event_agg
(
    tenant_id       LowCardinality(String),
    asset_id        String,
    time_window     DateTime,               -- rounded to 5-minute intervals
    event_count     UInt32,
    max_severity    Enum8('info' = 0, 'low' = 1, 'medium' = 2, 'high' = 3, 'critical' = 4),
    avg_risk_score  Float32,
    unique_sources  UInt8,
    unique_types    UInt8,
    has_critical    Bool,
    first_seen      DateTime,
    last_seen       DateTime
)
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(time_window)
ORDER BY (tenant_id, asset_id, time_window);

-- Incident events table
CREATE TABLE IF NOT EXISTS xdr_incidents
(
    incident_id     String,
    tenant_id       LowCardinality(String),
    title           String,
    description     String,
    incident_type   LowCardinality(String),
    severity        Enum8('low' = 1, 'medium' = 2, 'high' = 3, 'critical' = 4),
    status          Enum8('open' = 0, 'investigating' = 1, 'contained' = 2, 'resolved' = 3, 'false_positive' = 4),
    risk_score      UInt16,
    asset_id        Nullable(String),
    asset_name      Nullable(String),
    created_at      DateTime64(3, 'UTC'),
    updated_at      DateTime64(3, 'UTC'),
    resolved_at     Nullable(DateTime64(3, 'UTC')),
    assigned_to     Nullable(String),
    evidence_ids    Array(String),
    mitre_tactic    LowCardinality(String),
    mitre_technique LowCardinality(String),
    tags            Array(String)
)
ENGINE = ReplacingMergeTree(updated_at)
PARTITION BY toYYYYMM(created_at)
ORDER BY (tenant_id, incident_id);

-- Asset trust scores (updated by risk scoring service)
CREATE TABLE IF NOT EXISTS xdr_asset_trust
(
    tenant_id       LowCardinality(String),
    asset_id        String,
    asset_name      String,
    asset_type      LowCardinality(String),
    network_segment LowCardinality(String),
    trust_score     UInt16,                 -- 0-100
    risk_factors    String,                 -- JSON: { zk_attestation: 80, vuln_count: 3, ... }
    criticality     LowCardinality(String),
    status          LowCardinality(String),
    last_event_at   DateTime64(3, 'UTC'),
    updated_at      DateTime64(3, 'UTC')
)
ENGINE = ReplacingMergeTree(updated_at)
PARTITION BY (tenant_id, asset_type)
ORDER BY (tenant_id, asset_id);

-- CTI IoC match results
CREATE TABLE IF NOT EXISTS xdr_cti_matches
(
    match_id        String,
    tenant_id       LowCardinality(String),
    event_id        String,
    indicator_id    String,
    indicator_type  LowCardinality(String),
    indicator_value String,
    confidence      UInt8,
    tlp             LowCardinality(String),
    source          LowCardinality(String),
    matched_at      DateTime64(3, 'UTC'),
    verified        Bool DEFAULT false
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(matched_at)
ORDER BY (tenant_id, indicator_id, matched_at);
