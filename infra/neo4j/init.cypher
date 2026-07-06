// Neo4j schema initialization for ZK-XDR Graph Asset Risk Graph
// Run this after Neo4j starts for the first time

// Unique constraints
CREATE CONSTRAINT asset_id_unique IF NOT EXISTS
FOR (a:Asset) REQUIRE (a.id, a.tenant_id) IS UNIQUE;

CREATE CONSTRAINT ip_address_unique IF NOT EXISTS
FOR (ip:IPAddress) REQUIRE ip.address IS UNIQUE;

CREATE CONSTRAINT domain_name_unique IF NOT EXISTS
FOR (d:Domain) REQUIRE d.name IS UNIQUE;

CREATE CONSTRAINT mitre_technique_unique IF NOT EXISTS
FOR (t:MITRETechnique) REQUIRE t.id IS UNIQUE;

CREATE CONSTRAINT event_id_unique IF NOT EXISTS
FOR (e:Event) REQUIRE e.id IS UNIQUE;

CREATE CONSTRAINT cti_indicator_unique IF NOT EXISTS
FOR (ioc:CTIIndicator) REQUIRE (ioc.type, ioc.value) IS UNIQUE;

// Indexes for search performance
CREATE INDEX asset_name_index IF NOT EXISTS
FOR (a:Asset) ON (a.name);

CREATE INDEX asset_type_index IF NOT EXISTS
FOR (a:Asset) ON (a.type);

CREATE INDEX asset_trust_score_index IF NOT EXISTS
FOR (a:Asset) ON (a.trust_score);

CREATE INDEX event_severity_index IF NOT EXISTS
FOR (e:Event) ON (e.severity);

CREATE INDEX event_timestamp_index IF NOT EXISTS
FOR (e:Event) ON (e.timestamp);

CREATE INDEX event_source_index IF NOT EXISTS
FOR (e:Event) ON (e.source);

CREATE INDEX ip_last_seen_index IF NOT EXISTS
FOR (ip:IPAddress) ON (ip.last_seen);

CREATE INDEX domain_last_seen_index IF NOT EXISTS
FOR (d:Domain) ON (d.last_seen);

// Full-text search indexes
CREATE FULLTEXT INDEX asset_search IF NOT EXISTS
FOR (a:Asset) ON EACH [a.name, a.type];

CREATE FULLTEXT INDEX event_search IF NOT EXISTS
FOR (e:Event) ON EACH [e.type, e.source, e.severity];

// Relationship indexes
CREATE INDEX connected_from_index IF NOT EXISTS
FOR ()-[r:CONNECTED_FROM]-() ON (r.first_seen);

CREATE INDEX has_event_index IF NOT EXISTS
FOR ()-[r:HAS_EVENT]-() ON (r.timestamp);

// Sample data for development
MERGE (a1:Asset {id: 'asset_001', tenant_id: 't1'})
SET a1.name = 'IoT Camera 042',
    a1.type = 'iot',
    a1.trust_score = 45,
    a1.criticality = 'high',
    a1.status = 'quarantined',
    a1.network_segment = 'finance-iot',
    a1.created_at = datetime(),
    a1.updated_at = datetime();

MERGE (a2:Asset {id: 'asset_002', tenant_id: 't1'})
SET a2.name = 'Workstation 003',
    a2.type = 'endpoint',
    a2.trust_score = 72,
    a2.criticality = 'critical',
    a2.status = 'active',
    a2.network_segment = 'finance',
    a2.created_at = datetime(),
    a2.updated_at = datetime();

MERGE (a3:Asset {id: 'asset_003', tenant_id: 't1'})
SET a3.name = 'VDI Pool A',
    a3.type = 'vdi',
    a3.trust_score = 88,
    a3.criticality = 'medium',
    a3.status = 'active',
    a3.network_segment = 'engineering',
    a3.created_at = datetime(),
    a3.updated_at = datetime();

MERGE (ip1:IPAddress {address: '203.0.113.42'})
SET ip1.last_seen = datetime();

MERGE (d1:Domain {name: 'strange-domain.example'})
SET d1.last_seen = datetime();

MERGE (t1:MITRETechnique {id: 'T1078'})
SET t1.tactic = 'initial-access';

MERGE (t2:MITRETechnique {id: 'T1190'})
SET t2.tactic = 'initial-access';

MERGE (t3:MITRETechnique {id: 'T1566'})
SET t3.tactic = 'initial-access';

// Create relationships
MATCH (a1:Asset {id: 'asset_001'}), (ip1:IPAddress {address: '203.0.113.42'})
MERGE (a1)-[:CONNECTED_FROM {first_seen: datetime()}]->(ip1);

MATCH (a1:Asset {id: 'asset_001'}), (d1:Domain {name: 'strange-domain.example'})
MERGE (a1)-[:RESOLVED_TO {first_seen: datetime()}]->(d1);

MATCH (a1:Asset {id: 'asset_001'}), (t1:MITRETechnique {id: 'T1078'})
MERGE (a1)-[:EXPLOITED_BY {first_seen: datetime()}]->(t1);

MATCH (a2:Asset {id: 'asset_002'}), (t2:MITRETechnique {id: 'T1190'})
MERGE (a2)-[:EXPLOITED_BY {first_seen: datetime()}]->(t2);

MATCH (a1:Asset {id: 'asset_001'}), (a2:Asset {id: 'asset_002'})
MERGE (a1)-[:SAME_NETWORK_SEGMENT]->(a2);
