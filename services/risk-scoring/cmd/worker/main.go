package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/redis/go-redis/v9"
)

type XDRRiskEvent struct {
	EventID       string  `json:"event_id"`
	TenantID      string  `json:"tenant_id"`
	Timestamp     string  `json:"timestamp"`
	Source        string  `json:"source"`
	EventType     string  `json:"event_type"`
	Category      string  `json:"category"`
	Severity      string  `json:"severity"`
	Confidence    int     `json:"confidence"`
	RiskScore     int     `json:"risk_score"`
	AssetID       string  `json:"asset_id"`
	AssetName     string  `json:"asset_name"`
	AssetType     string  `json:"asset_type"`
	MitreTactic   string  `json:"mitre_tactic"`
	MitreTechnique string `json:"mitre_technique"`
	SourceIP      string  `json:"source_ip"`
	DestIP        string  `json:"dest_ip"`
	Domain        string  `json:"domain"`
}

type AssetRiskFactors struct {
	ZKAttestation   int     `json:"zk_attestation"`
	EventFrequency  int     `json:"event_frequency"`
	SeverityWeight  float64 `json:"severity_weight"`
	CTIMatchCount   int     `json:"cti_match_count"`
	VulnExposure    int     `json:"vuln_exposure"`
	NetworkSegment  string  `json:"network_segment"`
	Criticality     string  `json:"criticality"`
	LastEventAge    int     `json:"last_event_age_hours"`
}

type AssetTrustScore struct {
	TenantID       string            `json:"tenant_id"`
	AssetID        string            `json:"asset_id"`
	AssetName      string            `json:"asset_name"`
	AssetType      string            `json:"asset_type"`
	NetworkSegment string            `json:"network_segment"`
	TrustScore     int               `json:"trust_score"`
	RiskFactors    AssetRiskFactors  `json:"risk_factors"`
	Criticality    string            `json:"criticality"`
	Status         string            `json:"status"`
	LastEventAt    time.Time         `json:"last_event_at"`
	UpdatedAt      time.Time         `json:"updated_at"`
}

var (
	severityWeights = map[string]float64{
		"info":     0.0,
		"low":      0.25,
		"medium":   0.50,
		"high":     0.75,
		"critical": 1.0,
	}

	criticalityModifiers = map[string]float64{
		"critical": -20,
		"high":     -10,
		"medium":   0,
		"low":      10,
	}
)

func computeTrustScore(factors AssetRiskFactors) int {
	score := 80.0

	// ZK attestation contribution (0-20 points, higher is better)
	score -= float64(factors.ZKAttestation) * 0.2

	// Event frequency penalty (more events = less trusted)
	if factors.EventFrequency > 10 {
		score -= float64(factors.EventFrequency-10) * 1.5
	}

	// Severity contribution
	score -= factors.SeverityWeight * 30

	// CTI match penalty
	score -= float64(factors.CTIMatchCount) * 5

	// Vuln exposure penalty
	score -= float64(factors.VulnExposure) * 3

	// Criticality modifier
	if mod, ok := criticalityModifiers[factors.Criticality]; ok {
		score += mod
	}

	// Stale assets (no recent events) get slightly lower scores
	if factors.LastEventAge > 72 {
		score -= 5
	}

	// Clamp to 0-100
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	return int(score)
}

func determineStatus(trustScore int) string {
	switch {
	case trustScore < 40:
		return "quarantined"
	case trustScore < 60:
		return "suspicious"
	case trustScore < 80:
		return "active"
	default:
		return "trusted"
	}
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Connect to ClickHouse
	chDSN := os.Getenv("CLICKHOUSE_DSN")
	if chDSN == "" {
		chDSN = "clickhouse://default:@localhost:9000/default"
	}

	chConn, err := clickhouse.Open(&clickhouse.Options{
		Addr: chDSN,
	})
	if err != nil {
		log.Fatalf("Failed to connect to ClickHouse: %v", err)
	}
	defer chConn.Close()

	// Connect to Redis
	rdb := redis.NewClient(&redis.Options{
		Addr:     getEnv("REDIS_ADDR", "localhost:6379"),
		Password: getEnv("REDIS_PASSWORD", ""),
		DB:       0,
	})
	defer rdb.Close()

	// Ping ClickHouse
	if err := chConn.Ping(ctx); err != nil {
		log.Fatalf("ClickHouse ping failed: %v", err)
	}
	log.Println("Connected to ClickHouse")

	// Ping Redis
	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Fatalf("Redis ping failed: %v", err)
	}
	log.Println("Connected to Redis")

	// Ensure consumer group
	rdb.XGroupCreateMkStream(ctx, "xdr:events", "risk-scorers", "0")

	log.Println("Risk scoring service started, consuming from xdr:events...")

	// Graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Println("Shutting down risk scoring service...")
		cancel()
	}()

	// Main event loop
	for {
		select {
		case <-ctx.Done():
			return
		default:
			processEvents(ctx, rdb, chConn)
		}
	}
}

func processEvents(ctx context.Context, rdb *redis.Client, chConn clickhouse.Conn) {
	streams, err := rdb.XReadGroup(ctx, &redis.XReadGroupArgs{
		Group:    "risk-scorers",
		Consumer: "risk-scorer-1",
		Streams:  []string{"xdr:events", ">"},
		Count:    50,
		Block:    5 * time.Second,
	}).Result()

	if err != nil {
		if err != redis.Nil {
			log.Printf("Error reading from Redis: %v", err)
		}
		return
	}

	for _, stream := range streams {
		for _, msg := range stream.Messages {
			var event XDRRiskEvent
			if err := json.Unmarshal([]byte(msg.Values["data"].(string)), &event); err != nil {
				log.Printf("Error unmarshaling event: %v", err)
				continue
			}

			if err := processEvent(ctx, chConn, event); err != nil {
				log.Printf("Error processing event %s: %v", event.EventID, err)
				continue
			}

			// Acknowledge the event
			rdb.XAck(ctx, "xdr:events", "risk-scorers", msg.ID)
		}
	}
}

func processEvent(ctx context.Context, chConn clickhouse.Conn, event XDRRiskEvent) error {
	// Insert event into ClickHouse
	err := chConn.Exec(ctx, `
		INSERT INTO xdr_events (
			event_id, tenant_id, timestamp, source, event_type, category,
			severity, confidence, risk_score, asset_id, asset_name, asset_type,
			mitre_tactic, mitre_technique, source_ip, dest_ip, domain, raw_event
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		event.EventID, event.TenantID, event.Timestamp, event.Source,
		event.EventType, event.Category, event.Severity, event.Confidence,
		event.RiskScore, event.AssetID, event.AssetName, event.AssetType,
		event.MitreTactic, event.MitreTechnique, event.SourceIP, event.DestIP,
		event.Domain, "{}",
	)
	if err != nil {
		return fmt.Errorf("insert event: %w", err)
	}

	// If event has an asset, update asset trust score
	if event.AssetID != "" {
		if err := updateAssetTrustScore(ctx, chConn, event); err != nil {
			return fmt.Errorf("update trust score: %w", err)
		}
	}

	return nil
}

func updateAssetTrustScore(ctx context.Context, chConn clickhouse.Conn, event XDRRiskEvent) error {
	// Query recent events for this asset to compute factors
	var eventCount int
	var maxSeverity string
	var ctiMatchCount int

	err := chConn.QueryRow(ctx, `
		SELECT
			count() as event_count,
			max(severity) as max_severity,
			countIf(event_type LIKE 'cti.ioc_match%') as cti_matches
		FROM xdr_events
		WHERE tenant_id = ? AND asset_id = ?
		  AND timestamp > now() - INTERVAL 24 HOUR
	`, event.TenantID, event.AssetID).Scan(&eventCount, &maxSeverity, &ctiMatchCount)
	if err != nil {
		return fmt.Errorf("query asset events: %w", err)
	}

	// Compute severity weight
	severityWeight := severityWeights[maxSeverity]

	factors := AssetRiskFactors{
		ZKAttestation:  0,
		EventFrequency: eventCount,
		SeverityWeight: severityWeight,
		CTIMatchCount:  ctiMatchCount,
		VulnExposure:   0,
		NetworkSegment: "",
		Criticality:    "medium",
		LastEventAge:   0,
	}

	trustScore := computeTrustScore(factors)
	status := determineStatus(trustScore)

	factorsJSON, _ := json.Marshal(factors)

	// Upsert asset trust score
	err = chConn.Exec(ctx, `
		INSERT INTO xdr_asset_trust (
			tenant_id, asset_id, asset_name, asset_type, network_segment,
			trust_score, risk_factors, criticality, status, last_event_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, now64(3, 'UTC'))
	`,
		event.TenantID, event.AssetID, event.AssetName, event.AssetType,
		"", trustScore, string(factorsJSON), "medium", status, event.Timestamp,
	)
	if err != nil {
		return fmt.Errorf("upsert asset trust: %w", err)
	}

	log.Printf("Asset %s trust score updated: %d (%s)", event.AssetID, trustScore, status)
	return nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
