package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/redis/go-redis/v9"
)

type Event struct {
	EventID        string `json:"event_id"`
	TenantID       string `json:"tenant_id"`
	Timestamp      string `json:"timestamp"`
	Source         string `json:"source"`
	EventType      string `json:"event_type"`
	Category       string `json:"category"`
	Severity       string `json:"severity"`
	Confidence     int    `json:"confidence"`
	RiskScore      int    `json:"risk_score"`
	AssetID        string `json:"asset_id"`
	AssetName      string `json:"asset_name"`
	MitreTactic    string `json:"mitre_tactic"`
	MitreTechnique string `json:"mitre_technique"`
	SourceIP       string `json:"source_ip"`
	Domain         string `json:"domain"`
}

type Incident struct {
	IncidentID     string   `json:"incident_id"`
	TenantID       string   `json:"tenant_id"`
	Title          string   `json:"title"`
	Description    string   `json:"description"`
	IncidentType   string   `json:"incident_type"`
	Severity       string   `json:"severity"`
	Status         string   `json:"status"`
	RiskScore      int      `json:"risk_score"`
	AssetID        string   `json:"asset_id"`
	AssetName      string   `json:"asset_name"`
	MitreTactic    string   `json:"mitre_tactic"`
	MitreTechnique string   `json:"mitre_technique"`
	EventIDs       []string `json:"event_ids"`
	Tags           []string `json:"tags"`
	CreatedAt      string   `json:"created_at"`
}

type CorrelationRule struct {
	Name           string
	EventType      string
	TimeWindow     time.Duration
	MinEventCount  int
	Severity       string
	IncidentType   string
	MitreTactic    string
	MitreTechnique string
}

var correlationRules = []CorrelationRule{
	{
		Name:           "Credential Stuffing",
		EventType:      "waf.auth.failure",
		TimeWindow:     10 * time.Minute,
		MinEventCount:  5,
		Severity:       "high",
		IncidentType:   "api_abuse",
		MitreTactic:    "credential-access",
		MitreTechnique: "T1110",
	},
	{
		Name:           "DDoS Attack",
		EventType:      "waf.rate_limit.exceeded",
		TimeWindow:     5 * time.Minute,
		MinEventCount:  10,
		Severity:       "critical",
		IncidentType:   "ddos",
		MitreTactic:    "impact",
		MitreTechnique: "T1499",
	},
	{
		Name:           "Phishing Campaign",
		EventType:      "email.phishing.detected",
		TimeWindow:     30 * time.Minute,
		MinEventCount:  3,
		Severity:       "high",
		IncidentType:   "quishing_bec",
		MitreTactic:    "initial-access",
		MitreTechnique: "T1566",
	},
	{
		Name:           "DGA Domain Activity",
		EventType:      "dns.query.dga",
		TimeWindow:     15 * time.Minute,
		MinEventCount:  3,
		Severity:       "critical",
		IncidentType:   "c2_communication",
		MitreTactic:    "command-and-control",
		MitreTechnique: "T1568.002",
	},
	{
		Name:           "Suspicious DNS Beaconing",
		EventType:      "dns.query.suspicious",
		TimeWindow:     20 * time.Minute,
		MinEventCount:  5,
		Severity:       "high",
		IncidentType:   "suspicious_iot_beaconing",
		MitreTactic:    "command-and-control",
		MitreTechnique: "T1071.004",
	},
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

	if err := chConn.Ping(ctx); err != nil {
		log.Fatalf("ClickHouse ping failed: %v", err)
	}
	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Fatalf("Redis ping failed: %v", err)
	}

	log.Println("Correlation engine started")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Println("Shutting down correlation engine...")
		cancel()
	}()

	// Run correlation every 30 seconds
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runCorrelation(ctx, chConn, rdb)
		}
	}
}

func runCorrelation(ctx context.Context, chConn clickhouse.Conn, rdb *redis.Client) {
	for _, rule := range correlationRules {
		if err := checkRule(ctx, chConn, rdb, rule); err != nil {
			log.Printf("Error checking rule %s: %v", rule.Name, err)
		}
	}
}

func checkRule(ctx context.Context, chConn clickhouse.Conn, rdb *redis.Client, rule CorrelationRule) error {
	windowStart := time.Now().Add(-rule.TimeWindow).Format("2006-01-02 15:04:05")

	var count int
	err := chConn.QueryRow(ctx, `
		SELECT count() FROM xdr_events
		WHERE event_type = ?
		  AND timestamp >= ?
		  AND tenant_id = 't1'
	`, rule.EventType, windowStart).Scan(&count)
	if err != nil {
		return fmt.Errorf("query events: %w", err)
	}

	if count >= rule.MinEventCount {
		log.Printf("Rule triggered: %s (count: %d, threshold: %d)", rule.Name, count, rule.MinEventCount)

		// Create incident
		incident := Incident{
			IncidentID:     fmt.Sprintf("inc_%d", time.Now().UnixNano()),
			TenantID:       "t1",
			Title:          rule.Name,
			Description:    fmt.Sprintf("Correlated %d events of type %s in %s window", count, rule.EventType, rule.TimeWindow),
			IncidentType:   rule.IncidentType,
			Severity:       rule.Severity,
			Status:         "open",
			RiskScore:      computeIncidentRiskScore(rule, count),
			MitreTactic:    rule.MitreTactic,
			MitreTechnique: rule.MitreTechnique,
			EventIDs:       []string{},
			Tags:           []string{"auto-correlated", rule.IncidentType},
			CreatedAt:      time.Now().Format(time.RFC3339),
		}

		// Store incident in ClickHouse
		if err := storeIncident(ctx, chConn, incident); err != nil {
			return fmt.Errorf("store incident: %w", err)
		}

		// Publish to Redis for playbook engine
		data, _ := json.Marshal(incident)
		rdb.XAdd(ctx, &redis.XAddArgs{
			Stream: "xdr:incidents",
			Values: map[string]interface{}{"data": string(data)},
		})

		log.Printf("Created incident: %s (severity: %s, risk: %d)", incident.IncidentID, incident.Severity, incident.RiskScore)
	}

	return nil
}

func computeIncidentRiskScore(rule CorrelationRule, count int) int {
	baseScore := 0
	switch rule.Severity {
	case "critical":
		baseScore = 800
	case "high":
		baseScore = 650
	case "medium":
		baseScore = 400
	case "low":
		baseScore = 200
	}

	// Increase risk with event count
	excess := count - rule.MinEventCount
	if excess > 0 {
		baseScore += excess * 10
	}

	if baseScore > 1000 {
		baseScore = 1000
	}
	return baseScore
}

func storeIncident(ctx context.Context, chConn clickhouse.Conn, incident Incident) error {
	return chConn.Exec(ctx, `
		INSERT INTO xdr_incidents (
			incident_id, tenant_id, title, description, incident_type,
			severity, status, risk_score, mitre_tactic, mitre_technique,
			evidence_ids, tags, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		incident.IncidentID, incident.TenantID, incident.Title,
		incident.Description, incident.IncidentType, incident.Severity,
		incident.Status, incident.RiskScore, incident.MitreTactic,
		incident.MitreTechnique, incident.EventIDs, incident.Tags,
		incident.CreatedAt, incident.CreatedAt,
	)
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// unused but kept for future event retrieval
func _sortEvents(events []Event) {
	sort.Slice(events, func(i, j int) bool {
		return events[i].Timestamp < events[j].Timestamp
	})
}
