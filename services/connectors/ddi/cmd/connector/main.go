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

	"github.com/redis/go-redis/v9"
)

type DDIEvent struct {
	Timestamp   string `json:"timestamp"`
	Source      string `json:"source"`
	Domain      string `json:"domain"`
	QueryType   string `json:"query_type"`
	SourceIP    string `json:"source_ip"`
	ResponseIP  string `json:"response_ip"`
	StatusCode  int    `json:"status_code"`
	ResponseTime int   `json:"response_time_ms"`
	TenantID    string `json:"tenant_id"`
}

type NormalizedEvent struct {
	EventID      string            `json:"event_id"`
	TenantID     string            `json:"tenant_id"`
	Timestamp    string            `json:"timestamp"`
	Source       string            `json:"source"`
	EventType    string            `json:"event_type"`
	Category     string            `json:"category"`
	Severity     string            `json:"severity"`
	Confidence   int               `json:"confidence"`
	RiskScore    int               `json:"risk_score"`
	SourceIP     string            `json:"source_ip"`
	DestIP       string            `json:"dest_ip"`
	Domain       string            `json:"domain"`
	MitreTactic  string            `json:"mitre_tactic"`
	MitreTechnique string          `json:"mitre_technique"`
	RawEvent     DDIEvent          `json:"raw_event"`
	Tags         map[string]string `json:"tags"`
}

var suspiciousTLDs = map[string]bool{
	".xyz": true, ".top": true, ".buzz": true, ".tk": true,
	".ml": true, ".ga": true, ".cf": true, ".gq": true,
}

var dgaIndicators = []string{
	"random", "temp", "test", "update", "check",
	"verify", "secure", "login", "account", "billing",
}

func normalizeDDIEvent(event DDIEvent) NormalizedEvent {
	eventID := fmt.Sprintf("ddi_%d", time.Now().UnixNano())
	severity := "info"
	confidence := 50
	riskScore := 200
	eventType := "dns.query.normal"
	mitreTechnique := ""

	// Check for suspicious patterns
	if isSuspiciousDomain(event.Domain) {
		severity = "high"
		confidence = 80
		riskScore = 750
		eventType = "dns.query.suspicious"
		mitreTechnique = "T1071.004"
	} else if isDGAPattern(event.Domain) {
		severity = "critical"
		confidence = 85
		riskScore = 900
		eventType = "dns.query.dga"
		mitreTechnique = "T1568.002"
	} else if event.StatusCode == 0 || event.ResponseTime > 5000 {
		severity = "medium"
		confidence = 60
		riskScore = 400
		eventType = "dns.query.timeout"
	}

	return NormalizedEvent{
		EventID:        eventID,
		TenantID:       event.TenantID,
		Timestamp:      event.Timestamp,
		Source:         "ddi",
		EventType:      eventType,
		Category:       "network",
		Severity:       severity,
		Confidence:     confidence,
		RiskScore:      riskScore,
		SourceIP:       event.SourceIP,
		DestIP:         event.ResponseIP,
		Domain:         event.Domain,
		MitreTactic:    "command-and-control",
		MitreTechnique: mitreTechnique,
		RawEvent:       event,
		Tags: map[string]string{
			"query_type": event.QueryType,
			"connector":  "ddi",
		},
	}
}

func isSuspiciousDomain(domain string) bool {
	for tld := range suspiciousTLDs {
		if len(domain) > len(tld) && domain[len(domain)-len(tld):] == tld {
			return true
		}
	}
	return false
}

func isDGAPattern(domain string) bool {
	if len(domain) < 8 {
		return false
	}
	consonantCount := 0
	for _, c := range domain {
		if c == '.' {
			continue
		}
		switch c {
		case 'b', 'c', 'd', 'f', 'g', 'h', 'j', 'k', 'l', 'm', 'n', 'p', 'q', 'r', 's', 't', 'v', 'w', 'x', 'y', 'z':
			consonantCount++
		}
	}
	ratio := float64(consonantCount) / float64(len(domain))
	return ratio > 0.85 && len(domain) > 12
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rdb := redis.NewClient(&redis.Options{
		Addr:     getEnv("REDIS_ADDR", "localhost:6379"),
		Password: getEnv("REDIS_PASSWORD", ""),
		DB:       0,
	})
	defer rdb.Close()

	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Fatalf("Redis connection failed: %v", err)
	}

	log.Println("DDI connector started, consuming DNS events...")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Println("Shutting down DDI connector...")
		cancel()
	}()

	// Simulate DDI events for demo
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			generateDemoDDIEvents(ctx, rdb)
		}
	}
}

func generateDemoDDIEvents(ctx context.Context, rdb *redis.Client) {
	events := []DDIEvent{
		{
			Timestamp:   time.Now().Format(time.RFC3339),
			Source:      "ddi",
			Domain:      "strange-domain.xyz",
			QueryType:   "A",
			SourceIP:    "192.168.1.100",
			ResponseIP:  "203.0.113.42",
			StatusCode:  200,
			ResponseTime: 150,
			TenantID:    "t1",
		},
		{
			Timestamp:   time.Now().Format(time.RFC3339),
			Source:      "ddi",
			Domain:      "xkrjfmalwpq.top",
			QueryType:   "A",
			SourceIP:    "192.168.1.105",
			ResponseIP:  "198.51.100.23",
			StatusCode:  200,
			ResponseTime: 200,
			TenantID:    "t1",
		},
	}

	for _, event := range events {
		normalized := normalizeDDIEvent(event)
		data, _ := json.Marshal(normalized)
		rdb.XAdd(ctx, &redis.XAddArgs{
			Stream: "xdr:events",
			Values: map[string]interface{}{"data": string(data)},
		})
		log.Printf("Published DDI event: %s (severity: %s)", normalized.EventType, normalized.Severity)
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
