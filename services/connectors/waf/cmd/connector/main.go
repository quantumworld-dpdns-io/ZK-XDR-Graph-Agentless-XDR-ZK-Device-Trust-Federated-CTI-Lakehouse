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

type WAFEvent struct {
	Timestamp    string `json:"timestamp"`
	Source       string `json:"source"`
	ClientIP     string `json:"client_ip"`
	Method       string `json:"method"`
	Path         string `json:"path"`
	StatusCode   int    `json:"status_code"`
	ResponseSize int    `json:"response_size"`
	RuleID       string `json:"rule_id"`
	RuleAction   string `json:"rule_action"`
	RequestSize  int    `json:"request_size"`
	UserAgent    string `json:"user_agent"`
	Host         string `json:"host"`
	TenantID     string `json:"tenant_id"`
}

type NormalizedEvent struct {
	EventID        string            `json:"event_id"`
	TenantID       string            `json:"tenant_id"`
	Timestamp      string            `json:"timestamp"`
	Source         string            `json:"source"`
	EventType      string            `json:"event_type"`
	Category       string            `json:"category"`
	Severity       string            `json:"severity"`
	Confidence     int               `json:"confidence"`
	RiskScore      int               `json:"risk_score"`
	SourceIP       string            `json:"source_ip"`
	DestIP         string            `json:"dest_ip"`
	MitreTactic    string            `json:"mitre_tactic"`
	MitreTechnique string            `json:"mitre_technique"`
	RawEvent       WAFEvent          `json:"raw_event"`
	Tags           map[string]string `json:"tags"`
}

func normalizeWAFEvent(event WAFEvent) NormalizedEvent {
	eventID := fmt.Sprintf("waf_%d", time.Now().UnixNano())
	severity := "info"
	confidence := 50
	riskScore := 200
	eventType := "waf.request.normal"
	mitreTechnique := ""

	switch {
	case event.RuleAction == "block" && event.RuleID != "":
		severity = "high"
		confidence = 90
		riskScore = 800
		eventType = "waf.rule.blocked"
		mitreTechnique = "T1190"
	case event.StatusCode == 429:
		severity = "medium"
		confidence = 70
		riskScore = 500
		eventType = "waf.rate_limit.exceeded"
		mitreTechnique = "T1499"
	case event.StatusCode >= 500:
		severity = "medium"
		confidence = 60
		riskScore = 400
		eventType = "waf.server.error"
	case event.StatusCode == 403:
		severity = "medium"
		confidence = 65
		riskScore = 450
		eventType = "waf.access.denied"
	case event.StatusCode == 401:
		severity = "high"
		confidence = 75
		riskScore = 700
		eventType = "waf.auth.failure"
		mitreTechnique = "T1110"
	}

	return NormalizedEvent{
		EventID:        eventID,
		TenantID:       event.TenantID,
		Timestamp:      event.Timestamp,
		Source:         "waf",
		EventType:      eventType,
		Category:       "network",
		Severity:       severity,
		Confidence:     confidence,
		RiskScore:      riskScore,
		SourceIP:       event.ClientIP,
		MitreTactic:    "initial-access",
		MitreTechnique: mitreTechnique,
		RawEvent:       event,
		Tags: map[string]string{
			"method":     event.Method,
			"path":       event.Path,
			"rule_id":    event.RuleID,
			"rule_action": event.RuleAction,
			"connector":  "waf",
		},
	}
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

	log.Println("WAF connector started, consuming HTTP events...")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Println("Shutting down WAF connector...")
		cancel()
	}()

	ticker := time.NewTicker(45 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			generateDemoWAFEvents(ctx, rdb)
		}
	}
}

func generateDemoWAFEvents(ctx context.Context, rdb *redis.Client) {
	events := []WAFEvent{
		{
			Timestamp:    time.Now().Format(time.RFC3339),
			Source:       "waf",
			ClientIP:     "203.0.113.42",
			Method:       "POST",
			Path:         "/api/v1/auth/login",
			StatusCode:   429,
			ResponseSize: 0,
			RuleID:       "rl_001",
			RuleAction:   "block",
			RequestSize:  1024,
			UserAgent:    "Mozilla/5.0 (compatible; Nmap Scripting Engine)",
			Host:         "api.example.com",
			TenantID:     "t1",
		},
	}

	for _, event := range events {
		normalized := normalizeWAFEvent(event)
		data, _ := json.Marshal(normalized)
		rdb.XAdd(ctx, &redis.XAddArgs{
			Stream: "xdr:events",
			Values: map[string]interface{}{"data": string(data)},
		})
		log.Printf("Published WAF event: %s (severity: %s)", normalized.EventType, normalized.Severity)
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
