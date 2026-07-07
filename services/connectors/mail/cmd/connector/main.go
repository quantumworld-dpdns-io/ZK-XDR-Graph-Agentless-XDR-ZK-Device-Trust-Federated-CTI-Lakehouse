package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
)

var (
	mailEventsProcessed = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "mail_events_total", Help: "Total mail events processed"},
		[]string{"event_type", "severity"},
	)
	phishingDetected = prometheus.NewCounter(
		prometheus.CounterOpts{Name: "mail_phishing_detected_total", Help: "Phishing emails detected"},
	)
	suspiciousAttachments = prometheus.NewCounter(
		prometheus.CounterOpts{Name: "mail_suspicious_attachments_total", Help: "Suspicious attachments detected"},
	)
)

func init() {
	prometheus.MustRegister(mailEventsProcessed, phishingDetected, suspiciousAttachments)
}

type MailEvent struct {
	Timestamp   string   `json:"timestamp"`
	Source      string   `json:"source"`
	From        string   `json:"from"`
	To          string   `json:"to"`
	Subject     string   `json:"subject"`
	HasAttachment bool   `json:"has_attachment"`
	AttachmentCount int  `json:"attachment_count"`
	AttachmentTypes []string `json:"attachment_types"`
	SpamScore   float64  `json:"spam_score"`
	PhishScore  float64  `json:"phish_score"`
	SPFPass     bool     `json:"spf_pass"`
	DKIMPass    bool     `json:"dkim_pass"`
	DMARCPass   bool     `json:"dmarc_pass"`
	TenantID    string   `json:"tenant_id"`
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
	MitreTactic    string            `json:"mitre_tactic"`
	MitreTechnique string            `json:"mitre_technique"`
	RawEvent       MailEvent         `json:"raw_event"`
	Tags           map[string]string `json:"tags"`
}

func normalizeMailEvent(event MailEvent) NormalizedEvent {
	eventID := fmt.Sprintf("mail_%d", time.Now().UnixNano())
	severity := "info"
	confidence := 50
	riskScore := 200
	eventType := "email.received.normal"
	mitreTechnique := ""

	// Check for phishing indicators
	if event.PhishScore > 0.7 || event.SpamScore > 0.8 {
		severity = "high"
		confidence = 85
		riskScore = 800
		eventType = "email.phishing.detected"
		mitreTechnique = "T1566"
	} else if !event.SPFPass || !event.DKIMPass {
		severity = "medium"
		confidence = 65
		riskScore = 500
		eventType = "email.auth.failure"
		mitreTechnique = "T1566.001"
	} else if event.HasAttachment && containsSuspiciousAttachment(event.AttachmentTypes) {
		severity = "high"
		confidence = 75
		riskScore = 700
		eventType = "email.suspicious_attachment"
		mitreTechnique = "T1566.001"
	} else if event.PhishScore > 0.4 {
		severity = "medium"
		confidence = 60
		riskScore = 400
		eventType = "email.possibly_phishing"
	}

	return NormalizedEvent{
		EventID:        eventID,
		TenantID:       event.TenantID,
		Timestamp:      event.Timestamp,
		Source:         "mail",
		EventType:      eventType,
		Category:       "email",
		Severity:       severity,
		Confidence:     confidence,
		RiskScore:      riskScore,
		MitreTactic:    "initial-access",
		MitreTechnique: mitreTechnique,
		RawEvent:       event,
		Tags: map[string]string{
			"from":       event.From,
			"to":         event.To,
			"spam_score": fmt.Sprintf("%.2f", event.SpamScore),
			"phish_score": fmt.Sprintf("%.2f", event.PhishScore),
			"connector":  "mail",
		},
	}
}

func containsSuspiciousAttachment(types []string) bool {
	suspicious := map[string]bool{
		".exe": true, ".scr": true, ".bat": true, ".cmd": true,
		".js": true, ".vbs": true, ".ps1": true, ".docm": true,
		".xlsm": true, ".pptm": true, ".zip": true, ".rar": true,
	}
	for _, t := range types {
		if suspicious[t] {
			return true
		}
	}
	return false
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

	// Start metrics server
	go func() {
		http.Handle("/metrics", promhttp.Handler())
		http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
		log.Println("Metrics server on :9097")
		if err := http.ListenAndServe(":9097", nil); err != nil {
			log.Printf("Metrics server error: %v", err)
		}
	}()

	log.Println("Mail connector started, consuming email events...")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Println("Shutting down Mail connector...")
		cancel()
	}()

	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			generateDemoMailEvents(ctx, rdb)
		}
	}
}

func generateDemoMailEvents(ctx context.Context, rdb *redis.Client) {
	events := []MailEvent{
		{
			Timestamp:       time.Now().Format(time.RFC3339),
			Source:          "mail",
			From:            "phishing@malicious-domain.xyz",
			To:              "finance@company.com",
			Subject:         "Urgent: Verify your account credentials",
			HasAttachment:   true,
			AttachmentCount: 1,
			AttachmentTypes: []string{".zip"},
			SpamScore:       0.85,
			PhishScore:      0.92,
			SPFPass:         false,
			DKIMPass:        false,
			DMARCPass:       false,
			TenantID:        "t1",
		},
	}

	for _, event := range events {
		normalized := normalizeMailEvent(event)
		data, _ := json.Marshal(normalized)
		rdb.XAdd(ctx, &redis.XAddArgs{
			Stream: "xdr:events",
			Values: map[string]interface{}{"data": string(data)},
		})
		mailEventsProcessed.WithLabelValues(normalized.EventType, normalized.Severity).Inc()
		if normalized.EventType == "email.phishing.detected" {
			phishingDetected.Inc()
		} else if normalized.EventType == "email.suspicious_attachment" {
			suspiciousAttachments.Inc()
		}
		log.Printf("Published Mail event: %s (severity: %s)", normalized.EventType, normalized.Severity)
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
