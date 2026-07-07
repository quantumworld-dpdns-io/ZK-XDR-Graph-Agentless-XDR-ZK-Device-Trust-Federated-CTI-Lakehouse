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
	playbookExecutions = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "soar_playbook_executions_total", Help: "Playbook executions"},
		[]string{"playbook_id", "status"},
	)
	actionsExecuted = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "soar_actions_executed_total", Help: "Actions executed"},
		[]string{"action_type", "status"},
	)
)

func init() {
	prometheus.MustRegister(playbookExecutions, actionsExecuted)
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
	MitreTactic    string   `json:"mitre_tactic"`
	MitreTechnique string   `json:"mitre_technique"`
	EventIDs       []string `json:"event_ids"`
	Tags           []string `json:"tags"`
}

type PlaybookAction struct {
	Name             string            `json:"name"`
	Type             string            `json:"type"`
	Parameters       map[string]string `json:"parameters"`
	RequiresApproval bool              `json:"requires_approval"`
}

type Playbook struct {
	ID      string           `json:"id"`
	Name    string           `json:"name"`
	Trigger string           `json:"trigger"`
	Status  string           `json:"status"`
	Actions []PlaybookAction `json:"actions"`
}

type PlaybookExecution struct {
	ExecutionID string           `json:"execution_id"`
	PlaybookID  string           `json:"playbook_id"`
	IncidentID  string           `json:"incident_id"`
	Status      string           `json:"status"`
	Actions     []PlaybookAction `json:"actions"`
	StartedAt   string           `json:"started_at"`
	CompletedAt string           `json:"completed_at"`
	Result      string           `json:"result"`
}

func buildPlaybooks() []Playbook {
	return []Playbook{
		{
			ID:      "pb_001",
			Name:    "Low Trust Device Quarantine",
			Trigger: "zk.device.attestation.failed",
			Status:  "active",
			Actions: []PlaybookAction{
				{Name: "Query device trust score", Type: "query", Parameters: map[string]string{"source": "clickhouse"}},
				{Name: "Isolate device from network", Type: "isolate_device", Parameters: map[string]string{"method": "network_acl"}, RequiresApproval: true},
				{Name: "Notify SOC team", Type: "notify", Parameters: map[string]string{"channel": "slack", "message": "Device quarantined due to failed ZK attestation"}},
				{Name: "Create evidence snapshot", Type: "snapshot", Parameters: map[string]string{"storage": "minio"}},
			},
		},
		{
			ID:      "pb_002",
			Name:    "Suspicious DNS Response",
			Trigger: "dns.query.suspicious",
			Status:  "active",
			Actions: []PlaybookAction{
				{Name: "Enrich domain with CTI", Type: "enrich", Parameters: map[string]string{"source": "cti-lakehouse"}},
				{Name: "Block domain at DNS level", Type: "block_domain", Parameters: map[string]string{"method": "dns_sinkhole"}},
				{Name: "Log block action", Type: "log", Parameters: map[string]string{"level": "info"}},
			},
		},
		{
			ID:      "pb_003",
			Name:    "API Abuse Rate Limit",
			Trigger: "waf.rate_limit.exceeded",
			Status:  "active",
			Actions: []PlaybookAction{
				{Name: "Identify source IP", Type: "query", Parameters: map[string]string{"field": "source_ip"}},
				{Name: "Apply IP block", Type: "block_ip", Parameters: map[string]string{"duration": "1h"}, RequiresApproval: true},
				{Name: "Notify security team", Type: "notify", Parameters: map[string]string{"channel": "email"}},
			},
		},
		{
			ID:      "pb_004",
			Name:    "DDoS Mitigation",
			Trigger: "waf.ddos.detected",
			Status:  "active",
			Actions: []PlaybookAction{
				{Name: "Activate rate limiting", Type: "rate_limit", Parameters: map[string]string{"level": "aggressive"}},
				{Name: "Enable geo-blocking", Type: "geo_block", Parameters: map[string]string{"regions": "high_risk"}, RequiresApproval: true},
				{Name: "Notify NOC", Type: "notify", Parameters: map[string]string{"channel": "pagerduty"}},
			},
		},
		{
			ID:      "pb_005",
			Name:    "Quishing/BEC Response",
			Trigger: "email.phishing.detected",
			Status:  "active",
			Actions: []PlaybookAction{
				{Name: "Quarantine email", Type: "quarantine_email", Parameters: map[string]string{"action": "move_to_quarantine"}},
				{Name: "Block sender domain", Type: "block_sender", Parameters: map[string]string{"duration": "7d"}},
				{Name: "Notify affected users", Type: "notify", Parameters: map[string]string{"channel": "email", "template": "phishing_warning"}},
				{Name: "Create incident report", Type: "report", Parameters: map[string]string{"format": "pdf"}},
			},
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

	go func() {
		http.Handle("/metrics", promhttp.Handler())
		http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
		log.Println("Metrics server on :9094")
		if err := http.ListenAndServe(":9094", nil); err != nil {
			log.Printf("Metrics server error: %v", err)
		}
	}()

	rdb.XGroupCreateMkStream(ctx, "xdr:incidents", "playbook-executors", "0")

	log.Println("SOAR playbook engine started")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Println("Shutting down SOAR playbook engine...")
		cancel()
	}()

	playbooks := buildPlaybooks()

	for {
		select {
		case <-ctx.Done():
			return
		default:
			processIncidents(ctx, rdb, playbooks)
		}
	}
}

func processIncidents(ctx context.Context, rdb *redis.Client, playbooks []Playbook) {
	streams, err := rdb.XReadGroup(ctx, &redis.XReadGroupArgs{
		Group:    "playbook-executors",
		Consumer: "executor-1",
		Streams:  []string{"xdr:incidents", ">"},
		Count:    10,
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
			var incident Incident
			if err := json.Unmarshal([]byte(msg.Values["data"].(string)), &incident); err != nil {
				log.Printf("Error unmarshaling incident: %v", err)
				continue
			}

			executePlaybooks(ctx, rdb, incident, playbooks)
			rdb.XAck(ctx, "xdr:incidents", "playbook-executors", msg.ID)
		}
	}
}

func executePlaybooks(ctx context.Context, rdb *redis.Client, incident Incident, playbooks []Playbook) {
	for _, pb := range playbooks {
		if pb.Trigger == incident.IncidentType || pb.Trigger == incident.MitreTechnique {
			log.Printf("Executing playbook %s for incident %s", pb.Name, incident.IncidentID)

			execution := PlaybookExecution{
				ExecutionID: fmt.Sprintf("exec_%d", time.Now().UnixNano()),
				PlaybookID:  pb.ID,
				IncidentID:  incident.IncidentID,
				Status:      "running",
				Actions:     pb.Actions,
				StartedAt:   time.Now().Format(time.RFC3339),
			}

			for _, action := range pb.Actions {
				if action.RequiresApproval {
					log.Printf("  [APPROVAL REQUIRED] Action: %s", action.Name)
					execution.Status = "awaiting_approval"
					actionsExecuted.WithLabelValues(action.Type, "awaiting_approval").Inc()
				} else {
					log.Printf("  [EXECUTED] Action: %s (type: %s)", action.Name, action.Type)
					actionsExecuted.WithLabelValues(action.Type, "executed").Inc()
				}
			}

			execution.CompletedAt = time.Now().Format(time.RFC3339)
			execution.Result = "completed"

			data, _ := json.Marshal(execution)
			rdb.XAdd(ctx, &redis.XAddArgs{
				Stream: "xdr:playbook_executions",
				Values: map[string]interface{}{"data": string(data)},
			})

			log.Printf("Playbook %s execution completed: %s", pb.Name, execution.Result)
			playbookExecutions.WithLabelValues(pb.ID, execution.Result).Inc()
		}
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
