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

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
)

var (
	graphEventsProcessed = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "asset_graph_events_total", Help: "Total events processed by graph builder"},
		[]string{"source", "event_type"},
	)
	graphNodesCreated = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "asset_graph_nodes_created_total", Help: "Total graph nodes created"},
		[]string{"node_type"},
	)
	graphEdgesCreated = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "asset_graph_edges_created_total", Help: "Total graph edges created"},
		[]string{"edge_type"},
	)
)

func init() {
	prometheus.MustRegister(graphEventsProcessed, graphNodesCreated, graphEdgesCreated)
}

type GraphEvent struct {
	EventID        string `json:"event_id"`
	TenantID       string `json:"tenant_id"`
	Timestamp      string `json:"timestamp"`
	Source         string `json:"source"`
	EventType      string `json:"event_type"`
	Severity       string `json:"severity"`
	Confidence     int    `json:"confidence"`
	RiskScore      int    `json:"risk_score"`
	AssetID        string `json:"asset_id"`
	AssetName      string `json:"asset_name"`
	AssetType      string `json:"asset_type"`
	MitreTactic    string `json:"mitre_tactic"`
	MitreTechnique string `json:"mitre_technique"`
	SourceIP       string `json:"source_ip"`
	DestIP         string `json:"dest_ip"`
	Domain         string `json:"domain"`
	Username       string `json:"username"`
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Connect to Neo4j
	neo4jURI := getEnv("NEO4J_URI", "bolt://localhost:7687")
	neo4jUser := getEnv("NEO4J_USER", "neo4j")
	neo4jPass := getEnv("NEO4J_PASSWORD", "password")

	driver, err := neo4j.NewDriver(neo4jURI, neo4j.BasicAuth(neo4jUser, neo4jPass, ""))
	if err != nil {
		log.Fatalf("Failed to connect to Neo4j: %v", err)
	}
	defer driver.Close()

	// Verify connectivity
	if err := driver.VerifyConnectivity(); err != nil {
		log.Fatalf("Neo4j connectivity failed: %v", err)
	}
	log.Println("Connected to Neo4j")

	// Connect to Redis
	rdb := redis.NewClient(&redis.Options{
		Addr:     getEnv("REDIS_ADDR", "localhost:6379"),
		Password: getEnv("REDIS_PASSWORD", ""),
		DB:       0,
	})
	defer rdb.Close()

	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Fatalf("Redis ping failed: %v", err)
	}

	// Start metrics server
	go func() {
		http.Handle("/metrics", promhttp.Handler())
		http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
		log.Println("Metrics server on :9092")
		if err := http.ListenAndServe(":9092", nil); err != nil {
			log.Printf("Metrics server error: %v", err)
		}
	}()

	// Ensure consumer group
	rdb.XGroupCreateMkStream(ctx, "xdr:events", "graph-builders", "0")

	log.Println("Asset graph service started, consuming from xdr:events...")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Println("Shutting down asset graph service...")
		cancel()
	}()

	for {
		select {
		case <-ctx.Done():
			return
		default:
			processEvents(ctx, rdb, driver)
		}
	}
}

func processEvents(ctx context.Context, rdb *redis.Client, driver neo4j.Driver) {
	streams, err := rdb.XReadGroup(ctx, &redis.XReadGroupArgs{
		Group:    "graph-builders",
		Consumer: "graph-builder-1",
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
			var event GraphEvent
			if err := json.Unmarshal([]byte(msg.Values["data"].(string)), &event); err != nil {
				log.Printf("Error unmarshaling event: %v", err)
				continue
			}

			if err := processEvent(ctx, driver, event); err != nil {
				log.Printf("Error processing event %s: %v", event.EventID, err)
				continue
			}

			rdb.XAck(ctx, "xdr:events", "graph-builders", msg.ID)
		}
	}
}

func processEvent(ctx context.Context, driver neo4j.Driver, event GraphEvent) error {
	graphEventsProcessed.WithLabelValues(event.Source, event.EventType).Inc()
	session := driver.NewSession(neo4j.SessionConfig{DatabaseName: "neo4j"})
	defer session.Close()

	_, err := session.WriteTransaction(func(tx neo4j.Transaction) (any, error) {
		queries := []string{}

		// 1. Upsert Asset node
		if event.AssetID != "" {
			queries = append(queries, fmt.Sprintf(`
				MERGE (a:Asset {id: '%s', tenant_id: '%s'})
				SET a.name = '%s',
				    a.type = '%s',
				    a.last_seen = datetime('%s'),
				    a.updated_at = datetime()
			`, event.AssetID, event.TenantID, event.AssetName, event.AssetType, event.Timestamp))
		}

		// 2. Upsert Source IP node
		if event.SourceIP != "" {
			queries = append(queries, fmt.Sprintf(`
				MERGE (ip:IPAddress {address: '%s'})
				SET ip.last_seen = datetime('%s')
			`, event.SourceIP, event.Timestamp))

			// Link asset to source IP
			if event.AssetID != "" {
				queries = append(queries, fmt.Sprintf(`
					MATCH (a:Asset {id: '%s'}), (ip:IPAddress {address: '%s'})
					MERGE (a)-[:CONNECTED_FROM]->(ip)
				`, event.AssetID, event.SourceIP))
			}
		}

		// 3. Upsert Destination IP node
		if event.DestIP != "" {
			queries = append(queries, fmt.Sprintf(`
				MERGE (ip:IPAddress {address: '%s'})
				SET ip.last_seen = datetime('%s')
			`, event.DestIP, event.Timestamp))

			if event.AssetID != "" {
				queries = append(queries, fmt.Sprintf(`
					MATCH (a:Asset {id: '%s'}), (ip:IPAddress {address: '%s'})
					MERGE (a)-[:CONNECTED_TO]->(ip)
				`, event.AssetID, event.DestIP))
			}
		}

		// 4. Upsert Domain node and link
		if event.Domain != "" {
			queries = append(queries, fmt.Sprintf(`
				MERGE (d:Domain {name: '%s'})
				SET d.last_seen = datetime('%s')
			`, event.Domain, event.Timestamp))

			if event.AssetID != "" {
				queries = append(queries, fmt.Sprintf(`
					MATCH (a:Asset {id: '%s'}), (d:Domain {name: '%s'})
					MERGE (a)-[:RESOLVED_TO]->(d)
				`, event.AssetID, event.Domain))
			}
		}

		// 5. Upsert MITRE Technique node
		if event.MitreTechnique != "" {
			queries = append(queries, fmt.Sprintf(`
				MERGE (t:MITRETechnique {id: '%s'})
				SET t.tactic = '%s'
			`, event.MitreTechnique, event.MitreTactic))

			if event.AssetID != "" {
				queries = append(queries, fmt.Sprintf(`
					MATCH (a:Asset {id: '%s'}), (t:MITRETechnique {id: '%s'})
					MERGE (a)-[:EXPLOITED_BY]->(t)
				`, event.AssetID, event.MitreTechnique))
			}
		}

		// 6. Create Event node
		queries = append(queries, fmt.Sprintf(`
			MERGE (e:Event {id: '%s'})
			SET e.source = '%s',
			    e.type = '%s',
			    e.severity = '%s',
			    e.confidence = %d,
			    e.risk_score = %d,
			    e.timestamp = datetime('%s')
		`, event.EventID, event.Source, event.EventType, event.Severity,
			event.Confidence, event.RiskScore, event.Timestamp))

		// 7. Link Event to Asset
		if event.AssetID != "" {
			queries = append(queries, fmt.Sprintf(`
				MATCH (a:Asset {id: '%s'}), (e:Event {id: '%s'})
				MERGE (a)-[:HAS_EVENT]->(e)
			`, event.AssetID, event.EventID))
		}

		// Execute all queries
		for _, q := range queries {
			if _, err := tx.Run(q, nil); err != nil {
				return nil, fmt.Errorf("query failed: %w\nQuery: %s", err, q)
			}
		}

		// Track node/edge creation
		if event.AssetID != "" {
			graphNodesCreated.WithLabelValues("Asset").Inc()
		}
		if event.SourceIP != "" {
			graphNodesCreated.WithLabelValues("IPAddress").Inc()
		}
		if event.Domain != "" {
			graphNodesCreated.WithLabelValues("Domain").Inc()
		}
		if event.MitreTechnique != "" {
			graphNodesCreated.WithLabelValues("MITRETechnique").Inc()
		}
		graphNodesCreated.WithLabelValues("Event").Inc()

		return nil, nil
	})

	return err
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
