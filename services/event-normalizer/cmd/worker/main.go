package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/quantumworld-dpdns-io/zk-xdr-graph-platform/services/event-normalizer/internal/config"
	"github.com/quantumworld-dpdns-io/zk-xdr-graph-platform/services/event-normalizer/internal/normalizer"
)

func main() {
	cfg := config.Load()

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})))

	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisHost + ":" + cfg.RedisPort,
		Password: cfg.RedisPassword,
		DB:       0,
	})
	defer rdb.Close()

	ctx := context.Background()

	err := rdb.XGroupCreateMkStream(ctx, cfg.StreamKey, cfg.ConsumerGroup, "0").Err()
	if err != nil && err.Error() != "BUSYGROUP Consumer Group name already exists" {
		slog.Error("failed to create consumer group", "error", err)
		os.Exit(1)
	}
	slog.Info("connected to redis", "stream", cfg.StreamKey, "group", cfg.ConsumerGroup)

	factory := normalizer.NewNormalizerFactory()

	slog.Info("starting event normalizer", "consumer", cfg.ConsumerName)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		for {
			select {
			case <-quit:
				return
			default:
				streams, err := rdb.XReadGroup(ctx, &redis.XReadGroupArgs{
					Group:    cfg.ConsumerGroup,
					Consumer: cfg.ConsumerName,
					Streams:  []string{cfg.StreamKey, ">"},
					Count:    cfg.BatchSize,
					Block:    time.Duration(cfg.BlockTimeout) * time.Millisecond,
				}).Result()

				if err != nil {
					if err == redis.Nil || err == context.DeadlineExceeded {
						continue
					}
					slog.Error("failed to read from stream", "error", err)
					time.Sleep(time.Second)
					continue
				}

				for _, stream := range streams {
					for _, msg := range stream.Messages {
						processMessage(ctx, rdb, factory, cfg, msg)
					}
				}
			}
		}
	}()

	<-quit
	slog.Info("shutting down event normalizer...")
}

func processMessage(ctx context.Context, rdb *redis.Client, factory *normalizer.NormalizerFactory, cfg *config.Config, msg redis.XMessage) {
	data, ok := msg.Values["data"].(string)
	if !ok {
		slog.Error("invalid message format", "msg_id", msg.ID)
		return
	}

	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(data), &raw); err != nil {
		slog.Error("failed to parse event data", "error", err, "msg_id", msg.ID)
		return
	}

	source, _ := raw["source"].(string)
	if source == "" {
		source = "endpoint"
	}

	evt, err := factory.Normalize(source, raw)
	if err != nil {
		slog.Error("failed to normalize event", "error", err, "source", source, "msg_id", msg.ID)
		return
	}

	normalizedJSON, _ := json.Marshal(evt)

	err = rdb.XAdd(ctx, &redis.XAddArgs{
		Stream: "xdr.events.normalized",
		Values: map[string]interface{}{
			"event_id":    evt.EventID,
			"source":      evt.Source,
			"event_type":  evt.EventType,
			"severity":    evt.Severity,
			"risk_score":  fmt.Sprintf("%.2f", evt.Risk.Score),
			"data":        string(normalizedJSON),
		},
	}).Err()

	if err != nil {
		slog.Error("failed to publish normalized event", "error", err, "event_id", evt.EventID)
		return
	}

	slog.Info("normalized event",
		"event_id", evt.EventID,
		"source", evt.Source,
		"event_type", evt.EventType,
		"severity", evt.Severity,
		"risk_score", evt.Risk.Score,
	)

	rdb.XAck(ctx, cfg.StreamKey, cfg.ConsumerGroup, msg.ID)
}
