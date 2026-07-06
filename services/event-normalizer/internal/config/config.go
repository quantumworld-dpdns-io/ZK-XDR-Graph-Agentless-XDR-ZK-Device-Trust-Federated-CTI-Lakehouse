package config

import (
	"os"
	"strconv"
)

type Config struct {
	GoEnv      string
	GoLogLevel string

	RedisHost     string
	RedisPort     string
	RedisPassword string

	ClickhouseHost string
	ClickhousePort string

	StreamKey    string
	ConsumerGroup string
	ConsumerName  string
	BatchSize     int64
	BlockTimeout  int64
}

func Load() *Config {
	return &Config{
		GoEnv:      getEnv("GO_ENV", "development"),
		GoLogLevel: getEnv("GO_LOG_LEVEL", "debug"),

		RedisHost:     getEnv("REDIS_HOST", "localhost"),
		RedisPort:     getEnv("REDIS_PORT", "6379"),
		RedisPassword: getEnv("REDIS_PASSWORD", ""),

		ClickhouseHost: getEnv("CLICKHOUSE_HOST", "localhost"),
		ClickhousePort: getEnv("CLICKHOUSE_PORT", "8123"),

		StreamKey:    getEnv("STREAM_KEY", "xdr.events"),
		ConsumerGroup: getEnv("CONSUMER_GROUP", "normalizers"),
		ConsumerName:  getEnv("CONSUMER_NAME", "event-normalizer-1"),
		BatchSize:     getEnvInt64("BATCH_SIZE", 10),
		BlockTimeout:  getEnvInt64("BLOCK_TIMEOUT_MS", 5000),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt64(key string, defaultValue int64) int64 {
	if value := os.Getenv(key); value != "" {
		if i, err := strconv.ParseInt(value, 10, 64); err == nil {
			return i
		}
	}
	return defaultValue
}
