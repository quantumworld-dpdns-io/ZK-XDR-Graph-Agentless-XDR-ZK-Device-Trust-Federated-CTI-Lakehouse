package config

import (
	"os"
	"strconv"
)

type Config struct {
	GoEnv     string
	GoPort    string
	GoLogLevel string

	PostgresHost     string
	PostgresPort     string
	PostgresUser     string
	PostgresPassword string
	PostgresDB       string
	PostgresSSLMode  string

	RedisHost     string
	RedisPort     string
	RedisPassword string

	Neo4jURI      string
	Neo4jUser     string
	Neo4jPassword string

	ClickhouseHost string
	ClickhousePort string

	MinioEndpoint  string
	MinioAccessKey string
	MinioSecretKey string
	MinioUseSSL    bool

	QdrantHost       string
	QdrantPort       string
	QdrantAPIKey     string
	QdrantCollection string

	JWTSecret      string
	JWTIssuer      string
	JWTExpiryHours int

	NoirProverURL    string
	NoirProverAPIKey string

	Risc0ProverURL    string
	Risc0ProverAPIKey string

	JuliaAnalysisURL    string
	JuliaAnalysisAPIKey string
}

func Load() *Config {
	return &Config{
		GoEnv:      getEnv("GO_ENV", "development"),
		GoPort:     getEnv("GO_PORT", "8080"),
		GoLogLevel: getEnv("GO_LOG_LEVEL", "debug"),

		PostgresHost:     getEnv("POSTGRES_HOST", "localhost"),
		PostgresPort:     getEnv("POSTGRES_PORT", "5432"),
		PostgresUser:     getEnv("POSTGRES_USER", "zdxdr"),
		PostgresPassword: getEnv("POSTGRES_PASSWORD", "changeme"),
		PostgresDB:       getEnv("POSTGRES_DB", "zdxdr"),
		PostgresSSLMode:  getEnv("POSTGRES_SSLMODE", "disable"),

		RedisHost:     getEnv("REDIS_HOST", "localhost"),
		RedisPort:     getEnv("REDIS_PORT", "6379"),
		RedisPassword: getEnv("REDIS_PASSWORD", ""),

		Neo4jURI:      getEnv("NEO4J_URI", "bolt://localhost:7687"),
		Neo4jUser:     getEnv("NEO4J_USER", "neo4j"),
		Neo4jPassword: getEnv("NEO4J_PASSWORD", "changeme"),

		ClickhouseHost: getEnv("CLICKHOUSE_HOST", "localhost"),
		ClickhousePort: getEnv("CLICKHOUSE_PORT", "8123"),

		MinioEndpoint:  getEnv("MINIO_ENDPOINT", "localhost:9000"),
		MinioAccessKey: getEnv("MINIO_ACCESS_KEY", "minioadmin"),
		MinioSecretKey: getEnv("MINIO_SECRET_KEY", "minioadmin"),
		MinioUseSSL:    getEnvBool("MINIO_USE_SSL", false),

		QdrantHost:       getEnv("QDRANT_HOST", "localhost"),
		QdrantPort:       getEnv("QDRANT_PORT", "6333"),
		QdrantAPIKey:     getEnv("QDRANT_API_KEY", ""),
		QdrantCollection: getEnv("QDRANT_COLLECTION", "xdr_events"),

		JWTSecret:      getEnv("JWT_SECRET", "change-me-in-production"),
		JWTIssuer:      getEnv("JWT_ISSUER", "zk-xdr-graph"),
		JWTExpiryHours: getEnvInt("JWT_EXPIRY_HOURS", 24),

		NoirProverURL:    getEnv("NOIR_PROVER_URL", "http://localhost:3001"),
		NoirProverAPIKey: getEnv("NOIR_PROVER_API_KEY", ""),

		Risc0ProverURL:    getEnv("RISC0_PROVER_URL", "http://localhost:3002"),
		Risc0ProverAPIKey: getEnv("RISC0_PROVER_API_KEY", ""),

		JuliaAnalysisURL:    getEnv("JULIA_ANALYSIS_URL", "http://localhost:8090"),
		JuliaAnalysisAPIKey: getEnv("JULIA_ANALYSIS_API_KEY", ""),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if i, err := strconv.Atoi(value); err == nil {
			return i
		}
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if b, err := strconv.ParseBool(value); err == nil {
			return b
		}
	}
	return defaultValue
}
