.PHONY: help up down build test lint demo-e2e clean setup build-all test-all

# Default target
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# Setup
setup: ## Initial project setup
	cp .env.example .env 2>/dev/null || true
	cd apps/console-web && npm install

# Docker
up: ## Start local development stack
	docker compose -f infra/docker-compose.local.yml up --build -d

up-core: ## Start core services only (no workers)
	docker compose -f infra/docker-compose.local.yml up --build -d postgres redis neo4j clickhouse minio qdrant redpanda api-gateway console-web

down: ## Stop local development stack
	docker compose -f infra/docker-compose.local.yml down

logs: ## Follow all logs
	docker compose -f infra/docker-compose.local.yml logs -f

logs-core: ## Follow core service logs
	docker compose -f infra/docker-compose.local.yml logs -f api-gateway console-web postgres redis

status: ## Show service status
	docker compose -f infra/docker-compose.local.yml ps

# Build
build: build-api build-frontend ## Build all services

build-api: ## Build Go API gateway
	cd apps/api-gateway && go build -o ../../dist/api-gateway ./cmd/server

build-frontend: ## Build Next.js console
	cd apps/console-web && npm run build

build-all: ## Build all Go services
	cd apps/api-gateway && go build -o ../../dist/api-gateway ./cmd/server
	cd services/event-normalizer && go build -o ../../dist/event-normalizer ./cmd/worker
	cd services/risk-scoring && go build -o ../../dist/risk-scoring ./cmd/worker
	cd services/asset-graph && go build -o ../../dist/asset-graph ./cmd/worker
	cd services/correlation-engine && go build -o ../../dist/correlation-engine ./cmd/worker
	cd services/soar-playbook && go build -o ../../dist/soar-playbook ./cmd/worker
	cd services/connectors/ddi && go build -o ../../../dist/connector-ddi ./cmd/connector
	cd services/connectors/waf && go build -o ../../../dist/connector-waf ./cmd/connector
	cd services/connectors/mail && go build -o ../../../dist/connector-mail ./cmd/connector

# Test
test: test-api test-frontend ## Run all tests

test-api: ## Run Go API tests
	cd apps/api-gateway && go test ./... -race -cover -count=1

test-frontend: ## Run frontend tests
	cd apps/console-web && npm test

test-noir: ## Run Noir circuit tests
	cd circuits && nargo test

test-all: test-api test-frontend test-noir ## Run all tests

# Lint
lint: lint-api lint-frontend ## Run all linters

lint-api: ## Lint Go code
	cd apps/api-gateway && go vet ./...

lint-frontend: ## Lint frontend code
	cd apps/console-web && npm run lint

# Demo
demo-e2e: ## Run end-to-end attack demo
	python3 examples/demo_e2e.py

demo-attack: ## Run original demo attack
	python3 examples/attack-scenarios/run_demo_attack.py

demo-generate: ## Generate demo events
	python3 examples/attack-scenarios/generate_demo_events.py

# Integration health checks
health: ## Check all service health endpoints
	@echo "Checking API Gateway..."
	@curl -sf http://localhost:8080/api/v1/health || echo "  DOWN"
	@echo "Checking CTI Lakehouse..."
	@curl -sf http://localhost:8095/api/v1/health || echo "  DOWN"
	@echo "Checking Analyst Copilot..."
	@curl -sf http://localhost:8090/api/v1/health || echo "  DOWN"
	@echo "Checking IoC Parsers..."
	@curl -sf http://localhost:8085/api/v1/health || echo "  DOWN"
	@echo "Checking Anomaly Detection..."
	@curl -sf http://localhost:8086/api/v1/health || echo "  DOWN"
	@echo "Checking Neo4j..."
	@curl -sf http://localhost:7474 || echo "  DOWN"
	@echo "Checking ClickHouse..."
	@curl -sf http://localhost:8123/ping || echo "  DOWN"
	@echo "Checking Redis..."
	@redis-cli -h localhost -p 6379 ping 2>/dev/null || echo "  DOWN"
	@echo "Checking Frontend..."
	@curl -sf http://localhost:3000 || echo "  DOWN"

# Clean
clean: ## Clean build artifacts
	rm -rf dist/ target/ .next/ out/ node_modules/
	cd apps/api-gateway && go clean
	cd apps/console-web && rm -rf .next out
