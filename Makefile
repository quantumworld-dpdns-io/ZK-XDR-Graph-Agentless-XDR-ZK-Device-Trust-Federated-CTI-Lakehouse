.PHONY: help up down build test lint seed demo-attack clean setup

# Default target
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# Setup
setup: ## Initial project setup
	cp .env.example .env 2>/dev/null || true
	cd apps/api-gateway && go mod init github.com/quantumworld-dpdns-io/zk-xdr-graph-platform/apps/api-gateway && go mod tidy
	cd services/event-normalizer && go mod init github.com/quantumworld-dpdns-io/zk-xdr-graph-platform/services/event-normalizer && go mod tidy
	cd services/asset-risk-graph && go mod init github.com/quantumworld-dpdns-io/zk-xdr-graph-platform/services/asset-risk-graph && go mod tidy
	cd services/correlation-engine && go mod init github.com/quantumworld-dpdns-io/zk-xdr-graph-platform/services/correlation-engine && go mod tidy
	cd services/soar-playbook-engine && go mod init github.com/quantumworld-dpdns-io/zk-xdr-graph-platform/services/soar-playbook-engine && go mod tidy
	cd services/ddi-connector && go mod init github.com/quantumworld-dpdns-io/zk-xdr-graph-platform/services/ddi-connector && go mod tidy
	cd services/waf-api-connector && go mod init github.com/quantumworld-dpdns-io/zk-xdr-graph-platform/services/waf-api-connector && go mod tidy
	cd services/mail-threat-connector && go mod init github.com/quantumworld-dpdns-io/zk-xdr-graph-platform/services/mail-threat-connector && go mod tidy
	cd apps/console-web && npm install

# Docker
up: ## Start local development stack
	docker compose -f infra/docker-compose.local.yml up --build -d

down: ## Stop local development stack
	docker compose -f infra/docker-compose.local.yml down

logs: ## Follow logs
	docker compose -f infra/docker-compose.local.yml logs -f

# Build
build: build-api build-frontend ## Build all services

build-api: ## Build Go API gateway
	cd apps/api-gateway && go build -o ../../dist/api-gateway ./cmd/server

build-frontend: ## Build Next.js console
	cd apps/console-web && npm run build

# Test
test: test-api test-frontend ## Run all tests

test-api: ## Run Go tests
	cd apps/api-gateway && go test ./... -race -cover -count=1

test-frontend: ## Run frontend tests
	cd apps/console-web && npm test

# Lint
lint: lint-api lint-frontend ## Run all linters

lint-api: ## Lint Go code
	cd apps/api-gateway && golangci-lint run ./...

lint-frontend: ## Lint frontend code
	cd apps/console-web && npm run lint

# Database
seed: ## Seed demo data
	docker compose -f infra/docker-compose.local.yml exec api-gateway /app/seed

migrate: ## Run database migrations
	docker compose -f infra/docker-compose.local.yml exec api-gateway /app/migrate

# Demo
seed-demo: ## Seed demo attack scenario
	python3 examples/attack-scenarios/generate_demo_events.py

demo-attack: ## Generate demo incident
	python3 examples/attack-scenarios/run_demo_attack.py

# Clean
clean: ## Clean build artifacts
	rm -rf dist/ target/ .next/ out/ node_modules/
	cd apps/api-gateway && go clean
	cd apps/console-web && rm -rf .next out
