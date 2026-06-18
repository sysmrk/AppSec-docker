COMPOSE ?= docker-compose
COMPOSE_FILE ?= docker-compose.yaml
PROFILE ?= platform

.PHONY: help preflight init migrate up down restart ps logs build report-metabase trivy-db clean

help:
	@printf '%s\n' \
		'AppSec commands:' \
		'  make preflight        Check host requirements and ports' \
		'  make init             Start core services and initialize database' \
		'  make migrate          Run database migrations' \
		'  make up               Start platform profile' \
		'  make down             Stop platform services' \
		'  make restart          Restart platform services' \
		'  make ps               Show service status' \
		'  make logs             Tail service logs' \
		'  make build            Build runner/API images' \
		'  make report-metabase  Provision Metabase dashboards' \
		'  make trivy-db         Update Trivy vulnerability database'

preflight:
	./scripts/preflight.sh

init: preflight
	$(COMPOSE) -f $(COMPOSE_FILE) --profile $(PROFILE) up -d postgres buildkit minio minio-init api nginx worker scheduler grafana metabase
	./scripts/appsecctl.sh migrate
	./scripts/setup-metabase.sh

migrate:
	./scripts/appsecctl.sh migrate

up:
	$(COMPOSE) -f $(COMPOSE_FILE) --profile $(PROFILE) up -d postgres buildkit minio minio-init api nginx worker scheduler grafana metabase

down:
	./scripts/down.sh

restart: down up

ps:
	$(COMPOSE) -f $(COMPOSE_FILE) ps

logs:
	$(COMPOSE) -f $(COMPOSE_FILE) logs -f --tail=200

build:
	$(COMPOSE) -f $(COMPOSE_FILE) build api appsec-runner worker scheduler

report-metabase:
	./scripts/setup-metabase.sh

trivy-db:
	./scripts/update-trivy-db.sh --once

clean:
	find . -path './harbor/data/database' -prune -o -type d \( -name __pycache__ -o -name .pytest_cache -o -name .mypy_cache \) -exec rm -rf {} +
