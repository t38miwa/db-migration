.PHONY: up down connect migrate-diff migrate-apply migrate-status schema-diff schema-inspect migrate-lint

# Docker operations
up:
	docker compose up -d

down:
	docker compose down

connect:
	docker compose exec postgres psql -U user -d migration_db

schema-diff:
	atlas schema diff --env local --to file://schema.sql

migrate-diff:
	atlas migrate diff $(name) --env local

migrate-apply:
	atlas migrate apply --env local

migrate-status:
	atlas migrate status --env local

schema-inspect:
	atlas schema inspect --env local

migrate-lint:
	atlas migrate lint --env local