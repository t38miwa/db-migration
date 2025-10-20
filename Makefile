DB_URL := postgres://user:password@localhost:5434/migration_db?sslmode=disable

.PHONY: up down connect migrate-diff migrate-apply migrate-apply-dry-run migrate-status migrate-down migrate-down-dry-run migrate-hash schema-diff schema-inspect migrate-lint

# Docker operations
up:
	docker compose up -d

down:
	docker compose down

connect:
	docker compose exec postgres psql -U user -d migration_db

# atlas
#現状のローカルDBと、schema.sqlとの差分を調べるコマンド
schema-diff:
	atlas schema diff --env local --from ${DB_URL} --to file://schema.sql

migrate-diff:
	atlas migrate diff $(name) --env local

migrate-apply:
	atlas migrate apply --env local

migrate-apply-dry-run:
	atlas migrate apply --dry-run --env local

migrate-status:
	atlas migrate status --env local

migrate-down:
	atlas migrate down $(amount) --env local

migrate-down-dry-run:
	atlas migrate down $(amount) --dry-run --env local

migrate-hash:
	atlas migrate hash --env local

schema-inspect:
	atlas schema inspect --env local

migrate-lint:
	atlas migrate lint --latest 1 --env local

visualize-schema:
	atlas schema inspect -u ${DB_URL} -w

# sqruff
lint: ## sqruffでlint
	sqruff lint schema.sql
	
format: ## sqruffでフォーマット
	sqruff fix schema.sql