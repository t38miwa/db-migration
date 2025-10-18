.PHONY: up down

up:
	docker compose up -d

down:
	docker compose down

connect:
	docker compose exec postgres psql -U user -d migration_db