env "local" {
  dev = "docker://postgres/17/dev"
  src = "file://schema.sql"
  url = "postgres://user:password@localhost:5434/migration_db?sslmode=disable"

  migration {
    dir = "file://migrations"
    baseline = "20251022040505"
  }
  format {
    migrate {
      diff = "{{ sql . \"  \" }}"
    }
  }
}

env "ci" {
  dev = "docker://postgres/17/dev"
  src = "file://schema.sql"
  url = "postgres://user:password@localhost:5435/migration_db?sslmode=disable"

  migration {
    dir = "file://migrations"
  }
  format {
    migrate {
      diff = "{{ sql . \"  \" }}"
    }
  }
}

env "production" {
  dev = "docker://postgres/17/dev"
  url = getenv("DATABASE_URL")
  migration {
    dir = "file://migrations"
    revisions_schema = "public"
    baseline = "20251022040505"
  }
}