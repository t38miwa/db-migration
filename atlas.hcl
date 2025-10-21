env "local" {
  dev = "docker://postgres/17/dev"
  src = "file://schema.sql"
  url = "postgres://user:password@localhost:5434/migration_db?sslmode=disable"

  migration {
    dir = "file://migrations"
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
  url = getenv("DATABASE_URL")
  migration {
    dir = "file://migrations"
  }
}