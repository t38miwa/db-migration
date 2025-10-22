env "local" {
  dev = "docker://postgres/17/dev"
  src = "file://schema.sql"
  url = "postgres://user:password@localhost:5434/migration_db?sslmode=disable"
  schemas = ["public"]

  migration {
    dir = "file://migrations"
    revisions_schema = "public"
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
  schemas = ["public"]

  migration {
    dir = "file://migrations"
    revisions_schema = "public"
  }
  format {
    migrate {
      diff = "{{ sql . \"  \" }}"
    }
  }
}

env "production" {
  dev = "docker://postgres/17/dev"
  src = "file://schema.sql"
  url = getenv("DATABASE_URL")
  schemas = ["public"]
  migration {
    dir = "file://migrations"
    revisions_schema = "public"
  }
  format {
    migrate {
      diff = "{{ sql . \"  \" }}"
    }
  }
}