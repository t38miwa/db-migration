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