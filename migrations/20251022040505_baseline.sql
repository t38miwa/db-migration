-- Add new schema named "auth"
CREATE SCHEMA "auth";
-- Add new schema named "extensions"
CREATE SCHEMA "extensions";
-- Add new schema named "graphql"
CREATE SCHEMA "graphql";
-- Add new schema named "graphql_public"
CREATE SCHEMA "graphql_public";
-- Add new schema named "pgbouncer"
CREATE SCHEMA "pgbouncer";
-- Add new schema named "realtime"
CREATE SCHEMA "realtime";
-- Add new schema named "storage"
CREATE SCHEMA "storage";
-- Add new schema named "vault"
CREATE SCHEMA "vault";
-- Create extension "uuid-ossp"
CREATE EXTENSION "uuid-ossp" WITH SCHEMA "extensions" VERSION "1.1";
-- Create extension "supabase_vault"
CREATE EXTENSION "supabase_vault" WITH SCHEMA "vault" VERSION "0.3.1";
-- Create extension "pgcrypto"
CREATE EXTENSION "pgcrypto" WITH SCHEMA "extensions" VERSION "1.3";
-- Create extension "pg_stat_statements"
CREATE EXTENSION "pg_stat_statements" WITH SCHEMA "extensions" VERSION "1.11";
-- Create extension "pg_graphql"
CREATE EXTENSION "pg_graphql" WITH SCHEMA "graphql" VERSION "1.5.11";
-- Create enum type "buckettype"
CREATE TYPE "storage"."buckettype" AS ENUM ('STANDARD', 'ANALYTICS');
-- Create "buckets" table
CREATE TABLE "storage"."buckets" (
  "id" text NOT NULL,
  "name" text NOT NULL,
  "owner" uuid NULL,
  "created_at" timestamptz NULL DEFAULT now(),
  "updated_at" timestamptz NULL DEFAULT now(),
  "public" boolean NULL DEFAULT false,
  "avif_autodetection" boolean NULL DEFAULT false,
  "file_size_limit" bigint NULL,
  "allowed_mime_types" text[] NULL,
  "owner_id" text NULL,
  "type" "storage"."buckettype" NOT NULL DEFAULT 'STANDARD',
  PRIMARY KEY ("id")
);
-- Create index "bname" to table: "buckets"
CREATE UNIQUE INDEX "bname" ON "storage"."buckets" ("name");
-- Set comment to column: "owner" on table: "buckets"
COMMENT ON COLUMN "storage"."buckets"."owner" IS 'Field is deprecated, use owner_id instead';
-- Enable row-level security for "buckets" table
ALTER TABLE "storage"."buckets" ENABLE ROW LEVEL SECURITY;
-- Create "objects" table
CREATE TABLE "storage"."objects" (
  "id" uuid NOT NULL DEFAULT gen_random_uuid(),
  "bucket_id" text NULL,
  "name" text NULL,
  "owner" uuid NULL,
  "created_at" timestamptz NULL DEFAULT now(),
  "updated_at" timestamptz NULL DEFAULT now(),
  "last_accessed_at" timestamptz NULL DEFAULT now(),
  "metadata" jsonb NULL,
  "path_tokens" text[] NULL GENERATED ALWAYS AS (string_to_array(name, '/'::text)) STORED,
  "version" text NULL,
  "owner_id" text NULL,
  "user_metadata" jsonb NULL,
  "level" integer NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "objects_bucketId_fkey" FOREIGN KEY ("bucket_id") REFERENCES "storage"."buckets" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION
);
-- Create index "bucketid_objname" to table: "objects"
CREATE UNIQUE INDEX "bucketid_objname" ON "storage"."objects" ("bucket_id", "name");
-- Create index "idx_name_bucket_level_unique" to table: "objects"
CREATE UNIQUE INDEX "idx_name_bucket_level_unique" ON "storage"."objects" ("name", "bucket_id", "level");
-- Create index "idx_objects_bucket_id_name" to table: "objects"
CREATE INDEX "idx_objects_bucket_id_name" ON "storage"."objects" ("bucket_id", "name");
-- Create index "idx_objects_lower_name" to table: "objects"
CREATE INDEX "idx_objects_lower_name" ON "storage"."objects" ((path_tokens[level]), (lower(name)) text_pattern_ops, "bucket_id", "level");
-- Create index "name_prefix_search" to table: "objects"
CREATE INDEX "name_prefix_search" ON "storage"."objects" ("name" text_pattern_ops);
-- Create index "objects_bucket_id_level_idx" to table: "objects"
CREATE UNIQUE INDEX "objects_bucket_id_level_idx" ON "storage"."objects" ("bucket_id", "level", "name");
-- Set comment to column: "owner" on table: "objects"
COMMENT ON COLUMN "storage"."objects"."owner" IS 'Field is deprecated, use owner_id instead';
-- Enable row-level security for "objects" table
ALTER TABLE "storage"."objects" ENABLE ROW LEVEL SECURITY;
-- Create "get_size_by_bucket" function
CREATE FUNCTION "storage"."get_size_by_bucket" () RETURNS TABLE ("size" bigint, "bucket_id" text) LANGUAGE plpgsql STABLE AS $$
BEGIN
    return query
        select sum((metadata->>'size')::bigint) as size, obj.bucket_id
        from "storage".objects as obj
        group by obj.bucket_id;
END
$$;
-- Create "s3_multipart_uploads" table
CREATE TABLE "storage"."s3_multipart_uploads" (
  "id" text NOT NULL,
  "in_progress_size" bigint NOT NULL DEFAULT 0,
  "upload_signature" text NOT NULL,
  "bucket_id" text NOT NULL,
  "key" text NOT NULL COLLATE "C",
  "version" text NOT NULL,
  "owner_id" text NULL,
  "created_at" timestamptz NOT NULL DEFAULT now(),
  "user_metadata" jsonb NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "s3_multipart_uploads_bucket_id_fkey" FOREIGN KEY ("bucket_id") REFERENCES "storage"."buckets" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION
);
-- Create index "idx_multipart_uploads_list" to table: "s3_multipart_uploads"
CREATE INDEX "idx_multipart_uploads_list" ON "storage"."s3_multipart_uploads" ("bucket_id", "key", "created_at");
-- Enable row-level security for "s3_multipart_uploads" table
ALTER TABLE "storage"."s3_multipart_uploads" ENABLE ROW LEVEL SECURITY;
-- Create "list_multipart_uploads_with_delimiter" function
CREATE FUNCTION "storage"."list_multipart_uploads_with_delimiter" ("bucket_id" text, "prefix_param" text, "delimiter_param" text, "max_keys" integer DEFAULT 100, "next_key_token" text DEFAULT '', "next_upload_token" text DEFAULT '') RETURNS TABLE ("key" text, "id" text, "created_at" timestamptz) LANGUAGE plpgsql AS $$
BEGIN
    RETURN QUERY EXECUTE
        'SELECT DISTINCT ON(key COLLATE "C") * from (
            SELECT
                CASE
                    WHEN position($2 IN substring(key from length($1) + 1)) > 0 THEN
                        substring(key from 1 for length($1) + position($2 IN substring(key from length($1) + 1)))
                    ELSE
                        key
                END AS key, id, created_at
            FROM
                storage.s3_multipart_uploads
            WHERE
                bucket_id = $5 AND
                key ILIKE $1 || ''%'' AND
                CASE
                    WHEN $4 != '''' AND $6 = '''' THEN
                        CASE
                            WHEN position($2 IN substring(key from length($1) + 1)) > 0 THEN
                                substring(key from 1 for length($1) + position($2 IN substring(key from length($1) + 1))) COLLATE "C" > $4
                            ELSE
                                key COLLATE "C" > $4
                            END
                    ELSE
                        true
                END AND
                CASE
                    WHEN $6 != '''' THEN
                        id COLLATE "C" > $6
                    ELSE
                        true
                    END
            ORDER BY
                key COLLATE "C" ASC, created_at ASC) as e order by key COLLATE "C" LIMIT $3'
        USING prefix_param, delimiter_param, max_keys, next_key_token, bucket_id, next_upload_token;
END;
$$;
-- Create "set_graphql_placeholder" function
CREATE FUNCTION "extensions"."set_graphql_placeholder" () RETURNS event_trigger LANGUAGE plpgsql AS $BODY$
DECLARE
    graphql_is_dropped bool;
    BEGIN
    graphql_is_dropped = (
        SELECT ev.schema_name = 'graphql_public'
        FROM pg_event_trigger_dropped_objects() AS ev
        WHERE ev.schema_name = 'graphql_public'
    );

    IF graphql_is_dropped
    THEN
        create or replace function graphql_public.graphql(
            "operationName" text default null,
            query text default null,
            variables jsonb default null,
            extensions jsonb default null
        )
            returns jsonb
            language plpgsql
        as $$
            DECLARE
                server_version float;
            BEGIN
                server_version = (SELECT (SPLIT_PART((select version()), ' ', 2))::float);

                IF server_version >= 14 THEN
                    RETURN jsonb_build_object(
                        'errors', jsonb_build_array(
                            jsonb_build_object(
                                'message', 'pg_graphql extension is not enabled.'
                            )
                        )
                    );
                ELSE
                    RETURN jsonb_build_object(
                        'errors', jsonb_build_array(
                            jsonb_build_object(
                                'message', 'pg_graphql is only available on projects running Postgres 14 onwards.'
                            )
                        )
                    );
                END IF;
            END;
        $$;
    END IF;

    END;
$BODY$;
-- Set comment to function: "set_graphql_placeholder"
COMMENT ON FUNCTION "extensions"."set_graphql_placeholder" IS 'Reintroduces placeholder function for graphql_public.graphql';
-- Create event trigger "issue_graphql_placeholder"
CREATE EVENT TRIGGER "issue_graphql_placeholder" ON sql_drop WHEN TAG IN ('DROP EXTENSION') EXECUTE FUNCTION "extensions"."set_graphql_placeholder"();
-- Create "grant_pg_cron_access" function
CREATE FUNCTION "extensions"."grant_pg_cron_access" () RETURNS event_trigger LANGUAGE plpgsql AS $$
BEGIN
  IF EXISTS (
    SELECT
    FROM pg_event_trigger_ddl_commands() AS ev
    JOIN pg_extension AS ext
    ON ev.objid = ext.oid
    WHERE ext.extname = 'pg_cron'
  )
  THEN
    grant usage on schema cron to postgres with grant option;

    alter default privileges in schema cron grant all on tables to postgres with grant option;
    alter default privileges in schema cron grant all on functions to postgres with grant option;
    alter default privileges in schema cron grant all on sequences to postgres with grant option;

    alter default privileges for user supabase_admin in schema cron grant all
        on sequences to postgres with grant option;
    alter default privileges for user supabase_admin in schema cron grant all
        on tables to postgres with grant option;
    alter default privileges for user supabase_admin in schema cron grant all
        on functions to postgres with grant option;

    grant all privileges on all tables in schema cron to postgres with grant option;
    revoke all on table cron.job from postgres;
    grant select on table cron.job to postgres with grant option;
  END IF;
END;
$$;
-- Set comment to function: "grant_pg_cron_access"
COMMENT ON FUNCTION "extensions"."grant_pg_cron_access" IS 'Grants access to pg_cron';
-- Create event trigger "issue_pg_cron_access"
CREATE EVENT TRIGGER "issue_pg_cron_access" ON ddl_command_end WHEN TAG IN ('CREATE EXTENSION') EXECUTE FUNCTION "extensions"."grant_pg_cron_access"();
-- Create "grant_pg_graphql_access" function
CREATE FUNCTION "extensions"."grant_pg_graphql_access" () RETURNS event_trigger LANGUAGE plpgsql AS $BODY$
DECLARE
    func_is_graphql_resolve bool;
BEGIN
    func_is_graphql_resolve = (
        SELECT n.proname = 'resolve'
        FROM pg_event_trigger_ddl_commands() AS ev
        LEFT JOIN pg_catalog.pg_proc AS n
        ON ev.objid = n.oid
    );

    IF func_is_graphql_resolve
    THEN
        -- Update public wrapper to pass all arguments through to the pg_graphql resolve func
        DROP FUNCTION IF EXISTS graphql_public.graphql;
        create or replace function graphql_public.graphql(
            "operationName" text default null,
            query text default null,
            variables jsonb default null,
            extensions jsonb default null
        )
            returns jsonb
            language sql
        as $$
            select graphql.resolve(
                query := query,
                variables := coalesce(variables, '{}'),
                "operationName" := "operationName",
                extensions := extensions
            );
        $$;

        -- This hook executes when `graphql.resolve` is created. That is not necessarily the last
        -- function in the extension so we need to grant permissions on existing entities AND
        -- update default permissions to any others that are created after `graphql.resolve`
        grant usage on schema graphql to postgres, anon, authenticated, service_role;
        grant select on all tables in schema graphql to postgres, anon, authenticated, service_role;
        grant execute on all functions in schema graphql to postgres, anon, authenticated, service_role;
        grant all on all sequences in schema graphql to postgres, anon, authenticated, service_role;
        alter default privileges in schema graphql grant all on tables to postgres, anon, authenticated, service_role;
        alter default privileges in schema graphql grant all on functions to postgres, anon, authenticated, service_role;
        alter default privileges in schema graphql grant all on sequences to postgres, anon, authenticated, service_role;

        -- Allow postgres role to allow granting usage on graphql and graphql_public schemas to custom roles
        grant usage on schema graphql_public to postgres with grant option;
        grant usage on schema graphql to postgres with grant option;
    END IF;

END;
$BODY$;
-- Set comment to function: "grant_pg_graphql_access"
COMMENT ON FUNCTION "extensions"."grant_pg_graphql_access" IS 'Grants access to pg_graphql';
-- Create event trigger "issue_pg_graphql_access"
CREATE EVENT TRIGGER "issue_pg_graphql_access" ON ddl_command_end WHEN TAG IN ('CREATE FUNCTION') EXECUTE FUNCTION "extensions"."grant_pg_graphql_access"();
-- Create "grant_pg_net_access" function
CREATE FUNCTION "extensions"."grant_pg_net_access" () RETURNS event_trigger LANGUAGE plpgsql AS $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM pg_event_trigger_ddl_commands() AS ev
    JOIN pg_extension AS ext
    ON ev.objid = ext.oid
    WHERE ext.extname = 'pg_net'
  )
  THEN
    IF NOT EXISTS (
      SELECT 1
      FROM pg_roles
      WHERE rolname = 'supabase_functions_admin'
    )
    THEN
      CREATE USER supabase_functions_admin NOINHERIT CREATEROLE LOGIN NOREPLICATION;
    END IF;

    GRANT USAGE ON SCHEMA net TO supabase_functions_admin, postgres, anon, authenticated, service_role;

    IF EXISTS (
      SELECT FROM pg_extension
      WHERE extname = 'pg_net'
      -- all versions in use on existing projects as of 2025-02-20
      -- version 0.12.0 onwards don't need these applied
      AND extversion IN ('0.2', '0.6', '0.7', '0.7.1', '0.8', '0.10.0', '0.11.0')
    ) THEN
      ALTER function net.http_get(url text, params jsonb, headers jsonb, timeout_milliseconds integer) SECURITY DEFINER;
      ALTER function net.http_post(url text, body jsonb, params jsonb, headers jsonb, timeout_milliseconds integer) SECURITY DEFINER;

      ALTER function net.http_get(url text, params jsonb, headers jsonb, timeout_milliseconds integer) SET search_path = net;
      ALTER function net.http_post(url text, body jsonb, params jsonb, headers jsonb, timeout_milliseconds integer) SET search_path = net;

      REVOKE ALL ON FUNCTION net.http_get(url text, params jsonb, headers jsonb, timeout_milliseconds integer) FROM PUBLIC;
      REVOKE ALL ON FUNCTION net.http_post(url text, body jsonb, params jsonb, headers jsonb, timeout_milliseconds integer) FROM PUBLIC;

      GRANT EXECUTE ON FUNCTION net.http_get(url text, params jsonb, headers jsonb, timeout_milliseconds integer) TO supabase_functions_admin, postgres, anon, authenticated, service_role;
      GRANT EXECUTE ON FUNCTION net.http_post(url text, body jsonb, params jsonb, headers jsonb, timeout_milliseconds integer) TO supabase_functions_admin, postgres, anon, authenticated, service_role;
    END IF;
  END IF;
END;
$$;
-- Set comment to function: "grant_pg_net_access"
COMMENT ON FUNCTION "extensions"."grant_pg_net_access" IS 'Grants access to pg_net';
-- Create event trigger "issue_pg_net_access"
CREATE EVENT TRIGGER "issue_pg_net_access" ON ddl_command_end WHEN TAG IN ('CREATE EXTENSION') EXECUTE FUNCTION "extensions"."grant_pg_net_access"();
-- Create "pgrst_ddl_watch" function
CREATE FUNCTION "extensions"."pgrst_ddl_watch" () RETURNS event_trigger LANGUAGE plpgsql AS $$
DECLARE
  cmd record;
BEGIN
  FOR cmd IN SELECT * FROM pg_event_trigger_ddl_commands()
  LOOP
    IF cmd.command_tag IN (
      'CREATE SCHEMA', 'ALTER SCHEMA'
    , 'CREATE TABLE', 'CREATE TABLE AS', 'SELECT INTO', 'ALTER TABLE'
    , 'CREATE FOREIGN TABLE', 'ALTER FOREIGN TABLE'
    , 'CREATE VIEW', 'ALTER VIEW'
    , 'CREATE MATERIALIZED VIEW', 'ALTER MATERIALIZED VIEW'
    , 'CREATE FUNCTION', 'ALTER FUNCTION'
    , 'CREATE TRIGGER'
    , 'CREATE TYPE', 'ALTER TYPE'
    , 'CREATE RULE'
    , 'COMMENT'
    )
    -- don't notify in case of CREATE TEMP table or other objects created on pg_temp
    AND cmd.schema_name is distinct from 'pg_temp'
    THEN
      NOTIFY pgrst, 'reload schema';
    END IF;
  END LOOP;
END;
$$;
-- Create event trigger "pgrst_ddl_watch"
CREATE EVENT TRIGGER "pgrst_ddl_watch" ON ddl_command_end EXECUTE FUNCTION "extensions"."pgrst_ddl_watch"();
-- Create "pgrst_drop_watch" function
CREATE FUNCTION "extensions"."pgrst_drop_watch" () RETURNS event_trigger LANGUAGE plpgsql AS $$
DECLARE
  obj record;
BEGIN
  FOR obj IN SELECT * FROM pg_event_trigger_dropped_objects()
  LOOP
    IF obj.object_type IN (
      'schema'
    , 'table'
    , 'foreign table'
    , 'view'
    , 'materialized view'
    , 'function'
    , 'trigger'
    , 'type'
    , 'rule'
    )
    AND obj.is_temporary IS false -- no pg_temp objects
    THEN
      NOTIFY pgrst, 'reload schema';
    END IF;
  END LOOP;
END;
$$;
-- Create event trigger "pgrst_drop_watch"
CREATE EVENT TRIGGER "pgrst_drop_watch" ON sql_drop EXECUTE FUNCTION "extensions"."pgrst_drop_watch"();
-- Create enum type "factor_type"
CREATE TYPE "auth"."factor_type" AS ENUM ('totp', 'webauthn', 'phone');
-- Create enum type "factor_status"
CREATE TYPE "auth"."factor_status" AS ENUM ('unverified', 'verified');
-- Create enum type "aal_level"
CREATE TYPE "auth"."aal_level" AS ENUM ('aal1', 'aal2', 'aal3');
-- Create enum type "code_challenge_method"
CREATE TYPE "auth"."code_challenge_method" AS ENUM ('s256', 'plain');
-- Create enum type "one_time_token_type"
CREATE TYPE "auth"."one_time_token_type" AS ENUM ('confirmation_token', 'reauthentication_token', 'recovery_token', 'email_change_token_new', 'email_change_token_current', 'phone_change_token');
-- Create enum type "oauth_registration_type"
CREATE TYPE "auth"."oauth_registration_type" AS ENUM ('dynamic', 'manual');
-- Create enum type "oauth_authorization_status"
CREATE TYPE "auth"."oauth_authorization_status" AS ENUM ('pending', 'approved', 'denied', 'expired');
-- Create enum type "oauth_response_type"
CREATE TYPE "auth"."oauth_response_type" AS ENUM ('code');
-- Create enum type "oauth_client_type"
CREATE TYPE "auth"."oauth_client_type" AS ENUM ('public', 'confidential');
-- Create "email" function
CREATE FUNCTION "auth"."email" () RETURNS text LANGUAGE sql STABLE AS $$
select 
  coalesce(
    nullif(current_setting('request.jwt.claim.email', true), ''),
    (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'email')
  )::text
$$;
-- Set comment to function: "email"
COMMENT ON FUNCTION "auth"."email" IS 'Deprecated. Use auth.jwt() -> ''email'' instead.';
-- Create "jwt" function
CREATE FUNCTION "auth"."jwt" () RETURNS jsonb LANGUAGE sql STABLE AS $$
select 
    coalesce(
        nullif(current_setting('request.jwt.claim', true), ''),
        nullif(current_setting('request.jwt.claims', true), '')
    )::jsonb
$$;
-- Create "role" function
CREATE FUNCTION "auth"."role" () RETURNS text LANGUAGE sql STABLE AS $$
select 
  coalesce(
    nullif(current_setting('request.jwt.claim.role', true), ''),
    (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'role')
  )::text
$$;
-- Set comment to function: "role"
COMMENT ON FUNCTION "auth"."role" IS 'Deprecated. Use auth.jwt() -> ''role'' instead.';
-- Create "uid" function
CREATE FUNCTION "auth"."uid" () RETURNS uuid LANGUAGE sql STABLE AS $$
select 
  coalesce(
    nullif(current_setting('request.jwt.claim.sub', true), ''),
    (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'sub')
  )::uuid
$$;
-- Set comment to function: "uid"
COMMENT ON FUNCTION "auth"."uid" IS 'Deprecated. Use auth.jwt() -> ''sub'' instead.';
-- Create "audit_log_entries" table
CREATE TABLE "auth"."audit_log_entries" (
  "instance_id" uuid NULL,
  "id" uuid NOT NULL,
  "payload" json NULL,
  "created_at" timestamptz NULL,
  "ip_address" character varying(64) NOT NULL DEFAULT '',
  PRIMARY KEY ("id")
);
-- Create index "audit_logs_instance_id_idx" to table: "audit_log_entries"
CREATE INDEX "audit_logs_instance_id_idx" ON "auth"."audit_log_entries" ("instance_id");
-- Set comment to table: "audit_log_entries"
COMMENT ON TABLE "auth"."audit_log_entries" IS 'Auth: Audit trail for user actions.';
-- Enable row-level security for "audit_log_entries" table
ALTER TABLE "auth"."audit_log_entries" ENABLE ROW LEVEL SECURITY;
-- Create "get_prefixes" function
CREATE FUNCTION "storage"."get_prefixes" ("name" text) RETURNS text[] LANGUAGE plpgsql STRICT IMMUTABLE AS $$
DECLARE
    parts text[];
    prefixes text[];
    prefix text;
BEGIN
    -- Split the name into parts by '/'
    parts := string_to_array("name", '/');
    prefixes := '{}';

    -- Construct the prefixes, stopping one level below the last part
    FOR i IN 1..array_length(parts, 1) - 1 LOOP
            prefix := array_to_string(parts[1:i], '/');
            prefixes := array_append(prefixes, prefix);
    END LOOP;

    RETURN prefixes;
END;
$$;
-- Create "get_level" function
CREATE FUNCTION "storage"."get_level" ("name" text) RETURNS integer LANGUAGE sql STRICT IMMUTABLE AS $$ SELECT array_length(string_to_array("name", '/'), 1); $$;
-- Create "prefixes" table
CREATE TABLE "storage"."prefixes" (
  "bucket_id" text NOT NULL,
  "name" text NOT NULL COLLATE "C",
  "level" integer NOT NULL GENERATED ALWAYS AS (storage.get_level(name)) STORED,
  "created_at" timestamptz NULL DEFAULT now(),
  "updated_at" timestamptz NULL DEFAULT now(),
  PRIMARY KEY ("bucket_id", "level", "name"),
  CONSTRAINT "prefixes_bucketId_fkey" FOREIGN KEY ("bucket_id") REFERENCES "storage"."buckets" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION
);
-- Create index "idx_prefixes_lower_name" to table: "prefixes"
CREATE INDEX "idx_prefixes_lower_name" ON "storage"."prefixes" ("bucket_id", "level", ((string_to_array(name, '/'::text))[level]), (lower(name)) text_pattern_ops);
-- Enable row-level security for "prefixes" table
ALTER TABLE "storage"."prefixes" ENABLE ROW LEVEL SECURITY;
-- Create "add_prefixes" function
CREATE FUNCTION "storage"."add_prefixes" ("_bucket_id" text, "_name" text) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
    prefixes text[];
BEGIN
    prefixes := "storage"."get_prefixes"("_name");

    IF array_length(prefixes, 1) > 0 THEN
        INSERT INTO storage.prefixes (name, bucket_id)
        SELECT UNNEST(prefixes) as name, "_bucket_id" ON CONFLICT DO NOTHING;
    END IF;
END;
$$;
-- Create "prefixes_insert_trigger" function
CREATE FUNCTION "storage"."prefixes_insert_trigger" () RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM "storage"."add_prefixes"(NEW."bucket_id", NEW."name");
    RETURN NEW;
END;
$$;
-- Create trigger "prefixes_create_hierarchy"
CREATE TRIGGER "prefixes_create_hierarchy" BEFORE INSERT ON "storage"."prefixes" FOR EACH ROW WHEN (pg_trigger_depth() < 1) EXECUTE FUNCTION "storage"."prefixes_insert_trigger"();
-- Create "delete_prefix" function
CREATE FUNCTION "storage"."delete_prefix" ("_bucket_id" text, "_name" text) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
    -- Check if we can delete the prefix
    IF EXISTS(
        SELECT FROM "storage"."prefixes"
        WHERE "prefixes"."bucket_id" = "_bucket_id"
          AND level = "storage"."get_level"("_name") + 1
          AND "prefixes"."name" COLLATE "C" LIKE "_name" || '/%'
        LIMIT 1
    )
    OR EXISTS(
        SELECT FROM "storage"."objects"
        WHERE "objects"."bucket_id" = "_bucket_id"
          AND "storage"."get_level"("objects"."name") = "storage"."get_level"("_name") + 1
          AND "objects"."name" COLLATE "C" LIKE "_name" || '/%'
        LIMIT 1
    ) THEN
    -- There are sub-objects, skip deletion
    RETURN false;
    ELSE
        DELETE FROM "storage"."prefixes"
        WHERE "prefixes"."bucket_id" = "_bucket_id"
          AND level = "storage"."get_level"("_name")
          AND "prefixes"."name" = "_name";
        RETURN true;
    END IF;
END;
$$;
-- Create "get_prefix" function
CREATE FUNCTION "storage"."get_prefix" ("name" text) RETURNS text LANGUAGE sql STRICT IMMUTABLE AS $$
SELECT
    CASE WHEN strpos("name", '/') > 0 THEN
             regexp_replace("name", '[\/]{1}[^\/]+\/?$', '')
         ELSE
             ''
        END;
$$;
-- Create "delete_prefix_hierarchy_trigger" function
CREATE FUNCTION "storage"."delete_prefix_hierarchy_trigger" () RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    prefix text;
BEGIN
    prefix := "storage"."get_prefix"(OLD."name");

    IF coalesce(prefix, '') != '' THEN
        PERFORM "storage"."delete_prefix"(OLD."bucket_id", prefix);
    END IF;

    RETURN OLD;
END;
$$;
-- Create trigger "prefixes_delete_hierarchy"
CREATE TRIGGER "prefixes_delete_hierarchy" AFTER DELETE ON "storage"."prefixes" FOR EACH ROW EXECUTE FUNCTION "storage"."delete_prefix_hierarchy_trigger"();
-- Create "instances" table
CREATE TABLE "auth"."instances" (
  "id" uuid NOT NULL,
  "uuid" uuid NULL,
  "raw_base_config" text NULL,
  "created_at" timestamptz NULL,
  "updated_at" timestamptz NULL,
  PRIMARY KEY ("id")
);
-- Set comment to table: "instances"
COMMENT ON TABLE "auth"."instances" IS 'Auth: Manages users across multiple sites.';
-- Enable row-level security for "instances" table
ALTER TABLE "auth"."instances" ENABLE ROW LEVEL SECURITY;
-- Create "update_updated_at_column" function
CREATE FUNCTION "storage"."update_updated_at_column" () RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW; 
END;
$$;
-- Create trigger "update_objects_updated_at"
CREATE TRIGGER "update_objects_updated_at" BEFORE UPDATE ON "storage"."objects" FOR EACH ROW EXECUTE FUNCTION "storage"."update_updated_at_column"();
-- Create "objects_update_prefix_trigger" function
CREATE FUNCTION "storage"."objects_update_prefix_trigger" () RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    old_prefixes TEXT[];
BEGIN
    -- Ensure this is an update operation and the name has changed
    IF TG_OP = 'UPDATE' AND (NEW."name" <> OLD."name" OR NEW."bucket_id" <> OLD."bucket_id") THEN
        -- Retrieve old prefixes
        old_prefixes := "storage"."get_prefixes"(OLD."name");

        -- Remove old prefixes that are only used by this object
        WITH all_prefixes as (
            SELECT unnest(old_prefixes) as prefix
        ),
        can_delete_prefixes as (
             SELECT prefix
             FROM all_prefixes
             WHERE NOT EXISTS (
                 SELECT 1 FROM "storage"."objects"
                 WHERE "bucket_id" = OLD."bucket_id"
                   AND "name" <> OLD."name"
                   AND "name" LIKE (prefix || '%')
             )
         )
        DELETE FROM "storage"."prefixes" WHERE name IN (SELECT prefix FROM can_delete_prefixes);

        -- Add new prefixes
        PERFORM "storage"."add_prefixes"(NEW."bucket_id", NEW."name");
    END IF;
    -- Set the new level
    NEW."level" := "storage"."get_level"(NEW."name");

    RETURN NEW;
END;
$$;
-- Create trigger "objects_update_create_prefix"
CREATE TRIGGER "objects_update_create_prefix" BEFORE UPDATE ON "storage"."objects" FOR EACH ROW WHEN ((new.name <> old.name) OR (new.bucket_id <> old.bucket_id)) EXECUTE FUNCTION "storage"."objects_update_prefix_trigger"();
-- Create "objects_insert_prefix_trigger" function
CREATE FUNCTION "storage"."objects_insert_prefix_trigger" () RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM "storage"."add_prefixes"(NEW."bucket_id", NEW."name");
    NEW.level := "storage"."get_level"(NEW."name");

    RETURN NEW;
END;
$$;
-- Create trigger "objects_insert_create_prefix"
CREATE TRIGGER "objects_insert_create_prefix" BEFORE INSERT ON "storage"."objects" FOR EACH ROW EXECUTE FUNCTION "storage"."objects_insert_prefix_trigger"();
-- Create trigger "objects_delete_delete_prefix"
CREATE TRIGGER "objects_delete_delete_prefix" AFTER DELETE ON "storage"."objects" FOR EACH ROW EXECUTE FUNCTION "storage"."delete_prefix_hierarchy_trigger"();
-- Create "migrations" table
CREATE TABLE "storage"."migrations" (
  "id" integer NOT NULL,
  "name" character varying(100) NOT NULL,
  "hash" character varying(40) NOT NULL,
  "executed_at" timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY ("id"),
  CONSTRAINT "migrations_name_key" UNIQUE ("name")
);
-- Enable row-level security for "migrations" table
ALTER TABLE "storage"."migrations" ENABLE ROW LEVEL SECURITY;
-- Create "buckets_analytics" table
CREATE TABLE "storage"."buckets_analytics" (
  "id" text NOT NULL,
  "type" "storage"."buckettype" NOT NULL DEFAULT 'ANALYTICS',
  "format" text NOT NULL DEFAULT 'ICEBERG',
  "created_at" timestamptz NOT NULL DEFAULT now(),
  "updated_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("id")
);
-- Enable row-level security for "buckets_analytics" table
ALTER TABLE "storage"."buckets_analytics" ENABLE ROW LEVEL SECURITY;
-- Create "enforce_bucket_name_length" function
CREATE FUNCTION "storage"."enforce_bucket_name_length" () RETURNS trigger LANGUAGE plpgsql AS $$
begin
    if length(new.name) > 100 then
        raise exception 'bucket name "%" is too long (% characters). Max is 100.', new.name, length(new.name);
    end if;
    return new;
end;
$$;
-- Create trigger "enforce_bucket_name_length_trigger"
CREATE TRIGGER "enforce_bucket_name_length_trigger" BEFORE INSERT OR UPDATE OF "name" ON "storage"."buckets" FOR EACH ROW EXECUTE FUNCTION "storage"."enforce_bucket_name_length"();
-- Create "cast" function
CREATE FUNCTION "realtime"."cast" ("val" text, "type_" regtype) RETURNS jsonb LANGUAGE plpgsql IMMUTABLE AS $$
declare
      res jsonb;
    begin
      execute format('select to_jsonb(%L::'|| type_::text || ')', val)  into res;
      return res;
    end
$$;
-- Create "search_v1_optimised" function
CREATE FUNCTION "storage"."search_v1_optimised" ("prefix" text, "bucketname" text, "limits" integer DEFAULT 100, "levels" integer DEFAULT 1, "offsets" integer DEFAULT 0, "search" text DEFAULT '', "sortcolumn" text DEFAULT 'name', "sortorder" text DEFAULT 'asc') RETURNS TABLE ("name" text, "id" uuid, "updated_at" timestamptz, "created_at" timestamptz, "last_accessed_at" timestamptz, "metadata" jsonb) LANGUAGE plpgsql STABLE AS $$
declare
    v_order_by text;
    v_sort_order text;
begin
    case
        when sortcolumn = 'name' then
            v_order_by = 'name';
        when sortcolumn = 'updated_at' then
            v_order_by = 'updated_at';
        when sortcolumn = 'created_at' then
            v_order_by = 'created_at';
        when sortcolumn = 'last_accessed_at' then
            v_order_by = 'last_accessed_at';
        else
            v_order_by = 'name';
        end case;

    case
        when sortorder = 'asc' then
            v_sort_order = 'asc';
        when sortorder = 'desc' then
            v_sort_order = 'desc';
        else
            v_sort_order = 'asc';
        end case;

    v_order_by = v_order_by || ' ' || v_sort_order;

    return query execute
        'with folders as (
           select (string_to_array(name, ''/''))[level] as name
           from storage.prefixes
             where lower(prefixes.name) like lower($2 || $3) || ''%''
               and bucket_id = $4
               and level = $1
           order by name ' || v_sort_order || '
     )
     (select name,
            null as id,
            null as updated_at,
            null as created_at,
            null as last_accessed_at,
            null as metadata from folders)
     union all
     (select path_tokens[level] as "name",
            id,
            updated_at,
            created_at,
            last_accessed_at,
            metadata
     from storage.objects
     where lower(objects.name) like lower($2 || $3) || ''%''
       and bucket_id = $4
       and level = $1
     order by ' || v_order_by || ')
     limit $5
     offset $6' using levels, prefix, search, bucketname, limits, offsets;
end;
$$;
-- Create "schema_migrations" table
CREATE TABLE "auth"."schema_migrations" (
  "version" character varying(255) NOT NULL,
  PRIMARY KEY ("version")
);
-- Set comment to table: "schema_migrations"
COMMENT ON TABLE "auth"."schema_migrations" IS 'Auth: Manages updates to the auth system.';
-- Enable row-level security for "schema_migrations" table
ALTER TABLE "auth"."schema_migrations" ENABLE ROW LEVEL SECURITY;
-- Create "search_legacy_v1" function
CREATE FUNCTION "storage"."search_legacy_v1" ("prefix" text, "bucketname" text, "limits" integer DEFAULT 100, "levels" integer DEFAULT 1, "offsets" integer DEFAULT 0, "search" text DEFAULT '', "sortcolumn" text DEFAULT 'name', "sortorder" text DEFAULT 'asc') RETURNS TABLE ("name" text, "id" uuid, "updated_at" timestamptz, "created_at" timestamptz, "last_accessed_at" timestamptz, "metadata" jsonb) LANGUAGE plpgsql STABLE AS $$
declare
    v_order_by text;
    v_sort_order text;
begin
    case
        when sortcolumn = 'name' then
            v_order_by = 'name';
        when sortcolumn = 'updated_at' then
            v_order_by = 'updated_at';
        when sortcolumn = 'created_at' then
            v_order_by = 'created_at';
        when sortcolumn = 'last_accessed_at' then
            v_order_by = 'last_accessed_at';
        else
            v_order_by = 'name';
        end case;

    case
        when sortorder = 'asc' then
            v_sort_order = 'asc';
        when sortorder = 'desc' then
            v_sort_order = 'desc';
        else
            v_sort_order = 'asc';
        end case;

    v_order_by = v_order_by || ' ' || v_sort_order;

    return query execute
        'with folders as (
           select path_tokens[$1] as folder
           from storage.objects
             where objects.name ilike $2 || $3 || ''%''
               and bucket_id = $4
               and array_length(objects.path_tokens, 1) <> $1
           group by folder
           order by folder ' || v_sort_order || '
     )
     (select folder as "name",
            null as id,
            null as updated_at,
            null as created_at,
            null as last_accessed_at,
            null as metadata from folders)
     union all
     (select path_tokens[$1] as "name",
            id,
            updated_at,
            created_at,
            last_accessed_at,
            metadata
     from storage.objects
     where objects.name ilike $2 || $3 || ''%''
       and bucket_id = $4
       and array_length(objects.path_tokens, 1) = $1
     order by ' || v_order_by || ')
     limit $5
     offset $6' using levels, prefix, search, bucketname, limits, offsets;
end;
$$;
-- Create "search" function
CREATE FUNCTION "storage"."search" ("prefix" text, "bucketname" text, "limits" integer DEFAULT 100, "levels" integer DEFAULT 1, "offsets" integer DEFAULT 0, "search" text DEFAULT '', "sortcolumn" text DEFAULT 'name', "sortorder" text DEFAULT 'asc') RETURNS TABLE ("name" text, "id" uuid, "updated_at" timestamptz, "created_at" timestamptz, "last_accessed_at" timestamptz, "metadata" jsonb) LANGUAGE plpgsql AS $$
declare
    can_bypass_rls BOOLEAN;
begin
    SELECT rolbypassrls
    INTO can_bypass_rls
    FROM pg_roles
    WHERE rolname = coalesce(nullif(current_setting('role', true), 'none'), current_user);

    IF can_bypass_rls THEN
        RETURN QUERY SELECT * FROM storage.search_v1_optimised(prefix, bucketname, limits, levels, offsets, search, sortcolumn, sortorder);
    ELSE
        RETURN QUERY SELECT * FROM storage.search_legacy_v1(prefix, bucketname, limits, levels, offsets, search, sortcolumn, sortorder);
    END IF;
end;
$$;
-- Create "users" table
CREATE TABLE "auth"."users" (
  "instance_id" uuid NULL,
  "id" uuid NOT NULL,
  "aud" character varying(255) NULL,
  "role" character varying(255) NULL,
  "email" character varying(255) NULL,
  "encrypted_password" character varying(255) NULL,
  "email_confirmed_at" timestamptz NULL,
  "invited_at" timestamptz NULL,
  "confirmation_token" character varying(255) NULL,
  "confirmation_sent_at" timestamptz NULL,
  "recovery_token" character varying(255) NULL,
  "recovery_sent_at" timestamptz NULL,
  "email_change_token_new" character varying(255) NULL,
  "email_change" character varying(255) NULL,
  "email_change_sent_at" timestamptz NULL,
  "last_sign_in_at" timestamptz NULL,
  "raw_app_meta_data" jsonb NULL,
  "raw_user_meta_data" jsonb NULL,
  "is_super_admin" boolean NULL,
  "created_at" timestamptz NULL,
  "updated_at" timestamptz NULL,
  "phone" text NULL DEFAULT NULL::character varying,
  "phone_confirmed_at" timestamptz NULL,
  "phone_change" text NULL DEFAULT '',
  "phone_change_token" character varying(255) NULL DEFAULT '',
  "phone_change_sent_at" timestamptz NULL,
  "confirmed_at" timestamptz NULL GENERATED ALWAYS AS (LEAST(email_confirmed_at, phone_confirmed_at)) STORED,
  "email_change_token_current" character varying(255) NULL DEFAULT '',
  "email_change_confirm_status" smallint NULL DEFAULT 0,
  "banned_until" timestamptz NULL,
  "reauthentication_token" character varying(255) NULL DEFAULT '',
  "reauthentication_sent_at" timestamptz NULL,
  "is_sso_user" boolean NOT NULL DEFAULT false,
  "deleted_at" timestamptz NULL,
  "is_anonymous" boolean NOT NULL DEFAULT false,
  PRIMARY KEY ("id"),
  CONSTRAINT "users_phone_key" UNIQUE ("phone"),
  CONSTRAINT "users_email_change_confirm_status_check" CHECK ((email_change_confirm_status >= 0) AND (email_change_confirm_status <= 2))
);
-- Create index "confirmation_token_idx" to table: "users"
CREATE UNIQUE INDEX "confirmation_token_idx" ON "auth"."users" ("confirmation_token") WHERE ((confirmation_token)::text !~ '^[0-9 ]*$'::text);
-- Create index "email_change_token_current_idx" to table: "users"
CREATE UNIQUE INDEX "email_change_token_current_idx" ON "auth"."users" ("email_change_token_current") WHERE ((email_change_token_current)::text !~ '^[0-9 ]*$'::text);
-- Create index "email_change_token_new_idx" to table: "users"
CREATE UNIQUE INDEX "email_change_token_new_idx" ON "auth"."users" ("email_change_token_new") WHERE ((email_change_token_new)::text !~ '^[0-9 ]*$'::text);
-- Create index "reauthentication_token_idx" to table: "users"
CREATE UNIQUE INDEX "reauthentication_token_idx" ON "auth"."users" ("reauthentication_token") WHERE ((reauthentication_token)::text !~ '^[0-9 ]*$'::text);
-- Create index "recovery_token_idx" to table: "users"
CREATE UNIQUE INDEX "recovery_token_idx" ON "auth"."users" ("recovery_token") WHERE ((recovery_token)::text !~ '^[0-9 ]*$'::text);
-- Create index "users_email_partial_key" to table: "users"
CREATE UNIQUE INDEX "users_email_partial_key" ON "auth"."users" ("email") WHERE (is_sso_user = false);
-- Create index "users_instance_id_email_idx" to table: "users"
CREATE INDEX "users_instance_id_email_idx" ON "auth"."users" ("instance_id", (lower((email)::text)));
-- Create index "users_instance_id_idx" to table: "users"
CREATE INDEX "users_instance_id_idx" ON "auth"."users" ("instance_id");
-- Create index "users_is_anonymous_idx" to table: "users"
CREATE INDEX "users_is_anonymous_idx" ON "auth"."users" ("is_anonymous");
-- Set comment to table: "users"
COMMENT ON TABLE "auth"."users" IS 'Auth: Stores user login data within a secure schema.';
-- Set comment to column: "is_sso_user" on table: "users"
COMMENT ON COLUMN "auth"."users"."is_sso_user" IS 'Auth: Set this column to true when the account comes from SSO. These accounts can have duplicate emails.';
-- Set comment to index: "users_email_partial_key" on table: "users"
COMMENT ON INDEX "auth"."users_email_partial_key" IS 'Auth: A partial unique index that applies only when is_sso_user is false';
-- Enable row-level security for "users" table
ALTER TABLE "auth"."users" ENABLE ROW LEVEL SECURITY;
-- Create "get_auth" function
CREATE FUNCTION "pgbouncer"."get_auth" ("p_usename" text) RETURNS TABLE ("username" text, "password" text) LANGUAGE plpgsql SECURITY DEFINER AS $$
begin
    raise debug 'PgBouncer auth request: %', p_usename;

    return query
    select 
        rolname::text, 
        case when rolvaliduntil < now() 
            then null 
            else rolpassword::text 
        end 
    from pg_authid 
    where rolname=$1 and rolcanlogin;
end;
$$;
-- Create enum type "equality_op"
CREATE TYPE "realtime"."equality_op" AS ENUM ('eq', 'neq', 'lt', 'lte', 'gt', 'gte', 'in');
-- Create enum type "action"
CREATE TYPE "realtime"."action" AS ENUM ('INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'ERROR');
-- Create composite type "user_defined_filter"
CREATE TYPE "realtime"."user_defined_filter" AS ("column_name" text, "op" "realtime"."equality_op", "value" text);
-- Create composite type "wal_rls"
CREATE TYPE "realtime"."wal_rls" AS ("wal" jsonb, "is_rls_enabled" boolean, "subscription_ids" uuid[], "errors" text[]);
-- Create composite type "wal_column"
CREATE TYPE "realtime"."wal_column" AS ("name" text, "type_name" text, "type_oid" oid, "value" jsonb, "is_pkey" boolean, "is_selectable" boolean);
-- Create "check_equality_op" function
CREATE FUNCTION "realtime"."check_equality_op" ("op" "realtime"."equality_op", "type_" regtype, "val_1" text, "val_2" text) RETURNS boolean LANGUAGE plpgsql IMMUTABLE AS $$
/*
      Casts *val_1* and *val_2* as type *type_* and check the *op* condition for truthiness
      */
      declare
          op_symbol text = (
              case
                  when op = 'eq' then '='
                  when op = 'neq' then '!='
                  when op = 'lt' then '<'
                  when op = 'lte' then '<='
                  when op = 'gt' then '>'
                  when op = 'gte' then '>='
                  when op = 'in' then '= any'
                  else 'UNKNOWN OP'
              end
          );
          res boolean;
      begin
          execute format(
              'select %L::'|| type_::text || ' ' || op_symbol
              || ' ( %L::'
              || (
                  case
                      when op = 'in' then type_::text || '[]'
                      else type_::text end
              )
              || ')', val_1, val_2) into res;
          return res;
      end;
$$;
-- Create "is_visible_through_filters" function
CREATE FUNCTION "realtime"."is_visible_through_filters" ("columns" "realtime"."wal_column"[], "filters" "realtime"."user_defined_filter"[]) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
/*
    Should the record be visible (true) or filtered out (false) after *filters* are applied
    */
        select
            -- Default to allowed when no filters present
            $2 is null -- no filters. this should not happen because subscriptions has a default
            or array_length($2, 1) is null -- array length of an empty array is null
            or bool_and(
                coalesce(
                    realtime.check_equality_op(
                        op:=f.op,
                        type_:=coalesce(
                            col.type_oid::regtype, -- null when wal2json version <= 2.4
                            col.type_name::regtype
                        ),
                        -- cast jsonb to text
                        val_1:=col.value #>> '{}',
                        val_2:=f.value
                    ),
                    false -- if null, filter does not match
                )
            )
        from
            unnest(filters) f
            join unnest(columns) col
                on f.column_name = col.name;
$$;
-- Create "to_regrole" function
CREATE FUNCTION "realtime"."to_regrole" ("role_name" text) RETURNS regrole LANGUAGE sql IMMUTABLE AS $$ select role_name::regrole $$;
-- Create "subscription" table
CREATE TABLE "realtime"."subscription" (
  "id" bigint NOT NULL GENERATED ALWAYS AS IDENTITY,
  "subscription_id" uuid NOT NULL,
  "entity" regclass NOT NULL,
  "filters" "realtime"."user_defined_filter"[] NOT NULL DEFAULT '{}',
  "claims" jsonb NOT NULL,
  "claims_role" regrole NOT NULL GENERATED ALWAYS AS (realtime.to_regrole((claims ->> 'role'::text))) STORED,
  "created_at" timestamp NOT NULL DEFAULT timezone('utc'::text, now()),
  CONSTRAINT "pk_subscription" PRIMARY KEY ("id")
);
-- Create index "ix_realtime_subscription_entity" to table: "subscription"
CREATE INDEX "ix_realtime_subscription_entity" ON "realtime"."subscription" ("entity");
-- Create index "subscription_subscription_id_entity_filters_key" to table: "subscription"
CREATE UNIQUE INDEX "subscription_subscription_id_entity_filters_key" ON "realtime"."subscription" ("subscription_id", "entity", "filters");
-- Create "build_prepared_statement_sql" function
CREATE FUNCTION "realtime"."build_prepared_statement_sql" ("prepared_statement_name" text, "entity" regclass, "columns" "realtime"."wal_column"[]) RETURNS text LANGUAGE sql AS $$
/*
      Builds a sql string that, if executed, creates a prepared statement to
      tests retrive a row from *entity* by its primary key columns.
      Example
          select realtime.build_prepared_statement_sql('public.notes', '{"id"}'::text[], '{"bigint"}'::text[])
      */
          select
      'prepare ' || prepared_statement_name || ' as
          select
              exists(
                  select
                      1
                  from
                      ' || entity || '
                  where
                      ' || string_agg(quote_ident(pkc.name) || '=' || quote_nullable(pkc.value #>> '{}') , ' and ') || '
              )'
          from
              unnest(columns) pkc
          where
              pkc.is_pkey
          group by
              entity
$$;
-- Create "apply_rls" function
CREATE FUNCTION "realtime"."apply_rls" ("wal" jsonb, "max_record_bytes" integer DEFAULT (1024 * 1024)) RETURNS SETOF "realtime"."wal_rls" LANGUAGE plpgsql AS $$
declare
-- Regclass of the table e.g. public.notes
entity_ regclass = (quote_ident(wal ->> 'schema') || '.' || quote_ident(wal ->> 'table'))::regclass;

-- I, U, D, T: insert, update ...
action realtime.action = (
    case wal ->> 'action'
        when 'I' then 'INSERT'
        when 'U' then 'UPDATE'
        when 'D' then 'DELETE'
        else 'ERROR'
    end
);

-- Is row level security enabled for the table
is_rls_enabled bool = relrowsecurity from pg_class where oid = entity_;

subscriptions realtime.subscription[] = array_agg(subs)
    from
        realtime.subscription subs
    where
        subs.entity = entity_;

-- Subscription vars
roles regrole[] = array_agg(distinct us.claims_role::text)
    from
        unnest(subscriptions) us;

working_role regrole;
claimed_role regrole;
claims jsonb;

subscription_id uuid;
subscription_has_access bool;
visible_to_subscription_ids uuid[] = '{}';

-- structured info for wal's columns
columns realtime.wal_column[];
-- previous identity values for update/delete
old_columns realtime.wal_column[];

error_record_exceeds_max_size boolean = octet_length(wal::text) > max_record_bytes;

-- Primary jsonb output for record
output jsonb;

begin
perform set_config('role', null, true);

columns =
    array_agg(
        (
            x->>'name',
            x->>'type',
            x->>'typeoid',
            realtime.cast(
                (x->'value') #>> '{}',
                coalesce(
                    (x->>'typeoid')::regtype, -- null when wal2json version <= 2.4
                    (x->>'type')::regtype
                )
            ),
            (pks ->> 'name') is not null,
            true
        )::realtime.wal_column
    )
    from
        jsonb_array_elements(wal -> 'columns') x
        left join jsonb_array_elements(wal -> 'pk') pks
            on (x ->> 'name') = (pks ->> 'name');

old_columns =
    array_agg(
        (
            x->>'name',
            x->>'type',
            x->>'typeoid',
            realtime.cast(
                (x->'value') #>> '{}',
                coalesce(
                    (x->>'typeoid')::regtype, -- null when wal2json version <= 2.4
                    (x->>'type')::regtype
                )
            ),
            (pks ->> 'name') is not null,
            true
        )::realtime.wal_column
    )
    from
        jsonb_array_elements(wal -> 'identity') x
        left join jsonb_array_elements(wal -> 'pk') pks
            on (x ->> 'name') = (pks ->> 'name');

for working_role in select * from unnest(roles) loop

    -- Update `is_selectable` for columns and old_columns
    columns =
        array_agg(
            (
                c.name,
                c.type_name,
                c.type_oid,
                c.value,
                c.is_pkey,
                pg_catalog.has_column_privilege(working_role, entity_, c.name, 'SELECT')
            )::realtime.wal_column
        )
        from
            unnest(columns) c;

    old_columns =
            array_agg(
                (
                    c.name,
                    c.type_name,
                    c.type_oid,
                    c.value,
                    c.is_pkey,
                    pg_catalog.has_column_privilege(working_role, entity_, c.name, 'SELECT')
                )::realtime.wal_column
            )
            from
                unnest(old_columns) c;

    if action <> 'DELETE' and count(1) = 0 from unnest(columns) c where c.is_pkey then
        return next (
            jsonb_build_object(
                'schema', wal ->> 'schema',
                'table', wal ->> 'table',
                'type', action
            ),
            is_rls_enabled,
            -- subscriptions is already filtered by entity
            (select array_agg(s.subscription_id) from unnest(subscriptions) as s where claims_role = working_role),
            array['Error 400: Bad Request, no primary key']
        )::realtime.wal_rls;

    -- The claims role does not have SELECT permission to the primary key of entity
    elsif action <> 'DELETE' and sum(c.is_selectable::int) <> count(1) from unnest(columns) c where c.is_pkey then
        return next (
            jsonb_build_object(
                'schema', wal ->> 'schema',
                'table', wal ->> 'table',
                'type', action
            ),
            is_rls_enabled,
            (select array_agg(s.subscription_id) from unnest(subscriptions) as s where claims_role = working_role),
            array['Error 401: Unauthorized']
        )::realtime.wal_rls;

    else
        output = jsonb_build_object(
            'schema', wal ->> 'schema',
            'table', wal ->> 'table',
            'type', action,
            'commit_timestamp', to_char(
                ((wal ->> 'timestamp')::timestamptz at time zone 'utc'),
                'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
            ),
            'columns', (
                select
                    jsonb_agg(
                        jsonb_build_object(
                            'name', pa.attname,
                            'type', pt.typname
                        )
                        order by pa.attnum asc
                    )
                from
                    pg_attribute pa
                    join pg_type pt
                        on pa.atttypid = pt.oid
                where
                    attrelid = entity_
                    and attnum > 0
                    and pg_catalog.has_column_privilege(working_role, entity_, pa.attname, 'SELECT')
            )
        )
        -- Add "record" key for insert and update
        || case
            when action in ('INSERT', 'UPDATE') then
                jsonb_build_object(
                    'record',
                    (
                        select
                            jsonb_object_agg(
                                -- if unchanged toast, get column name and value from old record
                                coalesce((c).name, (oc).name),
                                case
                                    when (c).name is null then (oc).value
                                    else (c).value
                                end
                            )
                        from
                            unnest(columns) c
                            full outer join unnest(old_columns) oc
                                on (c).name = (oc).name
                        where
                            coalesce((c).is_selectable, (oc).is_selectable)
                            and ( not error_record_exceeds_max_size or (octet_length((c).value::text) <= 64))
                    )
                )
            else '{}'::jsonb
        end
        -- Add "old_record" key for update and delete
        || case
            when action = 'UPDATE' then
                jsonb_build_object(
                        'old_record',
                        (
                            select jsonb_object_agg((c).name, (c).value)
                            from unnest(old_columns) c
                            where
                                (c).is_selectable
                                and ( not error_record_exceeds_max_size or (octet_length((c).value::text) <= 64))
                        )
                    )
            when action = 'DELETE' then
                jsonb_build_object(
                    'old_record',
                    (
                        select jsonb_object_agg((c).name, (c).value)
                        from unnest(old_columns) c
                        where
                            (c).is_selectable
                            and ( not error_record_exceeds_max_size or (octet_length((c).value::text) <= 64))
                            and ( not is_rls_enabled or (c).is_pkey ) -- if RLS enabled, we can't secure deletes so filter to pkey
                    )
                )
            else '{}'::jsonb
        end;

        -- Create the prepared statement
        if is_rls_enabled and action <> 'DELETE' then
            if (select 1 from pg_prepared_statements where name = 'walrus_rls_stmt' limit 1) > 0 then
                deallocate walrus_rls_stmt;
            end if;
            execute realtime.build_prepared_statement_sql('walrus_rls_stmt', entity_, columns);
        end if;

        visible_to_subscription_ids = '{}';

        for subscription_id, claims in (
                select
                    subs.subscription_id,
                    subs.claims
                from
                    unnest(subscriptions) subs
                where
                    subs.entity = entity_
                    and subs.claims_role = working_role
                    and (
                        realtime.is_visible_through_filters(columns, subs.filters)
                        or (
                          action = 'DELETE'
                          and realtime.is_visible_through_filters(old_columns, subs.filters)
                        )
                    )
        ) loop

            if not is_rls_enabled or action = 'DELETE' then
                visible_to_subscription_ids = visible_to_subscription_ids || subscription_id;
            else
                -- Check if RLS allows the role to see the record
                perform
                    -- Trim leading and trailing quotes from working_role because set_config
                    -- doesn't recognize the role as valid if they are included
                    set_config('role', trim(both '"' from working_role::text), true),
                    set_config('request.jwt.claims', claims::text, true);

                execute 'execute walrus_rls_stmt' into subscription_has_access;

                if subscription_has_access then
                    visible_to_subscription_ids = visible_to_subscription_ids || subscription_id;
                end if;
            end if;
        end loop;

        perform set_config('role', null, true);

        return next (
            output,
            is_rls_enabled,
            visible_to_subscription_ids,
            case
                when error_record_exceeds_max_size then array['Error 413: Payload Too Large']
                else '{}'
            end
        )::realtime.wal_rls;

    end if;
end loop;

perform set_config('role', null, true);
end;
$$;
-- Create "search_v2" function
CREATE FUNCTION "storage"."search_v2" ("prefix" text, "bucket_name" text, "limits" integer DEFAULT 100, "levels" integer DEFAULT 1, "start_after" text DEFAULT '', "sort_order" text DEFAULT 'asc', "sort_column" text DEFAULT 'name', "sort_column_after" text DEFAULT '') RETURNS TABLE ("key" text, "name" text, "id" uuid, "updated_at" timestamptz, "created_at" timestamptz, "last_accessed_at" timestamptz, "metadata" jsonb) LANGUAGE plpgsql STABLE AS $$
DECLARE
    sort_col text;
    sort_ord text;
    cursor_op text;
    cursor_expr text;
    sort_expr text;
BEGIN
    -- Validate sort_order
    sort_ord := lower(sort_order);
    IF sort_ord NOT IN ('asc', 'desc') THEN
        sort_ord := 'asc';
    END IF;

    -- Determine cursor comparison operator
    IF sort_ord = 'asc' THEN
        cursor_op := '>';
    ELSE
        cursor_op := '<';
    END IF;
    
    sort_col := lower(sort_column);
    -- Validate sort column  
    IF sort_col IN ('updated_at', 'created_at') THEN
        cursor_expr := format(
            '($5 = '''' OR ROW(date_trunc(''milliseconds'', %I), name COLLATE "C") %s ROW(COALESCE(NULLIF($6, '''')::timestamptz, ''epoch''::timestamptz), $5))',
            sort_col, cursor_op
        );
        sort_expr := format(
            'COALESCE(date_trunc(''milliseconds'', %I), ''epoch''::timestamptz) %s, name COLLATE "C" %s',
            sort_col, sort_ord, sort_ord
        );
    ELSE
        cursor_expr := format('($5 = '''' OR name COLLATE "C" %s $5)', cursor_op);
        sort_expr := format('name COLLATE "C" %s', sort_ord);
    END IF;

    RETURN QUERY EXECUTE format(
        $sql$
        SELECT * FROM (
            (
                SELECT
                    split_part(name, '/', $4) AS key,
                    name,
                    NULL::uuid AS id,
                    updated_at,
                    created_at,
                    NULL::timestamptz AS last_accessed_at,
                    NULL::jsonb AS metadata
                FROM storage.prefixes
                WHERE name COLLATE "C" LIKE $1 || '%%'
                    AND bucket_id = $2
                    AND level = $4
                    AND %s
                ORDER BY %s
                LIMIT $3
            )
            UNION ALL
            (
                SELECT
                    split_part(name, '/', $4) AS key,
                    name,
                    id,
                    updated_at,
                    created_at,
                    last_accessed_at,
                    metadata
                FROM storage.objects
                WHERE name COLLATE "C" LIKE $1 || '%%'
                    AND bucket_id = $2
                    AND level = $4
                    AND %s
                ORDER BY %s
                LIMIT $3
            )
        ) obj
        ORDER BY %s
        LIMIT $3
        $sql$,
        cursor_expr,    -- prefixes WHERE
        sort_expr,      -- prefixes ORDER BY
        cursor_expr,    -- objects WHERE
        sort_expr,      -- objects ORDER BY
        sort_expr       -- final ORDER BY
    )
    USING prefix, bucket_name, limits, levels, start_after, sort_column_after;
END;
$$;
-- Create "quote_wal2json" function
CREATE FUNCTION "realtime"."quote_wal2json" ("entity" regclass) RETURNS text LANGUAGE sql STRICT IMMUTABLE AS $$
select
        (
          select string_agg('' || ch,'')
          from unnest(string_to_array(nsp.nspname::text, null)) with ordinality x(ch, idx)
          where
            not (x.idx = 1 and x.ch = '"')
            and not (
              x.idx = array_length(string_to_array(nsp.nspname::text, null), 1)
              and x.ch = '"'
            )
        )
        || '.'
        || (
          select string_agg('' || ch,'')
          from unnest(string_to_array(pc.relname::text, null)) with ordinality x(ch, idx)
          where
            not (x.idx = 1 and x.ch = '"')
            and not (
              x.idx = array_length(string_to_array(nsp.nspname::text, null), 1)
              and x.ch = '"'
            )
          )
      from
        pg_class pc
        join pg_namespace nsp
          on pc.relnamespace = nsp.oid
      where
        pc.oid = entity
$$;
-- Create "list_changes" function
CREATE FUNCTION "realtime"."list_changes" ("publication" name, "slot_name" name, "max_changes" integer, "max_record_bytes" integer) RETURNS SETOF "realtime"."wal_rls" LANGUAGE sql SET "log_min_messages" = 'fatal' AS $$
with pub as (
        select
          concat_ws(
            ',',
            case when bool_or(pubinsert) then 'insert' else null end,
            case when bool_or(pubupdate) then 'update' else null end,
            case when bool_or(pubdelete) then 'delete' else null end
          ) as w2j_actions,
          coalesce(
            string_agg(
              realtime.quote_wal2json(format('%I.%I', schemaname, tablename)::regclass),
              ','
            ) filter (where ppt.tablename is not null and ppt.tablename not like '% %'),
            ''
          ) w2j_add_tables
        from
          pg_publication pp
          left join pg_publication_tables ppt
            on pp.pubname = ppt.pubname
        where
          pp.pubname = publication
        group by
          pp.pubname
        limit 1
      ),
      w2j as (
        select
          x.*, pub.w2j_add_tables
        from
          pub,
          pg_logical_slot_get_changes(
            slot_name, null, max_changes,
            'include-pk', 'true',
            'include-transaction', 'false',
            'include-timestamp', 'true',
            'include-type-oids', 'true',
            'format-version', '2',
            'actions', pub.w2j_actions,
            'add-tables', pub.w2j_add_tables
          ) x
      )
      select
        xyz.wal,
        xyz.is_rls_enabled,
        xyz.subscription_ids,
        xyz.errors
      from
        w2j,
        realtime.apply_rls(
          wal := w2j.data::jsonb,
          max_record_bytes := max_record_bytes
        ) xyz(wal, is_rls_enabled, subscription_ids, errors)
      where
        w2j.w2j_add_tables <> ''
        and xyz.subscription_ids[1] is not null
$$;
-- Create "messages" table
CREATE TABLE "realtime"."messages" (
  "topic" text NOT NULL,
  "extension" text NOT NULL,
  "payload" jsonb NULL,
  "event" text NULL,
  "private" boolean NULL DEFAULT false,
  "updated_at" timestamp NOT NULL DEFAULT now(),
  "inserted_at" timestamp NOT NULL DEFAULT now(),
  "id" uuid NOT NULL DEFAULT gen_random_uuid(),
  PRIMARY KEY ("id", "inserted_at")
) PARTITION BY RANGE ("inserted_at");
-- Create index "messages_inserted_at_topic_index" to table: "messages"
CREATE INDEX "messages_inserted_at_topic_index" ON "realtime"."messages" ("inserted_at" DESC, "topic") WHERE ((extension = 'broadcast'::text) AND (private IS TRUE));
-- Enable row-level security for "messages" table
ALTER TABLE "realtime"."messages" ENABLE ROW LEVEL SECURITY;
-- Create "send" function
CREATE FUNCTION "realtime"."send" ("payload" jsonb, "event" text, "topic" text, "private" boolean DEFAULT true) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  BEGIN
    -- Set the topic configuration
    EXECUTE format('SET LOCAL realtime.topic TO %L', topic);

    -- Attempt to insert the message
    INSERT INTO realtime.messages (payload, event, topic, private, extension)
    VALUES (payload, event, topic, private, 'broadcast');
  EXCEPTION
    WHEN OTHERS THEN
      -- Capture and notify the error
      RAISE WARNING 'ErrorSendingBroadcastMessage: %', SQLERRM;
  END;
END;
$$;
-- Create "subscription_check_filters" function
CREATE FUNCTION "realtime"."subscription_check_filters" () RETURNS trigger LANGUAGE plpgsql AS $$
/*
    Validates that the user defined filters for a subscription:
    - refer to valid columns that the claimed role may access
    - values are coercable to the correct column type
    */
    declare
        col_names text[] = coalesce(
                array_agg(c.column_name order by c.ordinal_position),
                '{}'::text[]
            )
            from
                information_schema.columns c
            where
                format('%I.%I', c.table_schema, c.table_name)::regclass = new.entity
                and pg_catalog.has_column_privilege(
                    (new.claims ->> 'role'),
                    format('%I.%I', c.table_schema, c.table_name)::regclass,
                    c.column_name,
                    'SELECT'
                );
        filter realtime.user_defined_filter;
        col_type regtype;

        in_val jsonb;
    begin
        for filter in select * from unnest(new.filters) loop
            -- Filtered column is valid
            if not filter.column_name = any(col_names) then
                raise exception 'invalid column for filter %', filter.column_name;
            end if;

            -- Type is sanitized and safe for string interpolation
            col_type = (
                select atttypid::regtype
                from pg_catalog.pg_attribute
                where attrelid = new.entity
                      and attname = filter.column_name
            );
            if col_type is null then
                raise exception 'failed to lookup type for column %', filter.column_name;
            end if;

            -- Set maximum number of entries for in filter
            if filter.op = 'in'::realtime.equality_op then
                in_val = realtime.cast(filter.value, (col_type::text || '[]')::regtype);
                if coalesce(jsonb_array_length(in_val), 0) > 100 then
                    raise exception 'too many values for `in` filter. Maximum 100';
                end if;
            else
                -- raises an exception if value is not coercable to type
                perform realtime.cast(filter.value, col_type);
            end if;

        end loop;

        -- Apply consistent order to filters so the unique constraint on
        -- (subscription_id, entity, filters) can't be tricked by a different filter order
        new.filters = coalesce(
            array_agg(f order by f.column_name, f.op, f.value),
            '{}'
        ) from unnest(new.filters) f;

        return new;
    end;
$$;
-- Create "topic" function
CREATE FUNCTION "realtime"."topic" () RETURNS text LANGUAGE sql STABLE AS $$ select nullif(current_setting('realtime.topic', true), '')::text; $$;
-- Create "schema_migrations" table
CREATE TABLE "realtime"."schema_migrations" (
  "version" bigint NOT NULL,
  "inserted_at" timestamp(0) NULL,
  PRIMARY KEY ("version")
);
-- Create trigger "tr_check_filters"
CREATE TRIGGER "tr_check_filters" BEFORE INSERT OR UPDATE ON "realtime"."subscription" FOR EACH ROW EXECUTE FUNCTION "realtime"."subscription_check_filters"();
-- Create "can_insert_object" function
CREATE FUNCTION "storage"."can_insert_object" ("bucketid" text, "name" text, "owner" uuid, "metadata" jsonb) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  INSERT INTO "storage"."objects" ("bucket_id", "name", "owner", "metadata") VALUES (bucketid, name, owner, metadata);
  -- hack to rollback the successful insert
  RAISE sqlstate 'PT200' using
  message = 'ROLLBACK',
  detail = 'rollback successful insert';
END
$$;
-- Create "delete_leaf_prefixes" function
CREATE FUNCTION "storage"."delete_leaf_prefixes" ("bucket_ids" text[], "names" text[]) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
    v_rows_deleted integer;
BEGIN
    LOOP
        WITH candidates AS (
            SELECT DISTINCT
                t.bucket_id,
                unnest(storage.get_prefixes(t.name)) AS name
            FROM unnest(bucket_ids, names) AS t(bucket_id, name)
        ),
        uniq AS (
             SELECT
                 bucket_id,
                 name,
                 storage.get_level(name) AS level
             FROM candidates
             WHERE name <> ''
             GROUP BY bucket_id, name
        ),
        leaf AS (
             SELECT
                 p.bucket_id,
                 p.name,
                 p.level
             FROM storage.prefixes AS p
                  JOIN uniq AS u
                       ON u.bucket_id = p.bucket_id
                           AND u.name = p.name
                           AND u.level = p.level
             WHERE NOT EXISTS (
                 SELECT 1
                 FROM storage.objects AS o
                 WHERE o.bucket_id = p.bucket_id
                   AND o.level = p.level + 1
                   AND o.name COLLATE "C" LIKE p.name || '/%'
             )
             AND NOT EXISTS (
                 SELECT 1
                 FROM storage.prefixes AS c
                 WHERE c.bucket_id = p.bucket_id
                   AND c.level = p.level + 1
                   AND c.name COLLATE "C" LIKE p.name || '/%'
             )
        )
        DELETE
        FROM storage.prefixes AS p
            USING leaf AS l
        WHERE p.bucket_id = l.bucket_id
          AND p.name = l.name
          AND p.level = l.level;

        GET DIAGNOSTICS v_rows_deleted = ROW_COUNT;
        EXIT WHEN v_rows_deleted = 0;
    END LOOP;
END;
$$;
-- Create "extension" function
CREATE FUNCTION "storage"."extension" ("name" text) RETURNS text LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
    _parts text[];
    _filename text;
BEGIN
    SELECT string_to_array(name, '/') INTO _parts;
    SELECT _parts[array_length(_parts,1)] INTO _filename;
    RETURN reverse(split_part(reverse(_filename), '.', 1));
END
$$;
-- Create "filename" function
CREATE FUNCTION "storage"."filename" ("name" text) RETURNS text LANGUAGE plpgsql AS $$
DECLARE
_parts text[];
BEGIN
	select string_to_array(name, '/') into _parts;
	return _parts[array_length(_parts,1)];
END
$$;
-- Create "foldername" function
CREATE FUNCTION "storage"."foldername" ("name" text) RETURNS text[] LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
    _parts text[];
BEGIN
    -- Split on "/" to get path segments
    SELECT string_to_array(name, '/') INTO _parts;
    -- Return everything except the last segment
    RETURN _parts[1 : array_length(_parts,1) - 1];
END
$$;
-- Create "broadcast_changes" function
CREATE FUNCTION "realtime"."broadcast_changes" ("topic_name" text, "event_name" text, "operation" text, "table_name" text, "table_schema" text, "new" record, "old" record, "level" text DEFAULT 'ROW') RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    -- Declare a variable to hold the JSONB representation of the row
    row_data jsonb := '{}'::jsonb;
BEGIN
    IF level = 'STATEMENT' THEN
        RAISE EXCEPTION 'function can only be triggered for each row, not for each statement';
    END IF;
    -- Check the operation type and handle accordingly
    IF operation = 'INSERT' OR operation = 'UPDATE' OR operation = 'DELETE' THEN
        row_data := jsonb_build_object('old_record', OLD, 'record', NEW, 'operation', operation, 'table', table_name, 'schema', table_schema);
        PERFORM realtime.send (row_data, event_name, topic_name);
    ELSE
        RAISE EXCEPTION 'Unexpected operation type: %', operation;
    END IF;
EXCEPTION
    WHEN OTHERS THEN
        RAISE EXCEPTION 'Failed to process the row: %', SQLERRM;
END;
$$;
-- Create "list_objects_with_delimiter" function
CREATE FUNCTION "storage"."list_objects_with_delimiter" ("bucket_id" text, "prefix_param" text, "delimiter_param" text, "max_keys" integer DEFAULT 100, "start_after" text DEFAULT '', "next_token" text DEFAULT '') RETURNS TABLE ("name" text, "id" uuid, "metadata" jsonb, "updated_at" timestamptz) LANGUAGE plpgsql AS $$
BEGIN
    RETURN QUERY EXECUTE
        'SELECT DISTINCT ON(name COLLATE "C") * from (
            SELECT
                CASE
                    WHEN position($2 IN substring(name from length($1) + 1)) > 0 THEN
                        substring(name from 1 for length($1) + position($2 IN substring(name from length($1) + 1)))
                    ELSE
                        name
                END AS name, id, metadata, updated_at
            FROM
                storage.objects
            WHERE
                bucket_id = $5 AND
                name ILIKE $1 || ''%'' AND
                CASE
                    WHEN $6 != '''' THEN
                    name COLLATE "C" > $6
                ELSE true END
                AND CASE
                    WHEN $4 != '''' THEN
                        CASE
                            WHEN position($2 IN substring(name from length($1) + 1)) > 0 THEN
                                substring(name from 1 for length($1) + position($2 IN substring(name from length($1) + 1))) COLLATE "C" > $4
                            ELSE
                                name COLLATE "C" > $4
                            END
                    ELSE
                        true
                END
            ORDER BY
                name COLLATE "C" ASC) as e order by name COLLATE "C" LIMIT $3'
        USING prefix_param, delimiter_param, max_keys, next_token, bucket_id, start_after;
END;
$$;
-- Create "lock_top_prefixes" function
CREATE FUNCTION "storage"."lock_top_prefixes" ("bucket_ids" text[], "names" text[]) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
    v_bucket text;
    v_top text;
BEGIN
    FOR v_bucket, v_top IN
        SELECT DISTINCT t.bucket_id,
            split_part(t.name, '/', 1) AS top
        FROM unnest(bucket_ids, names) AS t(bucket_id, name)
        WHERE t.name <> ''
        ORDER BY 1, 2
        LOOP
            PERFORM pg_advisory_xact_lock(hashtextextended(v_bucket || '/' || v_top, 0));
        END LOOP;
END;
$$;
-- Create "objects_delete_cleanup" function
CREATE FUNCTION "storage"."objects_delete_cleanup" () RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
    v_bucket_ids text[];
    v_names      text[];
BEGIN
    IF current_setting('storage.gc.prefixes', true) = '1' THEN
        RETURN NULL;
    END IF;

    PERFORM set_config('storage.gc.prefixes', '1', true);

    SELECT COALESCE(array_agg(d.bucket_id), '{}'),
           COALESCE(array_agg(d.name), '{}')
    INTO v_bucket_ids, v_names
    FROM deleted AS d
    WHERE d.name <> '';

    PERFORM storage.lock_top_prefixes(v_bucket_ids, v_names);
    PERFORM storage.delete_leaf_prefixes(v_bucket_ids, v_names);

    RETURN NULL;
END;
$$;
-- Create "objects_update_cleanup" function
CREATE FUNCTION "storage"."objects_update_cleanup" () RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
    -- NEW - OLD (destinations to create prefixes for)
    v_add_bucket_ids text[];
    v_add_names      text[];

    -- OLD - NEW (sources to prune)
    v_src_bucket_ids text[];
    v_src_names      text[];
BEGIN
    IF TG_OP <> 'UPDATE' THEN
        RETURN NULL;
    END IF;

    -- 1) Compute NEW−OLD (added paths) and OLD−NEW (moved-away paths)
    WITH added AS (
        SELECT n.bucket_id, n.name
        FROM new_rows n
        WHERE n.name <> '' AND position('/' in n.name) > 0
        EXCEPT
        SELECT o.bucket_id, o.name FROM old_rows o WHERE o.name <> ''
    ),
    moved AS (
         SELECT o.bucket_id, o.name
         FROM old_rows o
         WHERE o.name <> ''
         EXCEPT
         SELECT n.bucket_id, n.name FROM new_rows n WHERE n.name <> ''
    )
    SELECT
        -- arrays for ADDED (dest) in stable order
        COALESCE( (SELECT array_agg(a.bucket_id ORDER BY a.bucket_id, a.name) FROM added a), '{}' ),
        COALESCE( (SELECT array_agg(a.name      ORDER BY a.bucket_id, a.name) FROM added a), '{}' ),
        -- arrays for MOVED (src) in stable order
        COALESCE( (SELECT array_agg(m.bucket_id ORDER BY m.bucket_id, m.name) FROM moved m), '{}' ),
        COALESCE( (SELECT array_agg(m.name      ORDER BY m.bucket_id, m.name) FROM moved m), '{}' )
    INTO v_add_bucket_ids, v_add_names, v_src_bucket_ids, v_src_names;

    -- Nothing to do?
    IF (array_length(v_add_bucket_ids, 1) IS NULL) AND (array_length(v_src_bucket_ids, 1) IS NULL) THEN
        RETURN NULL;
    END IF;

    -- 2) Take per-(bucket, top) locks: ALL prefixes in consistent global order to prevent deadlocks
    DECLARE
        v_all_bucket_ids text[];
        v_all_names text[];
    BEGIN
        -- Combine source and destination arrays for consistent lock ordering
        v_all_bucket_ids := COALESCE(v_src_bucket_ids, '{}') || COALESCE(v_add_bucket_ids, '{}');
        v_all_names := COALESCE(v_src_names, '{}') || COALESCE(v_add_names, '{}');

        -- Single lock call ensures consistent global ordering across all transactions
        IF array_length(v_all_bucket_ids, 1) IS NOT NULL THEN
            PERFORM storage.lock_top_prefixes(v_all_bucket_ids, v_all_names);
        END IF;
    END;

    -- 3) Create destination prefixes (NEW−OLD) BEFORE pruning sources
    IF array_length(v_add_bucket_ids, 1) IS NOT NULL THEN
        WITH candidates AS (
            SELECT DISTINCT t.bucket_id, unnest(storage.get_prefixes(t.name)) AS name
            FROM unnest(v_add_bucket_ids, v_add_names) AS t(bucket_id, name)
            WHERE name <> ''
        )
        INSERT INTO storage.prefixes (bucket_id, name)
        SELECT c.bucket_id, c.name
        FROM candidates c
        ON CONFLICT DO NOTHING;
    END IF;

    -- 4) Prune source prefixes bottom-up for OLD−NEW
    IF array_length(v_src_bucket_ids, 1) IS NOT NULL THEN
        -- re-entrancy guard so DELETE on prefixes won't recurse
        IF current_setting('storage.gc.prefixes', true) <> '1' THEN
            PERFORM set_config('storage.gc.prefixes', '1', true);
        END IF;

        PERFORM storage.delete_leaf_prefixes(v_src_bucket_ids, v_src_names);
    END IF;

    RETURN NULL;
END;
$$;
-- Create "objects_update_level_trigger" function
CREATE FUNCTION "storage"."objects_update_level_trigger" () RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    -- Ensure this is an update operation and the name has changed
    IF TG_OP = 'UPDATE' AND (NEW."name" <> OLD."name" OR NEW."bucket_id" <> OLD."bucket_id") THEN
        -- Set the new level
        NEW."level" := "storage"."get_level"(NEW."name");
    END IF;
    RETURN NEW;
END;
$$;
-- Create "operation" function
CREATE FUNCTION "storage"."operation" () RETURNS text LANGUAGE plpgsql STABLE AS $$
BEGIN
    RETURN current_setting('storage.operation', true);
END;
$$;
-- Create "prefixes_delete_cleanup" function
CREATE FUNCTION "storage"."prefixes_delete_cleanup" () RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
    v_bucket_ids text[];
    v_names      text[];
BEGIN
    IF current_setting('storage.gc.prefixes', true) = '1' THEN
        RETURN NULL;
    END IF;

    PERFORM set_config('storage.gc.prefixes', '1', true);

    SELECT COALESCE(array_agg(d.bucket_id), '{}'),
           COALESCE(array_agg(d.name), '{}')
    INTO v_bucket_ids, v_names
    FROM deleted AS d
    WHERE d.name <> '';

    PERFORM storage.lock_top_prefixes(v_bucket_ids, v_names);
    PERFORM storage.delete_leaf_prefixes(v_bucket_ids, v_names);

    RETURN NULL;
END;
$$;
-- Create "identities" table
CREATE TABLE "auth"."identities" (
  "provider_id" text NOT NULL,
  "user_id" uuid NOT NULL,
  "identity_data" jsonb NOT NULL,
  "provider" text NOT NULL,
  "last_sign_in_at" timestamptz NULL,
  "created_at" timestamptz NULL,
  "updated_at" timestamptz NULL,
  "email" text NULL GENERATED ALWAYS AS (lower((identity_data ->> 'email'::text))) STORED,
  "id" uuid NOT NULL DEFAULT gen_random_uuid(),
  PRIMARY KEY ("id"),
  CONSTRAINT "identities_provider_id_provider_unique" UNIQUE ("provider_id", "provider"),
  CONSTRAINT "identities_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users" ("id") ON UPDATE NO ACTION ON DELETE CASCADE
);
-- Create index "identities_email_idx" to table: "identities"
CREATE INDEX "identities_email_idx" ON "auth"."identities" ("email" text_pattern_ops);
-- Create index "identities_user_id_idx" to table: "identities"
CREATE INDEX "identities_user_id_idx" ON "auth"."identities" ("user_id");
-- Set comment to table: "identities"
COMMENT ON TABLE "auth"."identities" IS 'Auth: Stores identities associated to a user.';
-- Set comment to column: "email" on table: "identities"
COMMENT ON COLUMN "auth"."identities"."email" IS 'Auth: Email is a generated column that references the optional email property in the identity_data';
-- Set comment to index: "identities_email_idx" on table: "identities"
COMMENT ON INDEX "auth"."identities_email_idx" IS 'Auth: Ensures indexed queries on the email column';
-- Enable row-level security for "identities" table
ALTER TABLE "auth"."identities" ENABLE ROW LEVEL SECURITY;
-- Create "oauth_clients" table
CREATE TABLE "auth"."oauth_clients" (
  "id" uuid NOT NULL,
  "client_secret_hash" text NULL,
  "registration_type" "auth"."oauth_registration_type" NOT NULL,
  "redirect_uris" text NOT NULL,
  "grant_types" text NOT NULL,
  "client_name" text NULL,
  "client_uri" text NULL,
  "logo_uri" text NULL,
  "created_at" timestamptz NOT NULL DEFAULT now(),
  "updated_at" timestamptz NOT NULL DEFAULT now(),
  "deleted_at" timestamptz NULL,
  "client_type" "auth"."oauth_client_type" NOT NULL DEFAULT 'confidential',
  PRIMARY KEY ("id"),
  CONSTRAINT "oauth_clients_client_name_length" CHECK (char_length(client_name) <= 1024),
  CONSTRAINT "oauth_clients_client_uri_length" CHECK (char_length(client_uri) <= 2048),
  CONSTRAINT "oauth_clients_logo_uri_length" CHECK (char_length(logo_uri) <= 2048)
);
-- Create index "oauth_clients_deleted_at_idx" to table: "oauth_clients"
CREATE INDEX "oauth_clients_deleted_at_idx" ON "auth"."oauth_clients" ("deleted_at");
-- Create "sessions" table
CREATE TABLE "auth"."sessions" (
  "id" uuid NOT NULL,
  "user_id" uuid NOT NULL,
  "created_at" timestamptz NULL,
  "updated_at" timestamptz NULL,
  "factor_id" uuid NULL,
  "aal" "auth"."aal_level" NULL,
  "not_after" timestamptz NULL,
  "refreshed_at" timestamp NULL,
  "user_agent" text NULL,
  "ip" inet NULL,
  "tag" text NULL,
  "oauth_client_id" uuid NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "sessions_oauth_client_id_fkey" FOREIGN KEY ("oauth_client_id") REFERENCES "auth"."oauth_clients" ("id") ON UPDATE NO ACTION ON DELETE CASCADE,
  CONSTRAINT "sessions_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users" ("id") ON UPDATE NO ACTION ON DELETE CASCADE
);
-- Create index "sessions_not_after_idx" to table: "sessions"
CREATE INDEX "sessions_not_after_idx" ON "auth"."sessions" ("not_after" DESC);
-- Create index "sessions_oauth_client_id_idx" to table: "sessions"
CREATE INDEX "sessions_oauth_client_id_idx" ON "auth"."sessions" ("oauth_client_id");
-- Create index "sessions_user_id_idx" to table: "sessions"
CREATE INDEX "sessions_user_id_idx" ON "auth"."sessions" ("user_id");
-- Create index "user_id_created_at_idx" to table: "sessions"
CREATE INDEX "user_id_created_at_idx" ON "auth"."sessions" ("user_id", "created_at");
-- Set comment to table: "sessions"
COMMENT ON TABLE "auth"."sessions" IS 'Auth: Stores session data associated to a user.';
-- Set comment to column: "not_after" on table: "sessions"
COMMENT ON COLUMN "auth"."sessions"."not_after" IS 'Auth: Not after is a nullable column that contains a timestamp after which the session should be regarded as expired.';
-- Enable row-level security for "sessions" table
ALTER TABLE "auth"."sessions" ENABLE ROW LEVEL SECURITY;
-- Create "mfa_amr_claims" table
CREATE TABLE "auth"."mfa_amr_claims" (
  "session_id" uuid NOT NULL,
  "created_at" timestamptz NOT NULL,
  "updated_at" timestamptz NOT NULL,
  "authentication_method" text NOT NULL,
  "id" uuid NOT NULL,
  CONSTRAINT "amr_id_pk" PRIMARY KEY ("id"),
  CONSTRAINT "mfa_amr_claims_session_id_authentication_method_pkey" UNIQUE ("session_id", "authentication_method"),
  CONSTRAINT "mfa_amr_claims_session_id_fkey" FOREIGN KEY ("session_id") REFERENCES "auth"."sessions" ("id") ON UPDATE NO ACTION ON DELETE CASCADE
);
-- Set comment to table: "mfa_amr_claims"
COMMENT ON TABLE "auth"."mfa_amr_claims" IS 'auth: stores authenticator method reference claims for multi factor authentication';
-- Enable row-level security for "mfa_amr_claims" table
ALTER TABLE "auth"."mfa_amr_claims" ENABLE ROW LEVEL SECURITY;
-- Create "mfa_factors" table
CREATE TABLE "auth"."mfa_factors" (
  "id" uuid NOT NULL,
  "user_id" uuid NOT NULL,
  "friendly_name" text NULL,
  "factor_type" "auth"."factor_type" NOT NULL,
  "status" "auth"."factor_status" NOT NULL,
  "created_at" timestamptz NOT NULL,
  "updated_at" timestamptz NOT NULL,
  "secret" text NULL,
  "phone" text NULL,
  "last_challenged_at" timestamptz NULL,
  "web_authn_credential" jsonb NULL,
  "web_authn_aaguid" uuid NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "mfa_factors_last_challenged_at_key" UNIQUE ("last_challenged_at"),
  CONSTRAINT "mfa_factors_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users" ("id") ON UPDATE NO ACTION ON DELETE CASCADE
);
-- Create index "factor_id_created_at_idx" to table: "mfa_factors"
CREATE INDEX "factor_id_created_at_idx" ON "auth"."mfa_factors" ("user_id", "created_at");
-- Create index "mfa_factors_user_friendly_name_unique" to table: "mfa_factors"
CREATE UNIQUE INDEX "mfa_factors_user_friendly_name_unique" ON "auth"."mfa_factors" ("friendly_name", "user_id") WHERE (TRIM(BOTH FROM friendly_name) <> ''::text);
-- Create index "mfa_factors_user_id_idx" to table: "mfa_factors"
CREATE INDEX "mfa_factors_user_id_idx" ON "auth"."mfa_factors" ("user_id");
-- Create index "unique_phone_factor_per_user" to table: "mfa_factors"
CREATE UNIQUE INDEX "unique_phone_factor_per_user" ON "auth"."mfa_factors" ("user_id", "phone");
-- Set comment to table: "mfa_factors"
COMMENT ON TABLE "auth"."mfa_factors" IS 'auth: stores metadata about factors';
-- Enable row-level security for "mfa_factors" table
ALTER TABLE "auth"."mfa_factors" ENABLE ROW LEVEL SECURITY;
-- Create "mfa_challenges" table
CREATE TABLE "auth"."mfa_challenges" (
  "id" uuid NOT NULL,
  "factor_id" uuid NOT NULL,
  "created_at" timestamptz NOT NULL,
  "verified_at" timestamptz NULL,
  "ip_address" inet NOT NULL,
  "otp_code" text NULL,
  "web_authn_session_data" jsonb NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "mfa_challenges_auth_factor_id_fkey" FOREIGN KEY ("factor_id") REFERENCES "auth"."mfa_factors" ("id") ON UPDATE NO ACTION ON DELETE CASCADE
);
-- Create index "mfa_challenge_created_at_idx" to table: "mfa_challenges"
CREATE INDEX "mfa_challenge_created_at_idx" ON "auth"."mfa_challenges" ("created_at" DESC);
-- Set comment to table: "mfa_challenges"
COMMENT ON TABLE "auth"."mfa_challenges" IS 'auth: stores metadata about challenge requests made';
-- Enable row-level security for "mfa_challenges" table
ALTER TABLE "auth"."mfa_challenges" ENABLE ROW LEVEL SECURITY;
-- Create "oauth_authorizations" table
CREATE TABLE "auth"."oauth_authorizations" (
  "id" uuid NOT NULL,
  "authorization_id" text NOT NULL,
  "client_id" uuid NOT NULL,
  "user_id" uuid NULL,
  "redirect_uri" text NOT NULL,
  "scope" text NOT NULL,
  "state" text NULL,
  "resource" text NULL,
  "code_challenge" text NULL,
  "code_challenge_method" "auth"."code_challenge_method" NULL,
  "response_type" "auth"."oauth_response_type" NOT NULL DEFAULT 'code',
  "status" "auth"."oauth_authorization_status" NOT NULL DEFAULT 'pending',
  "authorization_code" text NULL,
  "created_at" timestamptz NOT NULL DEFAULT now(),
  "expires_at" timestamptz NOT NULL DEFAULT (now() + '00:03:00'::interval),
  "approved_at" timestamptz NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "oauth_authorizations_authorization_code_key" UNIQUE ("authorization_code"),
  CONSTRAINT "oauth_authorizations_authorization_id_key" UNIQUE ("authorization_id"),
  CONSTRAINT "oauth_authorizations_client_id_fkey" FOREIGN KEY ("client_id") REFERENCES "auth"."oauth_clients" ("id") ON UPDATE NO ACTION ON DELETE CASCADE,
  CONSTRAINT "oauth_authorizations_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users" ("id") ON UPDATE NO ACTION ON DELETE CASCADE,
  CONSTRAINT "oauth_authorizations_authorization_code_length" CHECK (char_length(authorization_code) <= 255),
  CONSTRAINT "oauth_authorizations_code_challenge_length" CHECK (char_length(code_challenge) <= 128),
  CONSTRAINT "oauth_authorizations_expires_at_future" CHECK (expires_at > created_at),
  CONSTRAINT "oauth_authorizations_redirect_uri_length" CHECK (char_length(redirect_uri) <= 2048),
  CONSTRAINT "oauth_authorizations_resource_length" CHECK (char_length(resource) <= 2048),
  CONSTRAINT "oauth_authorizations_scope_length" CHECK (char_length(scope) <= 4096),
  CONSTRAINT "oauth_authorizations_state_length" CHECK (char_length(state) <= 4096)
);
-- Create index "oauth_auth_pending_exp_idx" to table: "oauth_authorizations"
CREATE INDEX "oauth_auth_pending_exp_idx" ON "auth"."oauth_authorizations" ("expires_at") WHERE (status = 'pending'::auth.oauth_authorization_status);
-- Create "oauth_consents" table
CREATE TABLE "auth"."oauth_consents" (
  "id" uuid NOT NULL,
  "user_id" uuid NOT NULL,
  "client_id" uuid NOT NULL,
  "scopes" text NOT NULL,
  "granted_at" timestamptz NOT NULL DEFAULT now(),
  "revoked_at" timestamptz NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "oauth_consents_user_client_unique" UNIQUE ("user_id", "client_id"),
  CONSTRAINT "oauth_consents_client_id_fkey" FOREIGN KEY ("client_id") REFERENCES "auth"."oauth_clients" ("id") ON UPDATE NO ACTION ON DELETE CASCADE,
  CONSTRAINT "oauth_consents_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users" ("id") ON UPDATE NO ACTION ON DELETE CASCADE,
  CONSTRAINT "oauth_consents_revoked_after_granted" CHECK ((revoked_at IS NULL) OR (revoked_at >= granted_at)),
  CONSTRAINT "oauth_consents_scopes_length" CHECK (char_length(scopes) <= 2048),
  CONSTRAINT "oauth_consents_scopes_not_empty" CHECK (char_length(TRIM(BOTH FROM scopes)) > 0)
);
-- Create index "oauth_consents_active_client_idx" to table: "oauth_consents"
CREATE INDEX "oauth_consents_active_client_idx" ON "auth"."oauth_consents" ("client_id") WHERE (revoked_at IS NULL);
-- Create index "oauth_consents_active_user_client_idx" to table: "oauth_consents"
CREATE INDEX "oauth_consents_active_user_client_idx" ON "auth"."oauth_consents" ("user_id", "client_id") WHERE (revoked_at IS NULL);
-- Create index "oauth_consents_user_order_idx" to table: "oauth_consents"
CREATE INDEX "oauth_consents_user_order_idx" ON "auth"."oauth_consents" ("user_id", "granted_at" DESC);
-- Create "one_time_tokens" table
CREATE TABLE "auth"."one_time_tokens" (
  "id" uuid NOT NULL,
  "user_id" uuid NOT NULL,
  "token_type" "auth"."one_time_token_type" NOT NULL,
  "token_hash" text NOT NULL,
  "relates_to" text NOT NULL,
  "created_at" timestamp NOT NULL DEFAULT now(),
  "updated_at" timestamp NOT NULL DEFAULT now(),
  PRIMARY KEY ("id"),
  CONSTRAINT "one_time_tokens_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "auth"."users" ("id") ON UPDATE NO ACTION ON DELETE CASCADE,
  CONSTRAINT "one_time_tokens_token_hash_check" CHECK (char_length(token_hash) > 0)
);
-- Create index "one_time_tokens_relates_to_hash_idx" to table: "one_time_tokens"
CREATE INDEX "one_time_tokens_relates_to_hash_idx" ON "auth"."one_time_tokens" USING hash ("relates_to");
-- Create index "one_time_tokens_token_hash_hash_idx" to table: "one_time_tokens"
CREATE INDEX "one_time_tokens_token_hash_hash_idx" ON "auth"."one_time_tokens" USING hash ("token_hash");
-- Create index "one_time_tokens_user_id_token_type_key" to table: "one_time_tokens"
CREATE UNIQUE INDEX "one_time_tokens_user_id_token_type_key" ON "auth"."one_time_tokens" ("user_id", "token_type");
-- Enable row-level security for "one_time_tokens" table
ALTER TABLE "auth"."one_time_tokens" ENABLE ROW LEVEL SECURITY;
-- Create "refresh_tokens" table
CREATE TABLE "auth"."refresh_tokens" (
  "instance_id" uuid NULL,
  "id" bigserial NOT NULL,
  "token" character varying(255) NULL,
  "user_id" character varying(255) NULL,
  "revoked" boolean NULL,
  "created_at" timestamptz NULL,
  "updated_at" timestamptz NULL,
  "parent" character varying(255) NULL,
  "session_id" uuid NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "refresh_tokens_token_unique" UNIQUE ("token"),
  CONSTRAINT "refresh_tokens_session_id_fkey" FOREIGN KEY ("session_id") REFERENCES "auth"."sessions" ("id") ON UPDATE NO ACTION ON DELETE CASCADE
);
-- Create index "refresh_tokens_instance_id_idx" to table: "refresh_tokens"
CREATE INDEX "refresh_tokens_instance_id_idx" ON "auth"."refresh_tokens" ("instance_id");
-- Create index "refresh_tokens_instance_id_user_id_idx" to table: "refresh_tokens"
CREATE INDEX "refresh_tokens_instance_id_user_id_idx" ON "auth"."refresh_tokens" ("instance_id", "user_id");
-- Create index "refresh_tokens_parent_idx" to table: "refresh_tokens"
CREATE INDEX "refresh_tokens_parent_idx" ON "auth"."refresh_tokens" ("parent");
-- Create index "refresh_tokens_session_id_revoked_idx" to table: "refresh_tokens"
CREATE INDEX "refresh_tokens_session_id_revoked_idx" ON "auth"."refresh_tokens" ("session_id", "revoked");
-- Create index "refresh_tokens_updated_at_idx" to table: "refresh_tokens"
CREATE INDEX "refresh_tokens_updated_at_idx" ON "auth"."refresh_tokens" ("updated_at" DESC);
-- Set comment to table: "refresh_tokens"
COMMENT ON TABLE "auth"."refresh_tokens" IS 'Auth: Store of tokens used to refresh JWT tokens once they expire.';
-- Enable row-level security for "refresh_tokens" table
ALTER TABLE "auth"."refresh_tokens" ENABLE ROW LEVEL SECURITY;
-- Create "s3_multipart_uploads_parts" table
CREATE TABLE "storage"."s3_multipart_uploads_parts" (
  "id" uuid NOT NULL DEFAULT gen_random_uuid(),
  "upload_id" text NOT NULL,
  "size" bigint NOT NULL DEFAULT 0,
  "part_number" integer NOT NULL,
  "bucket_id" text NOT NULL,
  "key" text NOT NULL COLLATE "C",
  "etag" text NOT NULL,
  "owner_id" text NULL,
  "version" text NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY ("id"),
  CONSTRAINT "s3_multipart_uploads_parts_bucket_id_fkey" FOREIGN KEY ("bucket_id") REFERENCES "storage"."buckets" ("id") ON UPDATE NO ACTION ON DELETE NO ACTION,
  CONSTRAINT "s3_multipart_uploads_parts_upload_id_fkey" FOREIGN KEY ("upload_id") REFERENCES "storage"."s3_multipart_uploads" ("id") ON UPDATE NO ACTION ON DELETE CASCADE
);
-- Enable row-level security for "s3_multipart_uploads_parts" table
ALTER TABLE "storage"."s3_multipart_uploads_parts" ENABLE ROW LEVEL SECURITY;
-- Create "sso_providers" table
CREATE TABLE "auth"."sso_providers" (
  "id" uuid NOT NULL,
  "resource_id" text NULL,
  "created_at" timestamptz NULL,
  "updated_at" timestamptz NULL,
  "disabled" boolean NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "resource_id not empty" CHECK ((resource_id = NULL::text) OR (char_length(resource_id) > 0))
);
-- Create index "sso_providers_resource_id_idx" to table: "sso_providers"
CREATE UNIQUE INDEX "sso_providers_resource_id_idx" ON "auth"."sso_providers" ((lower(resource_id)));
-- Create index "sso_providers_resource_id_pattern_idx" to table: "sso_providers"
CREATE INDEX "sso_providers_resource_id_pattern_idx" ON "auth"."sso_providers" ("resource_id" text_pattern_ops);
-- Set comment to table: "sso_providers"
COMMENT ON TABLE "auth"."sso_providers" IS 'Auth: Manages SSO identity provider information; see saml_providers for SAML.';
-- Set comment to column: "resource_id" on table: "sso_providers"
COMMENT ON COLUMN "auth"."sso_providers"."resource_id" IS 'Auth: Uniquely identifies a SSO provider according to a user-chosen resource ID (case insensitive), useful in infrastructure as code.';
-- Enable row-level security for "sso_providers" table
ALTER TABLE "auth"."sso_providers" ENABLE ROW LEVEL SECURITY;
-- Create "saml_providers" table
CREATE TABLE "auth"."saml_providers" (
  "id" uuid NOT NULL,
  "sso_provider_id" uuid NOT NULL,
  "entity_id" text NOT NULL,
  "metadata_xml" text NOT NULL,
  "metadata_url" text NULL,
  "attribute_mapping" jsonb NULL,
  "created_at" timestamptz NULL,
  "updated_at" timestamptz NULL,
  "name_id_format" text NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "saml_providers_entity_id_key" UNIQUE ("entity_id"),
  CONSTRAINT "saml_providers_sso_provider_id_fkey" FOREIGN KEY ("sso_provider_id") REFERENCES "auth"."sso_providers" ("id") ON UPDATE NO ACTION ON DELETE CASCADE,
  CONSTRAINT "entity_id not empty" CHECK (char_length(entity_id) > 0),
  CONSTRAINT "metadata_url not empty" CHECK ((metadata_url = NULL::text) OR (char_length(metadata_url) > 0)),
  CONSTRAINT "metadata_xml not empty" CHECK (char_length(metadata_xml) > 0)
);
-- Create index "saml_providers_sso_provider_id_idx" to table: "saml_providers"
CREATE INDEX "saml_providers_sso_provider_id_idx" ON "auth"."saml_providers" ("sso_provider_id");
-- Set comment to table: "saml_providers"
COMMENT ON TABLE "auth"."saml_providers" IS 'Auth: Manages SAML Identity Provider connections.';
-- Enable row-level security for "saml_providers" table
ALTER TABLE "auth"."saml_providers" ENABLE ROW LEVEL SECURITY;
-- Create "flow_state" table
CREATE TABLE "auth"."flow_state" (
  "id" uuid NOT NULL,
  "user_id" uuid NULL,
  "auth_code" text NOT NULL,
  "code_challenge_method" "auth"."code_challenge_method" NOT NULL,
  "code_challenge" text NOT NULL,
  "provider_type" text NOT NULL,
  "provider_access_token" text NULL,
  "provider_refresh_token" text NULL,
  "created_at" timestamptz NULL,
  "updated_at" timestamptz NULL,
  "authentication_method" text NOT NULL,
  "auth_code_issued_at" timestamptz NULL,
  PRIMARY KEY ("id")
);
-- Create index "flow_state_created_at_idx" to table: "flow_state"
CREATE INDEX "flow_state_created_at_idx" ON "auth"."flow_state" ("created_at" DESC);
-- Create index "idx_auth_code" to table: "flow_state"
CREATE INDEX "idx_auth_code" ON "auth"."flow_state" ("auth_code");
-- Create index "idx_user_id_auth_method" to table: "flow_state"
CREATE INDEX "idx_user_id_auth_method" ON "auth"."flow_state" ("user_id", "authentication_method");
-- Set comment to table: "flow_state"
COMMENT ON TABLE "auth"."flow_state" IS 'stores metadata for pkce logins';
-- Enable row-level security for "flow_state" table
ALTER TABLE "auth"."flow_state" ENABLE ROW LEVEL SECURITY;
-- Create "saml_relay_states" table
CREATE TABLE "auth"."saml_relay_states" (
  "id" uuid NOT NULL,
  "sso_provider_id" uuid NOT NULL,
  "request_id" text NOT NULL,
  "for_email" text NULL,
  "redirect_to" text NULL,
  "created_at" timestamptz NULL,
  "updated_at" timestamptz NULL,
  "flow_state_id" uuid NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "saml_relay_states_flow_state_id_fkey" FOREIGN KEY ("flow_state_id") REFERENCES "auth"."flow_state" ("id") ON UPDATE NO ACTION ON DELETE CASCADE,
  CONSTRAINT "saml_relay_states_sso_provider_id_fkey" FOREIGN KEY ("sso_provider_id") REFERENCES "auth"."sso_providers" ("id") ON UPDATE NO ACTION ON DELETE CASCADE,
  CONSTRAINT "request_id not empty" CHECK (char_length(request_id) > 0)
);
-- Create index "saml_relay_states_created_at_idx" to table: "saml_relay_states"
CREATE INDEX "saml_relay_states_created_at_idx" ON "auth"."saml_relay_states" ("created_at" DESC);
-- Create index "saml_relay_states_for_email_idx" to table: "saml_relay_states"
CREATE INDEX "saml_relay_states_for_email_idx" ON "auth"."saml_relay_states" ("for_email");
-- Create index "saml_relay_states_sso_provider_id_idx" to table: "saml_relay_states"
CREATE INDEX "saml_relay_states_sso_provider_id_idx" ON "auth"."saml_relay_states" ("sso_provider_id");
-- Set comment to table: "saml_relay_states"
COMMENT ON TABLE "auth"."saml_relay_states" IS 'Auth: Contains SAML Relay State information for each Service Provider initiated login.';
-- Enable row-level security for "saml_relay_states" table
ALTER TABLE "auth"."saml_relay_states" ENABLE ROW LEVEL SECURITY;
-- Create "sso_domains" table
CREATE TABLE "auth"."sso_domains" (
  "id" uuid NOT NULL,
  "sso_provider_id" uuid NOT NULL,
  "domain" text NOT NULL,
  "created_at" timestamptz NULL,
  "updated_at" timestamptz NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "sso_domains_sso_provider_id_fkey" FOREIGN KEY ("sso_provider_id") REFERENCES "auth"."sso_providers" ("id") ON UPDATE NO ACTION ON DELETE CASCADE,
  CONSTRAINT "domain not empty" CHECK (char_length(domain) > 0)
);
-- Create index "sso_domains_domain_idx" to table: "sso_domains"
CREATE UNIQUE INDEX "sso_domains_domain_idx" ON "auth"."sso_domains" ((lower(domain)));
-- Create index "sso_domains_sso_provider_id_idx" to table: "sso_domains"
CREATE INDEX "sso_domains_sso_provider_id_idx" ON "auth"."sso_domains" ("sso_provider_id");
-- Set comment to table: "sso_domains"
COMMENT ON TABLE "auth"."sso_domains" IS 'Auth: Manages SSO email address domain mapping to an SSO Identity Provider.';
-- Enable row-level security for "sso_domains" table
ALTER TABLE "auth"."sso_domains" ENABLE ROW LEVEL SECURITY;
