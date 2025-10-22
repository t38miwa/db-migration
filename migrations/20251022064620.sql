-- Create "categories" table
CREATE TABLE "public"."categories" (
  "id" serial NOT NULL,
  "name" text NOT NULL,
  "description" text NULL,
  "created_at" timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY ("id"),
  CONSTRAINT "categories_name_key" UNIQUE ("name")
);
