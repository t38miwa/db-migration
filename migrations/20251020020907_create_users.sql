-- Create "users" table
CREATE TABLE "public"."users" (
  "id" serial NOT NULL,
  "name" text NOT NULL,
  "email" text NOT NULL,
  "age" integer NULL,
  PRIMARY KEY ("id")
);
