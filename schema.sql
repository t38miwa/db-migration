CREATE TABLE users (
    id serial PRIMARY KEY,
    name text NOT NULL,
    email text NOT NULL,
    age integer,
    address text,
    sports text
);

CREATE TABLE posts (
    id serial PRIMARY KEY,
    title text NOT NULL,
    content text,
    user_id integer REFERENCES users (id),
    created_at timestamp DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp DEFAULT CURRENT_TIMESTAMP
);
