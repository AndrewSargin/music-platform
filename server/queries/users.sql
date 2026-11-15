-- name: CreateUser :one
INSERT INTO users (id, username, display_name, email, password_hash)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: FindByUsername :one
SELECT username, email, password_hash
FROM users
WHERE username = $1;

-- name: FindByEmail :one
SELECT username, email, password_hash
FROM users
WHERE email = $1;