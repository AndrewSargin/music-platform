-- name: CreateSession :exec
INSERT INTO sessions (id, user_id, device_name, refresh_token_hash, refresh_token_expires_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6);

