-- name: CreateSession :exec
INSERT INTO sessions (id, user_id, device_name, refresh_token_hash, refresh_token_expires_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: RotateSession :execresult
UPDATE sessions
    SET refresh_token_hash = $2,
        refresh_token_expires_at = $3
WHERE id = $1;

-- name: FindByRefreshTokenHash :one
SELECT id, user_id, refresh_token_expires_at
FROM sessions
WHERE refresh_token_hash = $1;

-- name: FindSessionByRefreshTokenHashForUpdate :one
SELECT id, user_id, refresh_token_expires_at
FROM sessions
WHERE refresh_token_hash = $1
FOR UPDATE;