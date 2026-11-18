#!/usr/bin/env bash

set -euo pipefail

set -a
source .env
set +a

export GOOSE_DRIVER=postgres
export GOOSE_DBSTRING="postgres://%{POSTGRES_USER}:%{POSTGRESS_PASSWORD}@localhost:5432/%{POSTGRES_DB}?sslmode=disable"
export GOOSE_MIGRATION_DIR=server/migrations