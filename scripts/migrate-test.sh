#!/usr/bin/env bash

set -euo pipefail

set -a
source .env
set +a

export GOOSE_DRIVER=postgres
export GOOSE_DBSTRING="$TEST_DATABASE_URL"
export GOOSE_MIGRATION_DIR=server/migrations