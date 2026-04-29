#!/bin/sh
set -e

# Derive the data directory from DATA_FILE (default: /data/sources.json).
DATA_DIR="$(dirname "${DATA_FILE:-/data/sources.json}")"

# Create the directory if it doesn't exist (handles host-path bind mounts
# where Docker creates the directory as root before the container starts).
mkdir -p "$DATA_DIR"

# Hand ownership to calproxy so the app can write sources.json regardless of
# whether a named volume or a host-path bind mount is used.
chown calproxy:calproxy "$DATA_DIR"

exec su-exec calproxy ./calproxy "$@"
