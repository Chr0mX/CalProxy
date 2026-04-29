#!/bin/sh
set -e

# Derive the data directory from DATA_FILE env var.
DATA_DIR="$(dirname "${DATA_FILE:-/data/sources.json}")"

log() { echo "[CalProxy] INFO: $*"; }
warn() { echo "[CalProxy] WARN: $*" >&2; }
fatal() { echo "[CalProxy] FATAL: $*" >&2; exit 1; }

mkdir -p "$DATA_DIR" || fatal "cannot create data directory: $DATA_DIR"

# ── UID/GID handling ─────────────────────────────────────────────────────────
# Set PUID and PGID in docker-compose.yml to match the host user that owns
# the bind-mounted data directory. Omit them to run as the built-in calproxy
# user (suitable for named volumes).

PUID="${PUID:-}"
PGID="${PGID:-}"

if [ -n "$PUID" ] && [ -n "$PGID" ]; then
  log "Applying PUID=$PUID PGID=$PGID"

  # Create the group if no group with this GID exists yet.
  if ! getent group "$PGID" > /dev/null 2>&1; then
    addgroup -g "$PGID" calproxy_host || warn "addgroup failed; continuing"
  fi

  # Create the user if no user with this UID exists yet.
  if ! getent passwd "$PUID" > /dev/null 2>&1; then
    GRP="$(getent group "$PGID" | cut -d: -f1)"
    adduser -u "$PUID" -G "$GRP" -s /bin/sh -D calproxy_host || warn "adduser failed; continuing"
  fi

  chown -R "${PUID}:${PGID}" "$DATA_DIR" \
    || fatal "cannot chown $DATA_DIR to ${PUID}:${PGID} — check host permissions"

  exec su-exec "${PUID}:${PGID}" ./calproxy "$@"
else
  # Default: run as the built-in calproxy user created in the Dockerfile.
  chown calproxy:calproxy "$DATA_DIR" \
    || fatal "cannot chown $DATA_DIR to calproxy — check volume permissions"

  exec su-exec calproxy ./calproxy "$@"
fi
