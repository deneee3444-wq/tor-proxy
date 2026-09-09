#!/bin/sh
set -e

TOR_CONTROL_PASSWORD=${TOR_CONTROL_PASSWORD:-changeme123}
HASHED_PASSWORD=$(tor --hash-password "$TOR_CONTROL_PASSWORD" | tail -n 1)

tor --SocksPort 9050 \
    --ControlPort 9051 \
    --HashedControlPassword "$HASHED_PASSWORD" \
    --RunAsDaemon 0 &

sleep 8

exec gunicorn -k gthread --threads 100 -b 0.0.0.0:${PORT:-10000} app:app
