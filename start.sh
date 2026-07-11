#!/bin/sh
set -e

# Control port şifresi (Render'da environment variable olarak da set edebilirsin)
TOR_CONTROL_PASSWORD=${TOR_CONTROL_PASSWORD:-changeme123}

# Şifreyi Tor'un beklediği hash formatına çeviriyoruz
HASHED_PASSWORD=$(tor --hash-password "$TOR_CONTROL_PASSWORD" | tail -n 1)

# Tor'u arka planda başlat (SOCKS5 -> 9050, ControlPort -> 9051)
tor --SocksPort 9050 \
    --ControlPort 9051 \
    --HashedControlPassword "$HASHED_PASSWORD" \
    --RunAsDaemon 0 &

# Tor devrelerinin kurulması için kısa bir bekleme
sleep 8

# Flask/gunicorn'u Render'ın verdiği PORT üzerinde başlat
exec gunicorn -b 0.0.0.0:${PORT:-10000} app:app
