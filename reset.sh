#!/bin/bash
set -e

echo "🛑 Stopping containers..."
podman-compose down 2>/dev/null || true

echo "🧹 Cleaning old data..."
rm -f data/inventory.sqlite
rm -f data/zeek_logs/*
rm -f uploads/*

echo "🔨 Building Zeek container with ICS plugins..."
podman build --network=host -t localhost/zeek-ics:test -f Dockerfile.zeek \
  --build-arg GITHUB_USER=letsgetweird .

echo "🚀 Starting containers..."
podman-compose up -d

echo "📋 Checking status..."
podman-compose ps

echo "✅ Done! Tailing logs (Ctrl+C to exit)..."
sleep 2
podman logs -f brick-web
