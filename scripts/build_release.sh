#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DIST_DIR="$ROOT_DIR/dist"
RELEASE_FILE="$ROOT_DIR/.release-version"
if [[ ! -f "$RELEASE_FILE" ]]; then
  echo "69" > "$RELEASE_FILE"
fi
RELEASE_NUMBER="$(tr -d '[:space:]' < "$RELEASE_FILE")"
if [[ ! "$RELEASE_NUMBER" =~ ^[0-9]+$ ]]; then
  echo "Invalid release number in $RELEASE_FILE: $RELEASE_NUMBER" >&2
  exit 1
fi
ARCHIVE_NAME="LocalNetworkProtector_v${RELEASE_NUMBER}.tar.gz"
ARCHIVE_PATH="$DIST_DIR/$ARCHIVE_NAME"

mkdir -p "$DIST_DIR"

tar \
  --exclude='.git' \
  --exclude='dist' \
  --exclude='build' \
  --exclude='*.egg-info' \
  --exclude='config.yaml' \
  --exclude='config.yaml.live' \
  --exclude='venv' \
  --exclude='.venv' \
  --exclude='__pycache__' \
  --exclude='*.pyc' \
  --exclude='*.pyo' \
  --exclude='.DS_Store' \
  -czf "$ARCHIVE_PATH" \
  -C "$ROOT_DIR" \
  .

echo "Created release archive: $ARCHIVE_PATH"
