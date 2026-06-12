#!/usr/bin/env sh
set -eu

uvicorn server:app --host "${HOST:-0.0.0.0}" --port "${PORT:-8000}" --reload

