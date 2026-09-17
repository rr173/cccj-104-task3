#!/bin/sh
# Reproducible container entrypoint.
#   default          -> run the FOTA API server
#   test [args...]   -> run the pytest suite
#   anything else    -> executed as-is (e.g. a simulator fleet run)
set -e

if [ "$1" = "test" ]; then
    shift
    exec python -m pytest -q "$@"
fi

if [ "$#" -gt 0 ]; then
    exec "$@"
fi

exec uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-8080}"
