#!/bin/bash
PORT=${PORT:-8080}
if ! curl -sf "http://localhost:${PORT}/api/stats" > /dev/null 2>&1; then
    cd /opt/lampp/htdocs/VigIA && nohup .venv/bin/uvicorn backend.main:app --host 0.0.0.0 --port "${PORT}" &>/tmp/vigia.log &
fi
