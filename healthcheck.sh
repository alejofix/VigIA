#!/bin/bash
if ! curl -sf http://localhost:8080/api/stats > /dev/null 2>&1; then
    cd /opt/lampp/htdocs/VigIA && nohup .venv/bin/uvicorn backend.main:app --host 0.0.0.0 --port 8080 &>/tmp/vigia.log &
fi
