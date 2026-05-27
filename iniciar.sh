#!/bin/bash
# VigIA - Lanzador Linux/Mac
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

echo "=== VigIA - Monitoreo Inteligente de Redes ==="

# Verificar venv
if [ ! -d ".venv" ]; then
    echo "[*] Creando entorno virtual..."
    python3 -m venv .venv
fi

source .venv/bin/activate

# Verificar dependencias
if [ ! -f ".venv/installed" ]; then
    echo "[*] Instalando dependencias..."
    pip install -q -r requirements.txt
    touch .venv/installed
fi

# Verificar nmap
if ! command -v nmap &> /dev/null; then
    echo "[!] nmap no encontrado. Instala: sudo apt install nmap"
fi

echo "[*] Iniciando backend (con reinicio automatico)..."
while true; do
    echo "[*] $(date) - Iniciando servidor..."
    PORT=${PORT:-8080}
    uvicorn backend.main:app --host 0.0.0.0 --port "$PORT"
    echo "[!] $(date) - Servidor caido. Reiniciando en 2 segundos..."
    sleep 2
done
