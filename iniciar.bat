@echo off
REM VigIA - Lanzador Windows
cd /d "%~dp0"

echo === VigIA - Monitoreo Inteligente de Redes ===

IF NOT EXIST ".venv" (
    echo [*] Creando entorno virtual...
    python -m venv .venv
)

CALL .venv\Scripts\activate.bat

IF NOT EXIST ".venv\installed" (
    echo [*] Instalando dependencias...
    pip install -q -r requirements.txt
    type NUL > .venv\installed
)

echo [*] Iniciando backend...
start uvicorn backend.main:app --host 0.0.0.0 --port 8080 --reload

timeout /t 2 /nobreak >nul

echo [*] Abriendo dashboard...
start http://localhost:8080

echo.
echo   VigIA corriendo en http://localhost:8080
pause
