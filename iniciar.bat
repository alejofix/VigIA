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

if "%PORT%"=="" set PORT=8080

echo [*] Iniciando backend...
start uvicorn backend.main:app --host 0.0.0.0 --port %PORT% --reload

timeout /t 2 /nobreak >nul

echo [*] Abriendo dashboard...
start http://localhost:%PORT%

echo.
echo   VigIA corriendo en http://localhost:%PORT%
pause
