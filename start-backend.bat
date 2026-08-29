@echo off
title Email Threat Intel - Backend API
cd /d "%~dp0"

echo Starting Docker database and cache services (PostgreSQL ^& Redis)...
docker compose up -d db redis
if %errorlevel% equ 0 (
    echo [OK] Docker PostgreSQL and Redis are running.
) else (
    echo [NOTE] Docker command skipped or failed. Proceeding with backend startup...
)

echo.
cd /d "%~dp0backend"
echo Starting FastAPI Backend at http://localhost:8000 ...
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
pause
