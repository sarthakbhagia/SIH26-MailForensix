@echo off
title Email Threat Intel - Backend API
cd /d "%~dp0backend"
echo Starting FastAPI Backend at http://localhost:8000 ...
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
pause
