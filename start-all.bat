@echo off
title Email Threat Intel - Start All
cd /d "%~dp0"
echo Starting Docker containers...
docker compose up -d
echo Starting Backend in new window...
start "Email Threat Intel - Backend" cmd /k "%~dp0start-backend.bat"
echo Starting Frontend in new window...
start "Email Threat Intel - Frontend" cmd /k "%~dp0start-frontend.bat"
echo All services launched!
