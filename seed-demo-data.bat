@echo off
REM MailForensix - Hackathon Demo Data Reset & Seeding Script
echo =========================================================
echo MailForensix - Resetting & Seeding Demo Dataset...
echo =========================================================

cd /d "%~dp0backend"
call .venv\Scripts\activate.bat
python scripts\seed_demo_data.py --confirm

if %ERRORLEVEL% equ 0 (
    echo.
    echo =========================================================
    echo [SUCCESS] Demo dataset successfully seeded!
    echo SOC Dashboard: http://localhost:5173
    echo API Docs:      http://localhost:8000/docs
    echo Login:         admin@mailforensix.local / admin123
    echo =========================================================
) else (
    echo.
    echo [ERROR] Demo seeding failed with exit code %ERRORLEVEL%
)

pause
