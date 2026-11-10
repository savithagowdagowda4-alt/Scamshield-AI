@echo off
title ScamShield AI - Multi-Channel Scam Detection Platform
cd /d "%~dp0"

echo ====================================================================
echo   SCAMSHIELD AI - MULTI-CHANNEL SCAM DETECTION PLATFORM
echo ====================================================================

if not exist "venv\Scripts\python.exe" (
    echo [1/3] Creating local Python virtual environment...
    python -m venv venv
)

echo [2/3] Verifying and installing required dependencies...
call venv\Scripts\pip.exe install -r requirements.txt

echo [3/3] Launching ScamShield AI on http://127.0.0.1:5000 ...
start "" "http://127.0.0.1:5000"
call venv\Scripts\python.exe run.py
pause
