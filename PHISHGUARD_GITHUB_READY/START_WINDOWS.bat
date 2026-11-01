@echo off
cd /d "%~dp0"
echo Installing project dependencies...
python -m pip install -r requirements.txt
if errorlevel 1 (
  echo Python or installation missing. Install Python 3.11 or 3.12 first.
  pause
  exit /b 1
)
echo Opening PhishGuard-PK at http://127.0.0.1:7860
python run.py
pause
