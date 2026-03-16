@echo off
echo.
echo  ==========================================
echo   NIRVANA LAN - Network Audit Tool
echo  ==========================================
echo.
echo  Checking Python...
python --version 2>nul
if errorlevel 1 (
    echo  ERROR: Python not found. Install Python 3.8+ from python.org
    pause
    exit /b 1
)

echo  Installing dependencies...
pip install flask psutil requests --quiet

echo.
echo  Starting Nirvana LAN...
echo  Browser will open at http://localhost:7777
echo.
python app.py

pause
