@echo off
echo ============================================
echo   NetMon - Indigenous Network Monitoring
echo ============================================
echo.

:: Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python not found. Please install Python 3.9+
    pause
    exit /b 1
)

:: Install dependencies if needed
echo [1/3] Checking dependencies...
pip install -r requirements.txt -q --no-warn-script-location

echo [2/3] Starting NetMon server...
echo.
echo  Dashboard : http://127.0.0.1:5000
echo  Admin     : admin / admin123
echo  Viewer    : viewer / viewer123
echo.
echo  Press Ctrl+C to stop
echo ============================================

:: Run the app
python app.py

pause
