@echo off
echo ============================================
echo DLP Incident Downloader - Installation
echo ============================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8+ from https://www.python.org/downloads/
    pause
    exit /b 1
)

echo Installing required packages...
pip install -r requirements.txt

if errorlevel 1 (
    echo.
    echo ERROR: Failed to install packages
    pause
    exit /b 1
)

echo.
echo ============================================
echo Installation complete!
echo.
echo To run the application:
echo   python dlp_incident_downloader.py
echo.
echo Or double-click: run.bat
echo ============================================
pause
