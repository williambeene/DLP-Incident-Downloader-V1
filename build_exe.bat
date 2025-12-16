@echo off
echo ============================================
echo Building DLP Incident Downloader EXE
echo ============================================
echo.

REM Check if PyInstaller is installed
pip show pyinstaller >nul 2>&1
if errorlevel 1 (
    echo Installing PyInstaller...
    pip install pyinstaller
)

echo.
echo Building executable...
pyinstaller --onefile --windowed --name "DLP_Incident_Downloader" --icon=NONE dlp_incident_downloader.py

if errorlevel 1 (
    echo.
    echo ERROR: Build failed
    pause
    exit /b 1
)

echo.
echo ============================================
echo Build complete!
echo.
echo Executable located at:
echo   dist\DLP_Incident_Downloader.exe
echo ============================================
pause
