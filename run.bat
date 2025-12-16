@echo off
cd /d "%~dp0"
python dlp_incident_downloader.py
if errorlevel 1 pause
