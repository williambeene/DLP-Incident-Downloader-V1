============================================
DLP 16.x Incident Downloader
============================================

A Python application for downloading and exporting DLP incident details
from Symantec/Broadcom DLP 16.x Enforce servers.

REQUIREMENTS
------------
- Python 3.8 or higher
- Windows 10/11 (tested)

INSTALLATION
------------
1. Install Python from https://www.python.org/downloads/
   (Make sure to check "Add Python to PATH" during installation)

2. Double-click install.bat
   OR run: pip install -r requirements.txt

RUNNING THE APPLICATION
-----------------------
Double-click run.bat
OR run: python dlp_incident_downloader.py

CREATING A STANDALONE EXE
-------------------------
Double-click build_exe.bat
The executable will be created in the dist\ folder.

FEATURES
--------
- Connect to DLP Enforce servers with Basic Authentication
- Support for multiple environment types (DAR, WEB, MAIL, ENDPOINT)
- Save and load environment configurations
- Fetch saved reports by ID
- Download all incident details including:
  - Static and editable attributes
  - Component matches and violations
  - Correlations
  - History
  - Policy matches
  - Attachments (when available)

EXPORT OPTIONS
--------------
1. JSON + Attachments - Creates folder structure with JSON and attachment files
2. JSON - Single JSON file with all incident data
3. CSV (Summary) - Flattened CSV with all details in columns
4. Individual JSON Files - One JSON file per incident

FILES
-----
- dlp_incident_downloader.py  - Main application
- requirements.txt            - Python dependencies
- install.bat                 - Installation script
- run.bat                     - Launch script
- build_exe.bat              - Build standalone EXE
- dlp_config.json            - Saved environments (created on first save)

TROUBLESHOOTING
---------------
1. SSL/TLS Errors: The app includes workarounds for older DLP servers
   with legacy SSL configurations.

2. Connection Refused: Check that:
   - Server URL is correct (include https://)
   - You can reach the server from your machine
   - Firewall is not blocking the connection

3. Authentication Failed: Verify username and password.
   Default username is "Administrator".

4. No incidents found: Make sure the Report ID exists and contains data.

SUPPORT
-------
For issues, check the Results/Log panel for detailed error messages.
