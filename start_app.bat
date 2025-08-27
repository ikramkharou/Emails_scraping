@echo off
echo Starting Gmail Scraper Application...
echo.

REM Activate virtual environment
call venv\Scripts\activate.bat

REM Start the Flask application
echo Starting Flask application on http://localhost:5000
python app.py

pause
