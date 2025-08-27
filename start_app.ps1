Write-Host "Starting Gmail Scraper Application..." -ForegroundColor Green
Write-Host ""

# Activate virtual environment
Write-Host "Activating virtual environment..." -ForegroundColor Yellow
& "venv\Scripts\Activate.ps1"

# Start the Flask application
Write-Host "Starting Flask application on http://localhost:5000" -ForegroundColor Cyan
python app.py

Write-Host "Press any key to continue..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
