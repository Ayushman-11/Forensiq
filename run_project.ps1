# Forensiq Project Launcher for Windows PowerShell
$ErrorActionPreference = "Continue"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "         Starting Forensiq Platform       " -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# 1. Check MongoDB Service
$mongoService = Get-Service -Name "MongoDB" -ErrorAction SilentlyContinue
if ($mongoService) {
    if ($mongoService.Status -ne "Running") {
        Write-Host "[+] Starting MongoDB service..." -ForegroundColor Yellow
        Start-Service MongoDB -ErrorAction SilentlyContinue
    } else {
        Write-Host "[✓] MongoDB is running." -ForegroundColor Green
    }
} else {
    Write-Host "[!] MongoDB service not found. Ensure MongoDB is running locally on port 27017." -ForegroundColor Yellow
}

$rootDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# 2. Launch Backend in a new window
Write-Host "[+] Launching FastAPI Backend on http://localhost:8001..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$rootDir\backend'; Write-Host '--- Forensiq Backend (Port 8001) ---' -ForegroundColor Green; python -m uvicorn app.main:app --port 8001 --reload"

# 3. Launch Frontend in a new window
Write-Host "[+] Launching Next.js Frontend on http://localhost:3000..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$rootDir\frontend'; Write-Host '--- Forensiq Frontend (Port 3000) ---' -ForegroundColor Green; npm run dev"

Write-Host "==========================================" -ForegroundColor Green
Write-Host "All services started!" -ForegroundColor Green
Write-Host "Frontend Dashboard: http://localhost:3000" -ForegroundColor White
Write-Host "Backend API Docs:   http://localhost:8001/docs" -ForegroundColor White
Write-Host "==========================================" -ForegroundColor Green
