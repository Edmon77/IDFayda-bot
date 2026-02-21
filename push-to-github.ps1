# PowerShell script to push code to GitHub
# Run this script in PowerShell: .\push-to-github.ps1

Write-Host "🚀 Pushing code to GitHub..." -ForegroundColor Green

# Check if git is installed
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Host "❌ Git is not installed or not in PATH" -ForegroundColor Red
    exit 1
}

# Check if we're in a git repository
if (-not (Test-Path .git)) {
    Write-Host "📦 Initializing git repository..." -ForegroundColor Yellow
    git init
}

# Check remote
$remoteExists = git remote get-url origin 2>$null
if (-not $remoteExists) {
    Write-Host "➕ Adding remote repository..." -ForegroundColor Yellow
    git remote add origin https://github.com/Edmon77/IDFayda-bot.git
} else {
    Write-Host "🔄 Updating remote URL..." -ForegroundColor Yellow
    git remote set-url origin https://github.com/Edmon77/IDFayda-bot.git
}

# Stage all files
Write-Host "📝 Staging files..." -ForegroundColor Yellow
git add .

# Check if there are changes to commit
$status = git status --porcelain
if (-not $status) {
    Write-Host "✅ No changes to commit" -ForegroundColor Green
    exit 0
}

# Commit changes
Write-Host "💾 Committing changes..." -ForegroundColor Yellow
git commit -m "🚀 Major improvements: scalability, error handling, rate limiting, deployment ready

- Added Winston logger for structured logging
- Implemented queue-based async PDF processing
- Added MongoDB connection pooling
- Optimized database queries (fixed N+1 issues)
- Added rate limiting (per-user and per-IP)
- Added input validation and security improvements
- Created Docker and PM2 deployment configurations
- Added health check endpoint
- Optimized for 300+ concurrent users
- Comprehensive error handling throughout"

# Push to GitHub
Write-Host "⬆️  Pushing to GitHub..." -ForegroundColor Yellow
git branch -M main
git push -u origin main

if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ Successfully pushed to GitHub!" -ForegroundColor Green
    Write-Host "🔗 Repository: https://github.com/Edmon77/IDFayda-bot" -ForegroundColor Cyan
} else {
    Write-Host "❌ Push failed. You may need to authenticate." -ForegroundColor Red
    Write-Host "💡 Try: git push -u origin main" -ForegroundColor Yellow
}
