# PowerShell script to update package-lock.json
# Run this: .\update-lockfile.ps1

Write-Host "🔄 Updating package-lock.json..." -ForegroundColor Yellow

# Remove old lock file
if (Test-Path package-lock.json) {
    Remove-Item package-lock.json
    Write-Host "✅ Removed old package-lock.json" -ForegroundColor Green
}

# Install dependencies to regenerate lock file
Write-Host "📦 Installing dependencies..." -ForegroundColor Yellow
npm install

if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ package-lock.json updated successfully!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Cyan
    Write-Host "1. git add package-lock.json" -ForegroundColor White
    Write-Host "2. git commit -m 'Update package-lock.json'" -ForegroundColor White
    Write-Host "3. git push origin main" -ForegroundColor White
} else {
    Write-Host "❌ Failed to update package-lock.json" -ForegroundColor Red
    Write-Host "Try running: npm install" -ForegroundColor Yellow
}
