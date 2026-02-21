# PowerShell script to commit and push changes
# Run: .\commit-and-push.ps1

Write-Host "📝 Committing changes..." -ForegroundColor Yellow

# Stage all changes
git add .

# Commit with descriptive message
git commit -m "Fix: Improve error handling and webhook URL handling

- Fix MongoDB connection: remove deprecated bufferMaxEntries option
- Improve error handler: gracefully handle 'bot was blocked' errors
- Auto-add https:// to webhook URL if missing
- Prevent app crashes from common Telegram errors"

# Push to GitHub
Write-Host "⬆️  Pushing to GitHub..." -ForegroundColor Yellow
git push origin main

if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ Successfully pushed to GitHub!" -ForegroundColor Green
    Write-Host "🚀 Railway will auto-deploy the changes" -ForegroundColor Cyan
} else {
    Write-Host "❌ Push failed. Check your git status." -ForegroundColor Red
    Write-Host "💡 Try: git status" -ForegroundColor Yellow
}
