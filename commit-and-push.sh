#!/bin/bash
# Bash script to commit and push changes
# Run: bash commit-and-push.sh

echo "📝 Committing changes..."

# Stage all changes
git add .

# Commit with descriptive message
git commit -m "Fix: Improve error handling and webhook URL handling

- Fix MongoDB connection: remove deprecated bufferMaxEntries option
- Improve error handler: gracefully handle 'bot was blocked' errors
- Auto-add https:// to webhook URL if missing
- Prevent app crashes from common Telegram errors"

# Push to GitHub
echo "⬆️  Pushing to GitHub..."
git push origin main

if [ $? -eq 0 ]; then
    echo "✅ Successfully pushed to GitHub!"
    echo "🚀 Railway will auto-deploy the changes"
else
    echo "❌ Push failed. Check your git status."
    echo "💡 Try: git status"
fi
