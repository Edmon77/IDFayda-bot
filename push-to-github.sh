#!/bin/bash
# Bash script to push code to GitHub
# Run this script: bash push-to-github.sh

echo "🚀 Pushing code to GitHub..."

# Check if git is installed
if ! command -v git &> /dev/null; then
    echo "❌ Git is not installed"
    exit 1
fi

# Check if we're in a git repository
if [ ! -d .git ]; then
    echo "📦 Initializing git repository..."
    git init
fi

# Check remote
if ! git remote get-url origin &> /dev/null; then
    echo "➕ Adding remote repository..."
    git remote add origin https://github.com/Edmon77/IDFayda-bot.git
else
    echo "🔄 Updating remote URL..."
    git remote set-url origin https://github.com/Edmon77/IDFayda-bot.git
fi

# Stage all files
echo "📝 Staging files..."
git add .

# Check if there are changes to commit
if [ -z "$(git status --porcelain)" ]; then
    echo "✅ No changes to commit"
    exit 0
fi

# Commit changes
echo "💾 Committing changes..."
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
echo "⬆️  Pushing to GitHub..."
git branch -M main
git push -u origin main

if [ $? -eq 0 ]; then
    echo "✅ Successfully pushed to GitHub!"
    echo "🔗 Repository: https://github.com/Edmon77/IDFayda-bot"
else
    echo "❌ Push failed. You may need to authenticate."
    echo "💡 Try: git push -u origin main"
fi
