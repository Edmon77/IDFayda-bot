# Fayda Bot

A scalable Telegram bot for downloading Fayda ID documents with subscription management.

## Features

- 📥 Download Fayda ID PDFs via Telegram
- 👥 User management system (Admin, Buyer, Sub-user roles)
- 📊 Dashboard for tracking downloads and users
- ⚡ Queue-based PDF processing for scalability
- 🛡️ Rate limiting and security features
- 📈 Optimized for 300+ concurrent users

## Prerequisites

- Node.js 18+ 
- MongoDB database
- Redis instance
- Telegram Bot Token
- 2Captcha API key

## Environment Variables

Create a `.env` file with the following variables:

```env
# Bot Configuration
BOT_TOKEN=your_telegram_bot_token
CAPTCHA_KEY=your_2captcha_api_key

# Database
MONGODB_URI=mongodb://localhost:27017/fayda_bot
REDIS_URL=redis://localhost:6379

# Session & Security
SESSION_SECRET=your_random_secret_key_here

# Deployment
WEBHOOK_DOMAIN=https://your-domain.com
PORT=3000
NODE_ENV=production
```

## Installation

```bash
# Install dependencies
npm install

# Create logs directory
mkdir -p logs

# Start the application
npm start
```

## Deployment Options

### Option 1: Docker (Recommended)

```bash
# Build and run with Docker Compose
docker-compose up -d

# Or build and run manually
docker build -t fayda-bot .
docker run -d --env-file .env -p 3000:3000 fayda-bot
```

### Option 2: PM2 (Production)

```bash
# Install PM2 globally
npm install -g pm2

# Start with PM2
npm run pm2:start

# Monitor
pm2 monit

# View logs
pm2 logs fayda-bot
```

### Option 3: Render.com

1. Connect your GitHub repository
2. Set environment variables in Render dashboard
3. Set build command: `npm install`
4. Set start command: `node index.js`
5. Deploy!

### Option 4: Railway.app

1. Connect your GitHub repository
2. Add environment variables
3. Railway will auto-detect and deploy

### Option 5: DigitalOcean App Platform

1. Connect your GitHub repository
2. Configure environment variables
3. Set build command: `npm install`
4. Set start command: `node index.js`
5. Deploy!

## Architecture

### Scalability Features

- **Connection Pooling**: MongoDB connection pool (5-50 connections)
- **Queue System**: Bull queue with Redis for async PDF processing
- **Rate Limiting**: Per-user and per-IP rate limiting
- **Database Indexes**: Optimized queries with proper indexes
- **Error Handling**: Comprehensive error handling and logging
- **Health Checks**: `/health` endpoint for monitoring

### Performance Optimizations

- Batch database queries to avoid N+1 problems
- Async job processing for PDF generation
- Connection reuse and pooling
- Efficient session management

## Monitoring

- Health check endpoint: `GET /health`
- Logs are stored in `logs/` directory
- Winston logger for structured logging
- PM2 monitoring (if using PM2)

## Security

- Input validation for all user inputs
- Rate limiting to prevent abuse
- Secure session management
- Environment variable validation
- SQL injection protection (MongoDB)
- XSS protection

## Troubleshooting

### Bot not responding
- Check webhook URL is correct
- Verify BOT_TOKEN is valid
- Check logs for errors

### Database connection issues
- Verify MONGODB_URI is correct
- Check network connectivity
- Ensure database is accessible

### Queue not processing
- Verify REDIS_URL is correct
- Check Redis connection
- Review queue logs

## License

MIT
