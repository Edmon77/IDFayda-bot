# Deployment Guide

## Recommended Deployment Platforms

### 1. Railway.app (Best for Simplicity) ⭐ RECOMMENDED

**Why Railway:**
- Automatic HTTPS/SSL
- Built-in Redis and MongoDB options
- Easy environment variable management
- Auto-deploy from GitHub
- Free tier available
- Great for scaling

**Steps:**
1. Sign up at [railway.app](https://railway.app)
2. Click "New Project" → "Deploy from GitHub"
3. Select your repository
4. Add environment variables:
   - `BOT_TOKEN`
   - `CAPTCHA_KEY`
   - `MONGODB_URI` (use Railway's MongoDB plugin or external)
   - `REDIS_URL` (use Railway's Redis plugin or Upstash)
   - `SESSION_SECRET`
   - `WEBHOOK_DOMAIN` (Railway provides this automatically)
   - `NODE_ENV=production`
5. Railway will auto-detect Node.js and deploy
6. Copy the generated domain and update `WEBHOOK_DOMAIN`

**Cost:** Free tier available, then ~$5-20/month

---

### 2. Render.com (Best for Free Tier)

**Why Render:**
- Free tier with limitations
- Easy setup
- Auto-deploy from GitHub
- Built-in SSL

**Steps:**
1. Sign up at [render.com](https://render.com)
2. Create "New Web Service"
3. Connect GitHub repository
4. Configure:
   - Build Command: `npm install`
   - Start Command: `node index.js`
   - Environment: Node
5. Add environment variables (same as Railway)
6. Deploy!

**Cost:** Free tier (with limitations), then $7/month+

---

### 3. DigitalOcean App Platform

**Why DigitalOcean:**
- More control
- Better for production workloads
- Good documentation

**Steps:**
1. Sign up at [digitalocean.com](https://digitalocean.com)
2. Go to App Platform
3. Create new app from GitHub
4. Configure build and start commands
5. Add environment variables
6. Add MongoDB and Redis databases (or use external)
7. Deploy!

**Cost:** $5-12/month

---

### 4. AWS EC2 / Lightsail (Best for Control)

**Why AWS:**
- Full control
- Can handle high traffic
- Cost-effective at scale

**Steps:**
1. Launch EC2 instance (Ubuntu 22.04)
2. Install Node.js 18+:
   ```bash
   curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
   sudo apt-get install -y nodejs
   ```
3. Install PM2:
   ```bash
   sudo npm install -g pm2
   ```
4. Clone repository:
   ```bash
   git clone <your-repo>
   cd fayda-bot
   npm install
   ```
5. Set up environment variables
6. Start with PM2:
   ```bash
   npm run pm2:start
   ```
7. Set up Nginx reverse proxy
8. Configure SSL with Let's Encrypt

**Cost:** $5-20/month depending on instance

---

### 5. Docker + Any Cloud Provider

**Why Docker:**
- Consistent deployment
- Easy to scale
- Works anywhere

**Steps:**
1. Build Docker image:
   ```bash
   docker build -t fayda-bot .
   ```
2. Run container:
   ```bash
   docker run -d \
     --env-file .env \
     -p 3000:3000 \
     --name fayda-bot \
     fayda-bot
   ```
3. Or use docker-compose:
   ```bash
   docker-compose up -d
   ```

---

## Database Options

### MongoDB

**Recommended:**
- **MongoDB Atlas** (Free tier available)
- **Railway MongoDB** plugin
- **DigitalOcean Managed MongoDB**

**Connection String Format:**
```
mongodb+srv://username:password@cluster.mongodb.net/dbname?retryWrites=true&w=majority
```

### Redis

**Recommended:**
- **Upstash Redis** (Free tier, serverless)
- **Railway Redis** plugin
- **Redis Cloud** (Free tier)

**Connection String Format:**
```
rediss://default:password@host:6379
```

---

## Environment Variables Checklist

Before deploying, ensure you have:

- [ ] `BOT_TOKEN` - From @BotFather on Telegram
- [ ] `CAPTCHA_KEY` - From 2captcha.com
- [ ] `MONGODB_URI` - MongoDB connection string
- [ ] `REDIS_URL` - Redis connection string
- [ ] `SESSION_SECRET` - Random secret (generate with `openssl rand -hex 32`)
- [ ] `WEBHOOK_DOMAIN` - Your deployment URL (e.g., `https://your-app.railway.app`)
- [ ] `PORT` - Usually 3000 (or let platform set it)
- [ ] `NODE_ENV` - Set to `production`

---

## Post-Deployment Checklist

- [ ] Verify health endpoint: `https://your-domain.com/health`
- [ ] Check webhook is set: Test bot with `/start`
- [ ] Monitor logs for errors
- [ ] Test download flow end-to-end
- [ ] Set up monitoring/alerts (optional)
- [ ] Configure backup for database (if needed)

---

## Scaling for 300+ Users

### Current Configuration Supports:
- ✅ 300 concurrent users
- ✅ Queue-based processing (10 concurrent jobs)
- ✅ Rate limiting (30 requests/min per user)
- ✅ Connection pooling (5-50 MongoDB connections)

### To Scale Further:

1. **Horizontal Scaling:**
   - Run multiple instances behind load balancer
   - Use PM2 cluster mode (already configured)
   - Or use Docker Swarm/Kubernetes

2. **Database:**
   - Use MongoDB replica set
   - Add read replicas
   - Optimize indexes

3. **Redis:**
   - Use Redis Cluster for high availability
   - Monitor memory usage

4. **Monitoring:**
   - Set up APM (Application Performance Monitoring)
   - Monitor queue length
   - Alert on errors

---

## Troubleshooting

### Bot Not Responding
1. Check webhook URL matches `WEBHOOK_DOMAIN`
2. Verify bot token is correct
3. Check logs for errors
4. Test health endpoint

### High Memory Usage
1. Reduce PM2 instances
2. Lower queue concurrency
3. Check for memory leaks

### Slow Responses
1. Check database connection
2. Monitor queue length
3. Verify Redis is working
4. Check network latency

---

## Support

For issues or questions:
1. Check logs in `logs/` directory
2. Review error messages
3. Check platform-specific logs
4. Verify all environment variables are set
