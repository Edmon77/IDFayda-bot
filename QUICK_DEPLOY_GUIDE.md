# 🚀 Quick Deployment Guide

## Option 1: Railway.app (EASIEST - Recommended) ⭐

### Step-by-Step:

1. **Sign Up**
   - Go to https://railway.app
   - Sign up with GitHub (easiest)

2. **Create New Project**
   - Click "New Project"
   - Select "Deploy from GitHub repo"
   - Choose your repository: `Edmon77/IDFayda-bot`
   - Click "Deploy Now"

3. **Add Environment Variables**
   - Go to your project → Variables tab
   - Add these variables one by one:

   ```
   BOT_TOKEN=your_telegram_bot_token
   CAPTCHA_KEY=your_2captcha_key
   MONGODB_URI=mongodb+srv://...
   REDIS_URL=rediss://...
   SESSION_SECRET=your_random_secret
   WEBHOOK_DOMAIN=https://your-app-name.railway.app
   NODE_ENV=production
   PORT=3000
   ```

4. **Get MongoDB (if you don't have one)**
   - In Railway, click "New" → "Database" → "MongoDB"
   - Copy the connection string to `MONGODB_URI`

5. **Get Redis (if you don't have one)**
   - Option A: Use Railway's Redis plugin
   - Option B: Use Upstash (free): https://upstash.com
     - Create Redis database
     - Copy connection URL to `REDIS_URL`

6. **Update WEBHOOK_DOMAIN**
   - Railway gives you a domain like: `your-app-name.railway.app`
   - Set `WEBHOOK_DOMAIN=https://your-app-name.railway.app`

7. **Deploy!**
   - Railway auto-deploys when you push to GitHub
   - Or click "Deploy" button
   - Wait 2-3 minutes

8. **Test**
   - Check health: `https://your-app-name.railway.app/health`
   - Test bot: Send `/start` to your Telegram bot

**Cost:** Free tier available, then ~$5/month

---

## Option 2: Render.com (Good Free Option)

### Step-by-Step:

1. **Sign Up**
   - Go to https://render.com
   - Sign up with GitHub

2. **Create New Web Service**
   - Click "New +" → "Web Service"
   - Connect your GitHub repo: `Edmon77/IDFayda-bot`

3. **Configure**
   - Name: `fayda-bot`
   - Region: Choose closest to you
   - Branch: `main`
   - Root Directory: (leave empty)
   - Runtime: `Node`
   - Build Command: `npm install`
   - Start Command: `node index.js`

4. **Add Environment Variables**
   - Scroll to "Environment Variables"
   - Add all variables (same as Railway above)

5. **Get Databases**
   - **MongoDB**: Use MongoDB Atlas (free): https://www.mongodb.com/cloud/atlas
     - Create cluster → Get connection string
   - **Redis**: Use Upstash (free): https://upstash.com
     - Create database → Copy URL

6. **Deploy**
   - Click "Create Web Service"
   - Wait 5-10 minutes for first deploy

7. **Update WEBHOOK_DOMAIN**
   - Render gives you: `your-app.onrender.com`
   - Update `WEBHOOK_DOMAIN` in environment variables
   - Redeploy

**Cost:** Free tier (spins down after inactivity), then $7/month

---

## Option 3: DigitalOcean App Platform

### Step-by-Step:

1. **Sign Up**
   - Go to https://digitalocean.com
   - Sign up (get $200 free credit)

2. **Create App**
   - Go to App Platform → "Create App"
   - Connect GitHub → Select `Edmon77/IDFayda-bot`

3. **Configure**
   - Name: `fayda-bot`
   - Region: Choose closest
   - Branch: `main`
   - Build Command: `npm install`
   - Run Command: `node index.js`

4. **Add Databases**
   - Click "Add Resource" → "Database"
   - Add MongoDB (or use external)
   - Add Redis (or use external)

5. **Add Environment Variables**
   - Go to Settings → Environment Variables
   - Add all variables

6. **Deploy**
   - Click "Create Resources"
   - Wait for deployment

**Cost:** $5-12/month

---

## Option 4: Docker (Works Anywhere)

### If you have a VPS/Server:

```bash
# 1. Clone repository
git clone https://github.com/Edmon77/IDFayda-bot.git
cd IDFayda-bot

# 2. Create .env file
cp .env.example .env
# Edit .env with your values

# 3. Run with Docker Compose
docker-compose up -d

# 4. Check logs
docker-compose logs -f
```

### Or use Docker on any cloud:
- AWS EC2
- Google Cloud Run
- Azure Container Instances
- Any VPS provider

---

## 📋 Pre-Deployment Checklist

Before deploying, make sure you have:

- [ ] **Telegram Bot Token**
  - Get from @BotFather on Telegram
  - Command: `/newbot` → Follow instructions

- [ ] **2Captcha API Key**
  - Sign up at https://2captcha.com
  - Get API key from dashboard

- [ ] **MongoDB Connection String**
  - Option 1: MongoDB Atlas (free): https://www.mongodb.com/cloud/atlas
  - Option 2: Railway MongoDB plugin
  - Format: `mongodb+srv://user:pass@cluster.mongodb.net/dbname`

- [ ] **Redis Connection String**
  - Option 1: Upstash (free): https://upstash.com
  - Option 2: Railway Redis plugin
  - Format: `rediss://default:password@host:6379`

- [ ] **Session Secret**
  - Generate random string: `openssl rand -hex 32`
  - Or use: https://randomkeygen.com

- [ ] **Webhook Domain**
  - Will be provided by your hosting platform
  - Format: `https://your-app-name.platform.com`

---

## 🔧 Post-Deployment Steps

After deploying:

1. **Test Health Endpoint**
   ```
   https://your-domain.com/health
   ```
   Should return: `{"status":"ok",...}`

2. **Test Bot**
   - Open Telegram
   - Find your bot
   - Send `/start`
   - Should see main menu

3. **Test Download Flow**
   - Click "Download ID"
   - Enter 16-digit Fayda number
   - Complete OTP
   - Should receive PDF

4. **Monitor Logs**
   - Check platform logs
   - Look for errors
   - Verify queue is processing

5. **Set Up Monitoring** (Optional)
   - Use platform's monitoring tools
   - Set up alerts for errors
   - Monitor queue length

---

## 🆘 Troubleshooting

### Bot Not Responding?
1. Check `WEBHOOK_DOMAIN` matches your deployment URL
2. Verify `BOT_TOKEN` is correct
3. Check logs for errors
4. Test health endpoint

### Database Connection Failed?
1. Verify `MONGODB_URI` is correct
2. Check MongoDB allows connections from your IP (if using Atlas)
3. Verify credentials are correct

### Redis Connection Failed?
1. Verify `REDIS_URL` is correct
2. Check Redis is accessible
3. Try connecting manually

### High Memory Usage?
1. Reduce PM2 instances in `ecosystem.config.js`
2. Lower queue concurrency in `queue.js`
3. Upgrade your plan

---

## 💰 Cost Comparison

| Platform | Free Tier | Paid Tier | Best For |
|----------|-----------|-----------|----------|
| Railway | ✅ Limited | $5-20/mo | Easiest setup |
| Render | ✅ (spins down) | $7+/mo | Free tier |
| DigitalOcean | ❌ | $5-12/mo | More control |
| Docker/VPS | ❌ | $5-20/mo | Full control |

---

## 🎯 Recommended: Start with Railway

**Why Railway?**
- ✅ Easiest setup (5 minutes)
- ✅ Auto-deploys from GitHub
- ✅ Built-in databases
- ✅ Free tier available
- ✅ Great documentation

**Next Steps:**
1. Sign up at https://railway.app
2. Deploy from GitHub
3. Add environment variables
4. Test your bot!

---

## 📚 More Help

- Full deployment guide: `DEPLOYMENT.md`
- Improvements summary: `IMPROVEMENTS_SUMMARY.md`
- README: `README.md`

Need help? Check the logs or review the troubleshooting section above!
