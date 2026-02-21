# 🧪 Bot Testing Guide

Complete guide to test your Fayda Bot after setup.

---

## ✅ Pre-Testing Checklist

Before testing, make sure:

- [ ] All environment variables are set in Railway Variables
- [ ] MongoDB URI is correct (tested connection)
- [ ] Redis URL is correct
- [ ] WEBHOOK_DOMAIN is your actual Railway URL (`https://xxx.up.railway.app`)
- [ ] Bot is deployed and running (check Railway logs)

---

## 🚀 Step 1: Check Bot is Running

### On Railway:

1. Go to your Railway dashboard
2. Click your **fayda-bot** service
3. Check **Logs** tab
4. You should see:
   ```
   ✅ Environment variables validated
   ✅ MongoDB connected successfully
   🚀 Server running on port 8080
   🤖 Webhook active at https://xxx.up.railway.app/webhook
   ```

**If you see errors:**
- ❌ "Missing environment variables" → Add missing vars in Railway Variables
- ❌ "MongoDB connection error" → Check MONGODB_URI format
- ❌ "Redis connection error" → Check REDIS_URL format

### Test Health Endpoint:

Open in browser:
```
https://YOUR-RAILWAY-URL/health
```

Should return:
```json
{
  "status": "ok",
  "timestamp": "2026-02-21T...",
  "uptime": 123.45
}
```

✅ **If this works, your server is running!**

---

## 🤖 Step 2: Test Bot in Telegram

### Basic Test:

1. **Open Telegram** (mobile or desktop)
2. **Search for your bot** by username (e.g., `@fayda_pdfbot`)
3. **Click "Start"** or send `/start`

**Expected Response:**
```
🏠 Main Menu
Choose an option:

[📥 Download ID]
```

✅ **If you see the menu, bot is working!**

### If Bot Doesn't Respond:

1. **Check Railway logs** for errors
2. **Verify WEBHOOK_DOMAIN** is correct:
   - Must be: `https://xxx.up.railway.app` (no trailing slash)
   - Check Railway Settings → Networking for exact URL
3. **Check BOT_TOKEN** is correct (from @BotFather)
4. **Wait 30 seconds** and try again (webhook might need time to register)

---

## 📥 Step 3: Test Download Flow

### Test with Real Fayda ID:

1. **Click "📥 Download ID"** button
2. **Enter a 16-digit Fayda Number** (e.g., `1234567890123456`)
3. **Wait for captcha solving** (may take 10-30 seconds)
4. **Enter OTP** sent to your phone
5. **Receive PDF** document

**Expected Flow:**
```
🏁 Fayda ID Downloader
Please enter your **16-digit Fayda Number**:

[You type: 1234567890123456]

⏳ Solving Captcha...
✅ Captcha Solved!

Enter the OTP sent to your phone:

[You type: 123456]

⏳ Verifying OTP and generating document...
✅ Your request has been queued. You will receive your PDF shortly.

[PDF arrives in chat]
✨ Your Digital ID is ready!
```

✅ **If PDF arrives, full flow works!**

### Common Issues:

| Issue | Solution |
|------|----------|
| "Too many requests" | Rate limit working (wait 60 seconds) |
| "Invalid format" | Enter exactly 16 digits |
| "Verification failed" | Check CAPTCHA_KEY is correct |
| "OTP failed" | OTP might be expired, try again |
| PDF doesn't arrive | Check Railway logs for queue errors |

---

## 👥 Step 4: Test Admin Features (if you're admin)

### If you're a Super Admin:

1. **Send `/start`** → Should see:
   ```
   [📥 Download ID]
   [📊 Dashboard]
   [👥 Manage Users]
   ```

2. **Click "📊 Dashboard"** → Should show user statistics

3. **Click "👥 Manage Users"** → Should list all buyers

### If you're a Buyer:

1. **Send `/start`** → Should see:
   ```
   [📥 Download ID]
   [📊 Dashboard]
   [👥 Manage Sub‑Users]
   ```

2. **Click "📊 Dashboard"** → Should show your stats

3. **Click "👥 Manage Sub‑Users"** → Should show your sub-users

---

## 🔍 Step 5: Check Logs for Issues

### On Railway:

1. Go to **Logs** tab
2. Look for:
   - ✅ Green messages = working
   - ⚠️ Yellow warnings = minor issues (usually OK)
   - ❌ Red errors = problems to fix

### Common Log Messages:

**Good:**
```
✅ Environment variables validated
✅ MongoDB connected successfully
🚀 Server running on port 8080
🤖 Webhook active at https://...
PDF job completed for user 123456789
```

**Warnings (usually OK):**
```
⚠️ WEBHOOK_DOMAIN looks like a placeholder
⚠️ Ignoring Telegram error: bot was blocked by the user
```

**Errors (need fixing):**
```
❌ MongoDB connection error: ...
❌ Redis connection error: ...
❌ Failed to start server: ...
```

---

## 🧪 Step 6: Test Rate Limiting

1. **Send `/start`** multiple times quickly (30+ times in 1 minute)
2. **Should see:** `⏳ Too many requests. Please wait X seconds.`
3. **Wait** the specified time
4. **Try again** → Should work

✅ **If rate limit works, Redis is connected!**

---

## 📊 Step 7: Verify Database

### Check MongoDB:

1. Go to **MongoDB Atlas** → **Browse Collections**
2. Select database: `fayda_bot`
3. Should see collection: `users`
4. After testing, should see user documents

**If empty:**
- Bot might not have created users yet
- Try sending `/start` again
- Check Railway logs for MongoDB errors

---

## ✅ Success Checklist

Your bot is working correctly if:

- [ ] Health endpoint returns `{"status":"ok"}`
- [ ] Bot responds to `/start` with main menu
- [ ] Download flow works (captcha → OTP → PDF)
- [ ] Rate limiting works (shows wait time, not NaN)
- [ ] No errors in Railway logs
- [ ] MongoDB has user data (after using bot)
- [ ] Admin features work (if you're admin)

---

## 🆘 Troubleshooting

### Bot Not Responding:

1. **Check webhook:**
   - Railway logs should show: `🤖 Webhook active at https://...`
   - If shows placeholder URL → Update WEBHOOK_DOMAIN

2. **Check BOT_TOKEN:**
   - Verify in Railway Variables
   - Must match @BotFather token exactly

3. **Check logs:**
   - Look for errors in Railway logs
   - Share error message if stuck

### PDF Not Arriving:

1. **Check queue:**
   - Railway logs should show: `PDF job completed`
   - If shows errors → Check Redis connection

2. **Check CAPTCHA_KEY:**
   - Verify in Railway Variables
   - Must be valid 2captcha API key

3. **Check OTP:**
   - Make sure OTP is correct
   - OTP expires quickly, enter fast

### Rate Limit Shows "NaN seconds":

1. **Already fixed** in latest code
2. **Push latest changes** if not deployed yet:
   ```bash
   git add .
   git commit -m "Fix rate limiting"
   git push origin main
   ```

---

## 🎉 You're Done!

If all tests pass, your bot is **production-ready** and can handle users!

**Next Steps:**
- Share bot username with users
- Monitor logs for issues
- Check MongoDB for user growth
- Enjoy your working bot! 🚀
