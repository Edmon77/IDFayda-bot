# Add Your First User to the Bot

Your bot is working, but you need to add yourself as a user in the database first!

---

## 🚀 Quick Method: Use the Script

### Step 1: Get Your Telegram ID

1. Open Telegram
2. Search for **@userinfobot**
3. Send `/start` to it
4. It will reply with your ID (a number like `7284397926`)
5. **Copy that number**

### Step 2: Run the Script

**Option A: Run Locally (if you have Node.js)**

```bash
# Make sure you're in the project directory
cd c:\Users\Edmon\Documents\fayda-bot

# Run the script with your Telegram ID
node scripts/create-admin.js YOUR_TELEGRAM_ID
```

Replace `YOUR_TELEGRAM_ID` with the number from @userinfobot.

**Example:**
```bash
node scripts/create-admin.js 7284397926
```

**Option B: Add via MongoDB Atlas (No Code)**

1. Go to **MongoDB Atlas** → **Browse Collections**
2. Select database: `fayda_bot`
3. Click **"INSERT DOCUMENT"** in the `users` collection
4. Paste this JSON (replace `YOUR_TELEGRAM_ID` with your ID):

```json
{
  "telegramId": "YOUR_TELEGRAM_ID",
  "role": "admin",
  "firstName": "Admin",
  "createdAt": {"$date": "2026-02-21T00:00:00.000Z"},
  "lastActive": {"$date": "2026-02-21T00:00:00.000Z"}
}
```

5. Click **"Insert"**

---

## ✅ After Adding Yourself

1. **Go back to Telegram**
2. **Send `/start` to your bot again**
3. **You should now see:**
   ```
   🏠 Main Menu
   Choose an option:
   
   [📥 Download ID]
   [📊 Dashboard]
   [👥 Manage Users]
   ```

---

## 🔧 Alternative: Add via Railway (One-Time Command)

If you want to run the script on Railway:

1. Go to Railway → Your service → **Deployments**
2. Click **"..."** → **"Open Shell"** (or use Railway CLI)
3. Run:
   ```bash
   node scripts/create-admin.js YOUR_TELEGRAM_ID
   ```

---

## 📝 What the Script Does

- Creates a user with `role: 'admin'` in MongoDB
- Sets your Telegram ID
- Makes you a super admin (can manage all users)

---

## 🆘 Troubleshooting

**"User already exists"**
- Script will update them to admin if they're not already

**"MongoDB connection error"**
- Check your `MONGODB_URI` in `.env` or Railway Variables
- Make sure MongoDB Atlas allows connections from anywhere (`0.0.0.0/0`)

**"Cannot find module"**
- Make sure you're in the project directory
- Run `npm install` first

---

## 🎯 Next Steps

After adding yourself:

1. ✅ Test `/start` - should show admin menu
2. ✅ Test download flow
3. ✅ Add other users via "Manage Users" menu
4. ✅ Set expiry dates for buyers/sub-users

---

**Quick Command:**
```bash
node scripts/create-admin.js YOUR_TELEGRAM_ID
```

Replace `YOUR_TELEGRAM_ID` with your actual ID from @userinfobot!
