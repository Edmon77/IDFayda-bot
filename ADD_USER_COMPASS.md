# Add Your First Admin User with MongoDB Compass

Step-by-step guide using MongoDB Compass.

---

## 1. Get Your Telegram ID

1. Open **Telegram**
2. Search for **@userinfobot**
3. Send **/start**
4. Copy the **ID number** it sends (e.g. `7284397926`)

---

## 2. Connect in MongoDB Compass

1. Open **MongoDB Compass**
2. Paste your **connection string** (same as in `.env`):
   ```
   mongodb+srv://YOUR_USER:YOUR_PASSWORD@cluster0.xxxxx.mongodb.net
   ```
   Or use the one from Atlas: **Connect** → **Compass** → copy the URI.
3. Click **Connect**

---

## 3. Open the Database and Collection

1. In the left sidebar, click your **cluster**
2. Open database: **fayda_bot**
   - If it doesn’t exist yet, click **Create Database**, name it `fayda_bot`, create collection `users`
3. Click the **users** collection
   - If `users` doesn’t exist: right‑click `fayda_bot` → **Create Collection** → name: `users`

---

## 4. Add Your Admin Document

1. Click **ADD DATA** → **Insert Document**
2. You’ll see an empty JSON document like `{ }`
3. Replace it with this (use **your** Telegram ID):

```json
{
  "telegramId": "7284397926",
  "role": "admin",
  "firstName": "Admin",
  "createdAt": {"$date": "2026-02-21T00:00:00.000Z"},
  "lastActive": {"$date": "2026-02-21T00:00:00.000Z"}
}
```

4. Change **"7284397926"** to your real Telegram ID (as a string, in quotes)
5. Click **Insert**

---

## 5. Check It’s There

- You should see one document in **users** with:
  - `telegramId`: your ID  
  - `role`: `"admin"`

---

## 6. Test the Bot

1. Open **Telegram**
2. Open your bot (e.g. @fayda_pdfbot)
3. Send **/start**

You should see the main menu with **Download ID**, **Dashboard**, **Manage Users**.

---

## Quick Reference

| Field         | Value                          |
|--------------|---------------------------------|
| telegramId   | Your ID from @userinfobot       |
| role         | "admin"                         |
| firstName    | "Admin" (or your name)          |
| createdAt    | Any recent date                 |
| lastActive   | Any recent date                 |

---

## If You Get Errors

**“Database/collection doesn’t exist”**  
- Create database `fayda_bot`, then collection `users`, then insert the document.

**“Duplicate key”**  
- A user with that `telegramId` already exists. Find that document, edit it, and set `"role": "admin"`.

**Bot still says “not authorized”**  
- Confirm `telegramId` in Compass matches the number from @userinfobot exactly (no extra spaces, same number).
- Restart the bot / wait a few seconds and try `/start` again.
