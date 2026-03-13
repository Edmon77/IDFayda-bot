# Yegara VPS Deployment Guide - fayda-bot

This guide provides step-by-step instructions for deploying `fayda-bot` on a **Yegara Unmanaged VPS** (Ubuntu 22.04).

---

## 🚀 1. Initial Server Security

Since your VPS is unmanaged, you are responsible for its security. Do these first.

### Step 1.1: Log in via SSH
Replace `YOUR_VPS_IP` with the IP provided by Yegara.
```bash
ssh root@YOUR_VPS_IP
```

### Step 1.2: Update System & Create User
```bash
# Update software
apt update && apt upgrade -y

# Create a non-root user (e.g., 'deploy')
adduser deploy
usermod -aG sudo deploy

# Switch to the new user
su - deploy
```

### Step 1.3: Configure Firewall (UFW)
```bash
# Allow essential ports
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 3000/tcp

# Enable firewall
sudo ufw enable
```

---

## 🛠️ 2. Environment Setup

### Step 2.1: Install Node.js (via NVM)
```bash
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash
source ~/.bashrc
nvm install 20
nvm use 20
node -v # Should be v20.x
```

### Step 2.2: Database Preparation (External)
Since you've decided to use external databases (Recommended for performance):

1. **MongoDB Atlas:** [Follow this guide](https://www.mongodb.com/docs/atlas/getting-started/) to create a free cluster and get your connection string.
2. **Upstash Redis:** [Sign up here](https://upstash.com/) and create a free Redis database to get your `rediss://` URL.

> [!TIP]
> This keeps your VPS RAM free for the bot process itself, which is much more stable!

---

## 📦 3. Application Deployment

### Step 3.1: Clone & Install
```bash
git clone https://github.com/YOUR_USERNAME/fayda-bot.git
cd fayda-bot
npm install
```

### Step 3.2: Configure Environment
```bash
cp .env.example .env
nano .env
```
**Update these values:**
- `BOT_TOKEN`: From @BotFather
- `CAPTCHA_KEY`: From 2captcha
- `MONGODB_URI`: **Your MongoDB Atlas URL** (`mongodb+srv://...`)
- `REDIS_URL`: **Your Upstash Redis URL** (`rediss://...`)
- `SESSION_SECRET`: Generate one (e.g., `openssl rand -hex 32`)
- `WEBHOOK_DOMAIN`: `https://myfidbot.pro.et`
- `NODE_ENV`: `production`

---

## ⚡ 4. Process Management (PM2)

Keep your bot running forever and restart it if it crashes.

```bash
sudo npm install -g pm2
pm2 start index.js --name fayda-bot
pm2 save
pm2 startup
```

---

## 🌐 5. Nginx & SSL (Crucial for Telegram)

Telegram requires `https` for webhooks. We will use Nginx as a reverse proxy.

### Step 5.1: Install Nginx
```bash
sudo apt install nginx -y
```

### Step 5.2: Configure Site
```bash
sudo nano /etc/nginx/sites-available/fayda-bot
```
Paste this:
```nginx
server {
    listen 80;
    server_name myfidbot.pro.et;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
```

### Step 5.3: Enable Configuration
```bash
sudo ln -s /etc/nginx/sites-available/fayda-bot /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

### Step 5.4: Install SSL (Certbot)
```bash
sudo apt install certbot python3-certbot-nginx -y
sudo certbot --nginx -d myfidbot.pro.et
```

---

## 🛡️ 6. Extra Security (Fail2Ban)

Prevent brute-force attacks on your SSH port.
```bash
sudo apt install fail2ban -y
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

---

## 📊 7. Monitoring & Logs

- Check bot logs: `pm2 logs fayda-bot`
- Check status: `pm2 status`
- Health Check: Visit `https://myfidbot.pro.et/health` in your browser.

---

### 💡 Pro Tip:
Since Yegara is unmanaged, periodically run `sudo apt update && sudo apt upgrade -y` to keep your system safe.
