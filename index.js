require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const axios = require('axios');
const Captcha = require('2captcha');
const mongoose = require('mongoose');

const bot = require('./bot');
const pdfQueue = require('./queue');
const User = require('./models/User');
const auth = require('./middleware/auth');

// ---------- Express App ----------
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: process.env.MONGODB_URI }),
  cookie: { maxAge: 1000 * 60 * 60 * 24 } // 1 day
}));

app.set('view engine', 'ejs');

// ---------- MongoDB Connection ----------
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => {
    console.error('❌ MongoDB error:', err);
    process.exit(1);
  });

// ---------- Constants ----------
const API_BASE = "https://api-resident.fayda.et";
const HEADERS = {
  'Content-Type': 'application/json',
  'User-Agent': 'Mozilla/5.0',
  'Origin': 'https://resident.fayda.et',
  'Referer': 'https://resident.fayda.et/'
};

const solver = new Captcha.Solver(process.env.CAPTCHA_KEY);

// ---------- Telegram Authorization Middleware ----------
bot.use(async (ctx, next) => {
  if (!ctx.from) return;

  const telegramId = ctx.from.id.toString();
  const user = await auth.getUser(telegramId);

  if (!user) {
    return ctx.reply('❌ You are not authorized.\nContact admin.');
  }

  if (
    user.role !== 'admin' &&
    user.expiryDate &&
    new Date(user.expiryDate) < new Date()
  ) {
    return ctx.reply('❌ Your subscription has expired.');
  }

  ctx.state.user = user;

  await User.updateOne(
    { telegramId },
    {
      $set: { lastActive: new Date() },
      $inc: { usageCount: 1 }
    }
  );

  return next();
});

// ---------- TEXT HANDLER ----------
bot.on('text', async (ctx) => {
  const state = ctx.session;
  if (!state) return;

  const text = ctx.message.text.trim();

  // ===== OTP STEP =====
  if (state.step === 'OTP') {

    const status = await ctx.reply("⏳ Verifying OTP and generating document...");
    const authHeader = { ...HEADERS, 'Authorization': `Bearer ${state.tempJwt}` };

    try {
      const otpResponse = await axios.post(
        `${API_BASE}/validateOtp`,
        {
          otp: text,
          uniqueId: state.id,
          verificationMethod: "FCN"
        },
        { headers: authHeader }
      );

      const { signature, uin, fullName } = otpResponse.data;

      if (!signature || !uin) {
        throw new Error('Missing signature or uin in OTP response');
      }

      const pdfPayload = { uin, signature };

      // ✅ ENQUEUE JOB (NO WORKER LOGIC HERE)
      await pdfQueue.add({
        chatId: ctx.chat.id,
        userId: ctx.from.id.toString(),
        authHeader,
        pdfPayload,
        fullName: fullName || { eng: 'Fayda_Card' }
      });

      await ctx.telegram.editMessageText(
        ctx.chat.id,
        status.message_id,
        null,
        "⏳ OTP Verified. Your PDF is being prepared. You'll receive it shortly."
      );

      ctx.session = null;

    } catch (e) {
      console.error("OTP Error:", e.response?.data || e.message);
      await ctx.reply(`❌ Failed: ${e.message}`);
      ctx.session = null;
    }

    return;
  }
});

// ---------- ADMIN AUTH ----------
const requireAuth = (req, res, next) => {
  if (!req.session.admin) return res.redirect('/login');
  next();
};

// ---------- LOGIN ----------
app.get('/login', (req, res) => {
  res.render('login');
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (
    username === process.env.ADMIN_USER &&
    password === process.env.ADMIN_PASS
  ) {
    req.session.admin = true;
    return res.redirect('/dashboard');
  }

  res.render('login', { error: 'Invalid credentials' });
});

// ---------- DASHBOARD ----------
app.get('/dashboard', requireAuth, async (req, res) => {

  const totalDownloads = await User.aggregate([
    { $group: { _id: null, total: { $sum: "$downloadCount" } } }
  ]).then(r => r[0]?.total || 0);

  const stats = {
    totalUsers: await User.countDocuments(),
    buyers: await User.countDocuments({ role: 'buyer' }),
    subUsers: await User.countDocuments({ role: 'sub' }),
    expiringSoon: await User.countDocuments({
      expiryDate: {
        $lt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        $gt: new Date()
      }
    }),
    totalDownloads
  };

  const buyers = await User.find({ role: 'buyer' }).sort({ createdAt: -1 });

  const buyerList = await Promise.all(
    buyers.map(async (buyer) => {
      const subs = await User.find({
        telegramId: { $in: buyer.subUsers || [] }
      });

      const subDownloads = subs.reduce(
        (sum, sub) => sum + (sub.downloadCount || 0),
        0
      );

      return {
        ...buyer.toObject(),
        subDownloads,
        totalDownloads: (buyer.downloadCount || 0) + subDownloads
      };
    })
  );

  res.render('dashboard', { stats, buyers: buyerList });
});

// ---------- HEALTH CHECK ----------
app.get('/health', (req, res) => res.send('OK'));

// ---------- START SERVER ----------
async function startServer() {
  try {
    const webhookPath = '/webhook';

    await bot.telegram.setWebhook(
      `${process.env.WEBHOOK_DOMAIN}${webhookPath}`
    );

    app.use(bot.webhookCallback(webhookPath));

    const PORT = process.env.PORT || 3000;

    app.listen(PORT, () => {
      console.log(`🚀 API running on port ${PORT}`);
      console.log(`🤖 Webhook active`);
      console.log(`📦 Jobs are sent to Redis queue`);
    });

  } catch (err) {
    console.error("❌ Failed to start server:", err);
    process.exit(1);
  }
}

startServer();