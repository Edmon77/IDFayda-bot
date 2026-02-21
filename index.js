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
  .catch(err => console.error('❌ MongoDB error:', err));

// ---------- Constants ----------
const API_BASE = "https://api-resident.fayda.et";
const SITE_KEY = "6LcSAIwqAAAAAGsZElBPqf63_0fUtp17idU-SQYC";
const HEADERS = {
  'Content-Type': 'application/json',
  'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
  'Origin': 'https://resident.fayda.et',
  'Referer': 'https://resident.fayda.et/'
};
const solver = new Captcha.Solver(process.env.CAPTCHA_KEY);

// ---------- Authorization Middleware (unchanged) ----------
bot.use(async (ctx, next) => {
  const telegramId = ctx.from.id.toString();
  const user = await auth.getUser(telegramId);
  
  if (!user) {
    return ctx.reply('❌ You are not authorized to use this bot.\nContact admin to purchase access.');
  }
  
  if (user.role !== 'admin' && user.expiryDate && new Date(user.expiryDate) < new Date()) {
    return ctx.reply('❌ Your subscription has expired. Please renew.');
  }
  
  ctx.state.user = user;
  
  await User.updateOne(
    { telegramId },
    { $set: { lastActive: new Date() }, $inc: { usageCount: 1 } }
  );
  
  return next();
});

// ---------- Bot Commands (unchanged, but we need to ensure session works) ----------
// ... (copy your existing commands: start, cancel, mysubs, addsub, removesub, remove callback)
// I'll keep them as is, but note that telegraf session is already in bot.js.

// ---------- Text Handler (modified OTP step) ----------
bot.on('text', async (ctx) => {
  const state = ctx.session;
  if (!state) return;

  const text = ctx.message.text.trim();

  // ----- Step: AWAITING_SUB_IDENTIFIER -----
  if (state.step === 'AWAITING_SUB_IDENTIFIER') {
    // (copy your existing code – unchanged)
  }

  // ----- Step: ID -----
  if (state.step === 'ID') {
    // (copy your existing code – unchanged)
  }

  // ----- Step: OTP -----
  if (state.step === 'OTP') {
    const status = await ctx.reply("⏳ Verifying OTP and generating document...");
    const authHeader = { ...HEADERS, 'Authorization': `Bearer ${state.tempJwt}` };

    try {
      const otpResponse = await axios.post(`${API_BASE}/validateOtp`, {
        otp: text,
        uniqueId: state.id,
        verificationMethod: "FCN"
      }, { headers: authHeader });

      console.log('OTP response:', otpResponse.data);

      const { signature, uin, fullName } = otpResponse.data;
      if (!signature || !uin) {
        throw new Error('Missing signature or uin in OTP response');
      }

      const pdfPayload = { uin, signature };

      // Enqueue job
      await pdfQueue.add({
        chatId: ctx.chat.id,
        userId: ctx.from.id.toString(),
        authHeader,
        pdfPayload,
        id: state.id,
        fullName: fullName || { eng: 'Fayda_Card' }
      });

      await ctx.telegram.editMessageText(
        ctx.chat.id,
        status.message_id,
        null,
        "⏳ OTP Verified. Your PDF is being prepared. We'll send it shortly."
      );

      ctx.session = null; // clear session
    } catch (e) {
      console.error("OTP Error:", e.response?.data || e.message);
      ctx.reply(`❌ Failed: ${e.message}`);
      ctx.session = null;
    }
    return;
  }
});

// ---------- Admin Dashboard Routes (enhanced) ----------
const requireAuth = (req, res, next) => {
  if (!req.session.admin) return res.redirect('/login');
  next();
};

app.get('/login', (req, res) => {
  res.render('login');
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (username === process.env.ADMIN_USER && password === process.env.ADMIN_PASS) {
    req.session.admin = true;
    res.redirect('/dashboard');
  } else {
    res.render('login', { error: 'Invalid credentials' });
  }
});

app.get('/dashboard', requireAuth, async (req, res) => {
  const totalDownloads = await User.aggregate([
    { $group: { _id: null, total: { $sum: "$downloadCount" } } }
  ]).then(r => r[0]?.total || 0);

  const stats = {
    totalUsers: await User.countDocuments(),
    buyers: await User.countDocuments({ role: 'buyer' }),
    subUsers: await User.countDocuments({ role: 'sub' }),
    expiringSoon: await User.countDocuments({
      expiryDate: { $lt: new Date(Date.now() + 7*24*60*60*1000), $gt: new Date() }
    }),
    totalDownloads
  };

  const buyers = await User.find({ role: 'buyer' }).sort({ createdAt: -1 });
  // Enhance each buyer with sub-user download totals
  const buyerList = await Promise.all(buyers.map(async (buyer) => {
    const subs = await User.find({ telegramId: { $in: buyer.subUsers || [] } });
    const subDownloads = subs.reduce((sum, sub) => sum + (sub.downloadCount || 0), 0);
    return {
      ...buyer.toObject(),
      subDownloads,
      totalDownloads: (buyer.downloadCount || 0) + subDownloads
    };
  }));

  res.render('dashboard', { stats, buyers: buyerList });
});

app.post('/add-buyer', requireAuth, async (req, res) => {
  // (same as before)
});

app.get('/buyer/:id', requireAuth, async (req, res) => {
  const buyer = await User.findOne({ telegramId: req.params.id });
  if (!buyer) return res.status(404).send('Buyer not found');
  const subs = await User.find({ telegramId: { $in: buyer.subUsers || [] } });
  const subUsersTotal = subs.reduce((sum, sub) => sum + (sub.downloadCount || 0), 0);
  const buyerOwn = buyer.downloadCount || 0;
  const totalDownloads = buyerOwn + subUsersTotal;

  res.render('buyer-detail', {
    buyer,
    subs,
    buyerOwn,
    subUsersTotal,
    totalDownloads
  });
});

app.post('/buyer/:id/add-sub', requireAuth, async (req, res) => {
  // (same as before)
});

app.post('/buyer/:buyerId/remove-sub/:subId', requireAuth, async (req, res) => {
  // (same as before)
});

app.get('/export-users', requireAuth, async (req, res) => {
  // (same as before, but include downloadCount in CSV)
  const users = await User.find({});
  let csv = 'Telegram ID,Role,Added By,Expiry Date,Last Active,Usage Count,Download Count\n';
  users.forEach(u => {
    csv += `${u.telegramId},${u.role},${u.addedBy || 'N/A'},${u.expiryDate || 'N/A'},${u.lastActive || 'N/A'},${u.usageCount},${u.downloadCount}\n`;
  });
  res.header('Content-Type', 'text/csv');
  res.attachment('users.csv');
  res.send(csv);
});

app.get('/health', (req, res) => res.send('OK'));

// ---------- Start Server with Webhook ----------
async function startServer() {
  try {
    const webhookPath = '/webhook';
    await bot.telegram.setWebhook(`${process.env.WEBHOOK_DOMAIN}${webhookPath}`);
    app.use(bot.webhookCallback(webhookPath));

    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
      console.log(`🚀 Server running on port ${PORT}`);
      console.log(`🤖 Webhook active at ${process.env.WEBHOOK_DOMAIN}${webhookPath}`);
      console.log(`✅ Queue worker started with concurrency 5`);
    });
  } catch (err) {
    console.error("❌ Failed to start server:", err);
    process.exit(1);
  }
}

startServer();