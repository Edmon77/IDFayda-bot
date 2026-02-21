require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const axios = require('axios');
const Captcha = require('2captcha');
const mongoose = require('mongoose');

const bot = require('./bot');
const pdfQueue = require('./queue'); // only queue, no worker
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
const SITE_KEY = "6LcSAIwqAAAAAGsZElBPqf63_0fUtp17idU-SQYC";
const HEADERS = {
  'Content-Type': 'application/json',
  'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
  'Origin': 'https://resident.fayda.et',
  'Referer': 'https://resident.fayda.et/'
};
const solver = new Captcha.Solver(process.env.CAPTCHA_KEY);

// Helper: timeout for promises
const withTimeout = (promise, ms, errorMessage = 'Operation timed out') => {
  let timeout;
  const timeoutPromise = new Promise((_, reject) => {
    timeout = setTimeout(() => reject(new Error(errorMessage)), ms);
  });
  return Promise.race([promise, timeoutPromise]).finally(() => clearTimeout(timeout));
};

// ---------- Telegram Authorization ----------
bot.use(async (ctx, next) => {
  const telegramId = ctx.from.id.toString();
  const user = await auth.getUser(telegramId);
  if (!user) {
    return ctx.reply('❌ You are not authorized.');
  }
  if (user.role !== 'admin' && user.expiryDate && new Date(user.expiryDate) < new Date()) {
    return ctx.reply('❌ Subscription expired.');
  }
  ctx.state.user = user;
  await User.updateOne(
    { telegramId },
    { $set: { lastActive: new Date() }, $inc: { usageCount: 1 } }
  );
  return next();
});

// ---------- Bot Commands ----------
bot.start(async (ctx) => {
  ctx.session = { step: 'ID' };
  ctx.reply("🏁 Fayda ID Downloader\nPlease enter your **16-digit Fayda Number**:", { parse_mode: 'Markdown' });
});

bot.command('cancel', (ctx) => {
  ctx.session = null;
  ctx.reply("❌ Session cancelled.");
});

bot.command('mysubs', async (ctx) => {
  const user = ctx.state.user;
  if (user.role !== 'buyer' && user.role !== 'admin') {
    return ctx.reply('❌ Only buyers can use this command.');
  }
  const subs = await User.find({ telegramId: { $in: user.subUsers || [] } });
  if (!subs.length) return ctx.reply('📭 No employees.');
  let msg = '👥 **Your Employees**\n\n';
  subs.forEach((sub, i) => {
    msg += `${i+1}. ` + (sub.firstName || sub.telegramUsername || sub.telegramId) + '\n';
  });
  ctx.reply(msg, { parse_mode: 'Markdown' });
});

bot.command('addsub', async (ctx) => {
  const user = ctx.state.user;
  if (user.role !== 'buyer' && user.role !== 'admin') {
    return ctx.reply('❌ Only buyers can add employees.');
  }
  if ((user.subUsers || []).length >= 9) {
    return ctx.reply('❌ You already have 9 employees.');
  }
  ctx.reply(
    '📝 **Add an Employee**\n\nSend me the Telegram **ID**, **Username** (with @), or **Phone** (with +).',
    { parse_mode: 'Markdown' }
  );
  ctx.session = { ...ctx.session, step: 'AWAITING_SUB_IDENTIFIER' };
});

bot.command('removesub', async (ctx) => {
  const user = ctx.state.user;
  if (user.role !== 'buyer' && user.role !== 'admin') {
    return ctx.reply('❌ Only buyers can remove employees.');
  }
  if (!user.subUsers || !user.subUsers.length) {
    return ctx.reply('📭 No employees to remove.');
  }
  const subs = await User.find({ telegramId: { $in: user.subUsers } });
  const inlineKeyboard = subs.map(sub => {
    let label = sub.firstName || sub.telegramUsername || sub.telegramId;
    return [{ text: `❌ Remove ${label}`, callback_data: `remove_sub_${sub.telegramId}` }];
  });
  ctx.reply('👥 **Select an employee to remove:**', {
    parse_mode: 'Markdown',
    reply_markup: { inline_keyboard: inlineKeyboard }
  });
});

bot.action(/remove_sub_(.+)/, async (ctx) => {
  const subId = ctx.match[1];
  const buyerId = ctx.from.id.toString();
  const buyer = await User.findOne({ telegramId: buyerId });
  if (!buyer || (buyer.role !== 'buyer' && buyer.role !== 'admin')) {
    return ctx.answerCbQuery('❌ Not authorized');
  }
  buyer.subUsers = (buyer.subUsers || []).filter(id => id !== subId);
  await buyer.save();
  await User.deleteOne({ telegramId: subId });
  await ctx.editMessageText(`✅ Removed employee.`);
  ctx.answerCbQuery();
});

// ---------- TEXT HANDLER ----------
bot.on('text', async (ctx) => {
  const state = ctx.session;
  if (!state) return;
  const text = ctx.message.text.trim();

  // ----- AWAITING_SUB_IDENTIFIER -----
  if (state.step === 'AWAITING_SUB_IDENTIFIER') {
    const buyer = ctx.state.user;
    const statusMsg = await ctx.reply('🔍 Looking up user...');
    try {
      let subUser = await auth.findUserByIdentifier(text);
      if (!subUser) {
        return ctx.reply("⚠️ User hasn't started the bot yet.");
      }
      if ((buyer.subUsers || []).length >= 9) {
        return ctx.reply('❌ You already have 9 employees.');
      }
      if ((buyer.subUsers || []).includes(subUser.telegramId)) {
        return ctx.reply('❌ This user is already your employee.');
      }
      buyer.subUsers.push(subUser.telegramId);
      await buyer.save();
      subUser.role = 'sub';
      subUser.addedBy = buyer.telegramId;
      subUser.expiryDate = buyer.expiryDate;
      await subUser.save();
      await ctx.telegram.editMessageText(ctx.chat.id, statusMsg.message_id, null, `✅ Employee added!`);
      ctx.session.step = null;
    } catch (error) {
      console.error('Add sub error:', error);
      ctx.reply('❌ Failed to add employee.');
    }
    return;
  }

  // ----- ID -----
  if (state.step === 'ID') {
    if (!/^\d{16}$/.test(text)) {
      return ctx.reply("❌ Invalid format. Enter exactly 16 digits.");
    }
    const status = await ctx.reply("⏳ Solving Captcha...");
    try {
      const result = await solver.recaptcha(SITE_KEY, 'https://resident.fayda.et/');
      const res = await axios.post(`${API_BASE}/verify`, {
        idNumber: text,
        verificationMethod: "FCN",
        captchaValue: result.data
      }, { headers: HEADERS });
      ctx.session.tempJwt = res.data.token;
      ctx.session.id = text;
      ctx.session.step = 'OTP';
      await ctx.telegram.editMessageText(ctx.chat.id, status.message_id, null, "✅ Captcha Solved!\n\nEnter the OTP sent to your phone:");
    } catch (e) {
      console.error("Verify error:", e.response?.data || e.message);
      ctx.reply(`❌ Error: Verification failed.`);
      ctx.session = null;
    }
    return;
  }

  // ----- OTP -----
  if (state.step === 'OTP') {
    const status = await ctx.reply("⏳ Verifying OTP and generating document...");
    const authHeader = { ...HEADERS, 'Authorization': `Bearer ${state.tempJwt}` };
    try {
      const otpResponse = await axios.post(`${API_BASE}/validateOtp`, {
        otp: text,
        uniqueId: state.id,
        verificationMethod: "FCN"
      }, { headers: authHeader });
      const { signature, uin, fullName } = otpResponse.data;
      if (!signature || !uin) throw new Error('Missing signature or uin');
      const pdfPayload = { uin, signature };
      console.log('📦 Adding job to queue...');
      const job = await withTimeout(
        pdfQueue.add({
          chatId: ctx.chat.id,
          userId: ctx.from.id.toString(),
          authHeader,
          pdfPayload,
          fullName: fullName || { eng: 'Fayda_Card' }
        }),
        15000,
        'Queue add timed out'
      );
      console.log(`✅ Job added ID: ${job.id}`);
      await ctx.telegram.editMessageText(
        ctx.chat.id,
        status.message_id,
        null,
        "⏳ OTP Verified. Your PDF is being prepared. You'll receive it shortly."
      );
      ctx.session = null;
    } catch (e) {
      console.error("OTP Error:", e.message);
      ctx.reply(`❌ Failed: ${e.message}`);
      ctx.session = null;
    }
    return;
  }
});

// ---------- WORKER (runs in same process) ----------
pdfQueue.process(2, async (job) => {
  const { chatId, userId, authHeader, pdfPayload, fullName } = job.data;
  console.log(`🚀 Worker processing job ${job.id} for user ${userId}`);
  try {
    const pdfResponse = await axios.post(`${API_BASE}/printableCredentialRoute`, pdfPayload, {
      headers: authHeader,
      responseType: 'text',
      timeout: 20000
    });
    let base64Pdf = pdfResponse.data.trim();
    if (base64Pdf.startsWith('{') && base64Pdf.includes('"pdf"')) {
      try { const parsed = JSON.parse(base64Pdf); if (parsed.pdf) base64Pdf = parsed.pdf.trim(); } catch {}
    }
    if (!base64Pdf.startsWith('JVBERi0')) throw new Error('Invalid PDF header');
    const pdfBuffer = Buffer.from(base64Pdf, 'base64');
    const safeName = (fullName?.eng || 'Fayda_Card').replace(/[^a-zA-Z0-9]/g, '_');
    await bot.telegram.sendDocument(chatId, { source: pdfBuffer, filename: `${safeName}.pdf` }, { caption: "✨ Your Digital ID is ready!" });
    await User.updateOne({ telegramId: userId }, { $inc: { downloadCount: 1 }, $set: { lastDownload: new Date() } });
    console.log(`✅ Job ${job.id} completed`);
    return { success: true };
  } catch (err) {
    console.error(`❌ Job ${job.id} failed:`, err.message);
    throw err;
  }
});

// ---------- Admin Dashboard Routes ----------
const requireAuth = (req, res, next) => {
  if (!req.session.admin) return res.redirect('/login');
  next();
};

app.get('/login', (req, res) => res.render('login'));
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
  const totalDownloads = await User.aggregate([{ $group: { _id: null, total: { $sum: "$downloadCount" } } }]).then(r => r[0]?.total || 0);
  const stats = {
    totalUsers: await User.countDocuments(),
    buyers: await User.countDocuments({ role: 'buyer' }),
    subUsers: await User.countDocuments({ role: 'sub' }),
    expiringSoon: await User.countDocuments({ expiryDate: { $lt: new Date(Date.now() + 7*24*60*60*1000), $gt: new Date() } }),
    totalDownloads
  };
  const buyers = await User.find({ role: 'buyer' }).sort({ createdAt: -1 });
  const buyerList = await Promise.all(buyers.map(async (buyer) => {
    const subs = await User.find({ telegramId: { $in: buyer.subUsers || [] } });
    const subDownloads = subs.reduce((sum, sub) => sum + (sub.downloadCount || 0), 0);
    return { ...buyer.toObject(), subDownloads, totalDownloads: (buyer.downloadCount || 0) + subDownloads };
  }));
  res.render('dashboard', { stats, buyers: buyerList });
});

app.post('/add-buyer', requireAuth, async (req, res) => {
  const { telegramId, expiryDays } = req.body;
  if (!telegramId || !expiryDays) return res.status(400).send('Missing fields');
  let user = await User.findOne({ telegramId });
  if (user) {
    user.role = 'buyer';
    user.expiryDate = new Date(Date.now() + parseInt(expiryDays) * 24*60*60*1000);
    await user.save();
  } else {
    user = new User({ telegramId, role: 'buyer', expiryDate: new Date(Date.now() + parseInt(expiryDays) * 24*60*60*1000), subUsers: [] });
    await user.save();
  }
  res.redirect('/dashboard');
});

app.get('/buyer/:id', requireAuth, async (req, res) => {
  const buyer = await User.findOne({ telegramId: req.params.id });
  if (!buyer) return res.status(404).send('Buyer not found');
  const subs = await User.find({ telegramId: { $in: buyer.subUsers || [] } });
  const subUsersTotal = subs.reduce((sum, sub) => sum + (sub.downloadCount || 0), 0);
  res.render('buyer-detail', { buyer, subs, buyerOwn: buyer.downloadCount || 0, subUsersTotal, totalDownloads: (buyer.downloadCount || 0) + subUsersTotal });
});

app.post('/buyer/:id/add-sub', requireAuth, async (req, res) => {
  const buyerId = req.params.id;
  const { identifier, expiryDays } = req.body;
  const buyer = await User.findOne({ telegramId: buyerId });
  if (!buyer) return res.status(404).send('Buyer not found');
  if ((buyer.subUsers || []).length >= 9) return res.status(400).send('Max 9 sub-users');
  let subUser = await auth.findUserByIdentifier(identifier);
  if (!subUser) {
    if (/^\d+$/.test(identifier)) {
      subUser = new User({ telegramId: identifier, role: 'sub', addedBy: buyerId });
    } else {
      return res.status(400).send('User must start the bot first.');
    }
  }
  if ((buyer.subUsers || []).includes(subUser.telegramId)) return res.status(400).send('Already added');
  const expiryDate = new Date(Date.now() + parseInt(expiryDays) * 24*60*60*1000);
  subUser.expiryDate = expiryDate;
  subUser.role = 'sub';
  subUser.addedBy = buyerId;
  await subUser.save();
  buyer.subUsers.push(subUser.telegramId);
  await buyer.save();
  res.redirect(`/buyer/${buyerId}`);
});

app.post('/buyer/:buyerId/remove-sub/:subId', requireAuth, async (req, res) => {
  const { buyerId, subId } = req.params;
  await User.updateOne({ telegramId: buyerId }, { $pull: { subUsers: subId } });
  await User.deleteOne({ telegramId: subId });
  res.redirect(`/buyer/${buyerId}`);
});

app.get('/export-users', requireAuth, async (req, res) => {
  const users = await User.find({});
  let csv = 'Telegram ID,Role,Added By,Expiry Date,Last Active,Usage Count,Download Count\n';
  users.forEach(u => { csv += `${u.telegramId},${u.role},${u.addedBy || 'N/A'},${u.expiryDate || 'N/A'},${u.lastActive || 'N/A'},${u.usageCount},${u.downloadCount}\n`; });
  res.header('Content-Type', 'text/csv');
  res.attachment('users.csv');
  res.send(csv);
});

app.get('/health', (req, res) => res.send('OK'));

// ---------- Start Server ----------
async function startServer() {
  try {
    const webhookPath = '/webhook';
    await bot.telegram.setWebhook(`${process.env.WEBHOOK_DOMAIN}${webhookPath}`);
    app.use(bot.webhookCallback(webhookPath));
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
      console.log(`🚀 Server running on port ${PORT}`);
      console.log(`🤖 Webhook active at ${process.env.WEBHOOK_DOMAIN}${webhookPath}`);
      console.log(`✅ Worker started with concurrency 2`);
    });
  } catch (err) {
    console.error("❌ Failed to start server:", err);
    process.exit(1);
  }
}
startServer();