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

// ---------- Bot Commands ----------
bot.start(async (ctx) => {
  ctx.session = { step: 'ID' };
  ctx.reply("🏁 Fayda ID Downloader\nPlease enter your **16-digit Fayda Number**:", { parse_mode: 'Markdown' });
});

bot.command('cancel', (ctx) => {
  ctx.session = null;
  ctx.reply("❌ Session cancelled. Use /start to begin again.");
});

// Buyer commands
bot.command('mysubs', async (ctx) => {
  const user = ctx.state.user;
  if (user.role !== 'buyer' && user.role !== 'admin') {
    return ctx.reply('❌ This command is only for buyers.');
  }
  
  const subs = await User.find({ telegramId: { $in: user.subUsers || [] } });
  if (!subs.length) {
    return ctx.reply('📭 You have no employees added yet.\nUse /addsub to add someone.');
  }
  
  let msg = '👥 **Your Employees**\n\n';
  subs.forEach((sub, i) => {
    msg += `${i+1}. `;
    if (sub.firstName) msg += sub.firstName;
    if (sub.lastName) msg += ' ' + sub.lastName;
    msg += `\n   📱 ID: \`${sub.telegramId}\``;
    if (sub.telegramUsername) msg += `\n   @${sub.telegramUsername}`;
    if (sub.phoneNumber) msg += `\n   📞 ${sub.phoneNumber}`;
    msg += `\n   📅 Added: ${sub.createdAt.toLocaleDateString()}\n\n`;
  });
  msg += `Total: ${subs.length}/9 employees`;
  ctx.reply(msg, { parse_mode: 'Markdown' });
});

bot.command('addsub', async (ctx) => {
  const user = ctx.state.user;
  if (user.role !== 'buyer' && user.role !== 'admin') {
    return ctx.reply('❌ Only buyers can add employees.');
  }
  
  if ((user.subUsers || []).length >= 9) {
    return ctx.reply('❌ You already have 9 employees. Remove one first.');
  }
  
  ctx.reply(
    '📝 **Add an Employee**\n\n' +
    'Please send me the Telegram **ID**, **Username** (with @), or **Phone Number** (with +) of the person you want to add.\n\n' +
    'Examples:\n' +
    '• ID: `123456789`\n' +
    '• Username: `@john_doe`\n' +
    '• Phone: `+251912345678`',
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
    return ctx.reply('📭 You have no employees to remove.');
  }
  
  const subs = await User.find({ telegramId: { $in: user.subUsers } });
  const inlineKeyboard = subs.map(sub => {
    let label = sub.firstName || sub.telegramUsername || sub.telegramId;
    if (sub.firstName && sub.lastName) label = `${sub.firstName} ${sub.lastName}`;
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
  
  await ctx.editMessageText(`✅ Successfully removed employee.`);
  ctx.answerCbQuery();
});

// ---------- SINGLE TEXT HANDLER ----------
bot.on('text', async (ctx) => {
  const state = ctx.session;
  if (!state) return;

  const text = ctx.message.text.trim();

  // ----- Step: AWAITING_SUB_IDENTIFIER (adding sub-user) -----
  if (state.step === 'AWAITING_SUB_IDENTIFIER') {
    const buyer = ctx.state.user;
    const statusMsg = await ctx.reply('🔍 Looking up user...');
    
    try {
      let subUser = await auth.findUserByIdentifier(text);
      
      if (!subUser) {
        return ctx.reply(
          "⚠️ This user hasn't started the bot yet.\n\n" +
          "Ask them to send /start to the bot first, then try adding them again with their Telegram ID."
        );
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
      
      await ctx.telegram.editMessageText(
        ctx.chat.id,
        statusMsg.message_id,
        null,
        `✅ Employee added successfully!\n\nThey can now use the bot.`
      );
      
      ctx.session.step = null;
    } catch (error) {
      console.error('Add sub error:', error);
      ctx.reply('❌ Failed to add employee. Please try again.');
    }
    return;
  }

  // ----- Step: ID (Fayda login) -----
  if (state.step === 'ID') {
    if (!/^\d{16}$/.test(text)) {
      return ctx.reply("❌ Invalid format. Please enter exactly **16 digits**.", { parse_mode: 'Markdown' });
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
      const errMsg = e.response?.data?.message || "Verification failed.";
      console.error("ID Error:", errMsg);
      ctx.reply(`❌ Error: ${errMsg}\nTry /start again.`);
      ctx.session = null;
    }
    return;
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
  const { telegramId, expiryDays } = req.body;
  if (!telegramId || !expiryDays) {
    return res.status(400).send('Missing telegramId or expiryDays');
  }
  
  let user = await User.findOne({ telegramId });
  if (user) {
    user.role = 'buyer';
    user.expiryDate = new Date(Date.now() + parseInt(expiryDays) * 24*60*60*1000);
    await user.save();
  } else {
    user = new User({
      telegramId,
      role: 'buyer',
      expiryDate: new Date(Date.now() + parseInt(expiryDays) * 24*60*60*1000),
      subUsers: [],
      createdAt: new Date()
    });
    await user.save();
  }
  
  res.redirect('/dashboard');
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
  const buyerId = req.params.id;
  const { identifier, expiryDays } = req.body;
  
  const buyer = await User.findOne({ telegramId: buyerId });
  if (!buyer) return res.status(404).send('Buyer not found');
  
  if ((buyer.subUsers || []).length >= 9) {
    return res.status(400).send('Buyer already has 9 sub-users');
  }
  
  let subUser = await auth.findUserByIdentifier(identifier);
  if (!subUser) {
    if (/^\d+$/.test(identifier)) {
      subUser = new User({ telegramId: identifier, role: 'sub', addedBy: buyerId });
    } else {
      return res.status(400).send('User must start the bot first. Use Telegram ID.');
    }
  }
  
  if ((buyer.subUsers || []).includes(subUser.telegramId)) {
    return res.status(400).send('User already added');
  }
  
  const expiryDate = new Date();
  expiryDate.setDate(expiryDate.getDate() + parseInt(expiryDays));
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