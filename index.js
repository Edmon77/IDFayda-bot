// Environment validation and configuration
const { validateEnv } = require('./config/env');
validateEnv();

// ---------- Keep process alive on unhandled errors (log and continue) ----------
const logger = require('./utils/logger');
process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection at', { reason, stack: reason?.stack });
});
process.on('uncaughtException', (err) => {
  logger.error('Uncaught Exception', { message: err.message, stack: err.stack });
  // Don't exit - allow bot to keep serving other users (exit only on next fatal)
  // process.exit(1);
});

const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const Captcha = require('2captcha');
const fayda = require('./utils/faydaClient');
const { Markup } = require('telegraf');

const bot = require('./bot');
const User = require('./models/User');
const auth = require('./middleware/auth');
const { connectDB, disconnectDB } = require('./config/database');
const { apiLimiter, checkUserRateLimit } = require('./utils/rateLimiter');
const { validateFaydaId, validateOTP } = require('./utils/validators');
const { parsePdfResponse } = require('./utils/pdfHelper');
const { getMainMenu } = require('./utils/menu');
const pdfQueue = require('./queue');
const { safeResponseForLog } = require('./utils/logger');

const PDF_SYNC_ATTEMPTS = 2;
const PDF_SYNC_RETRY_DELAY_MS = 1500;
const CAPTCHA_VERIFY_ATTEMPTS = 3;
const CAPTCHA_VERIFY_RETRY_DELAY_MS = 3000;

// ---------- Express App ----------
const app = express();
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ 
    mongoUrl: process.env.MONGODB_URI,
    ttl: 24 * 60 * 60 // 24 hours
  }),
  cookie: { 
    maxAge: 1000 * 60 * 60 * 24,
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true
  }
}));
app.set('view engine', 'ejs');

// Health check endpoint (simple – for load balancers)
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// Deep health (MongoDB + Redis) – for monitoring / zero-failure setups
const { redisClient } = require('./utils/rateLimiter');
app.get('/health/ready', async (req, res) => {
  const mongodb = await (async () => {
    try {
      const mongoose = require('mongoose');
      return mongoose.connection.readyState === 1 ? 'ok' : 'disconnected';
    } catch (e) {
      return 'error';
    }
  })();
  let redis = 'ok';
  try {
    await redisClient.ping();
  } catch (e) {
    redis = 'error';
  }
  const ok = mongodb === 'ok' && redis === 'ok';
  res.status(ok ? 200 : 503).json({
    status: ok ? 'ok' : 'degraded',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    mongodb,
    redis
  });
});

// Apply rate limiting to API routes
app.use('/api', apiLimiter);

// ---------- Web Dashboard (Super Admin) - same options as bot ----------
const requireWebAuth = (req, res, next) => {
  if (!process.env.ADMIN_USER || !process.env.ADMIN_PASS) return res.status(503).send('Admin dashboard not configured. Set ADMIN_USER and ADMIN_PASS.');
  if (req.session && req.session.admin) return next();
  res.redirect('/login');
};
app.get('/login', (req, res) => {
  if (!process.env.ADMIN_USER || !process.env.ADMIN_PASS) {
    return res.status(503).send('Admin dashboard not configured. Set ADMIN_USER and ADMIN_PASS in environment.');
  }
  res.render('login', { error: req.query.error });
});
app.post('/login', (req, res) => {
  if (!process.env.ADMIN_USER || !process.env.ADMIN_PASS) {
    return res.status(503).send('Admin dashboard not configured.');
  }
  const { username, password } = req.body;
  if (username === process.env.ADMIN_USER && password === process.env.ADMIN_PASS) {
    req.session.admin = true;
    res.redirect('/dashboard');
  } else {
    res.render('login', { error: 'Invalid credentials' });
  }
});
app.get('/logout', (req, res) => {
  req.session.admin = false;
  res.redirect('/login');
});
app.get('/dashboard', requireWebAuth, async (req, res) => {
  const buyers = await User.find({ role: 'buyer' }).sort({ createdAt: -1 }).lean();
  const allSubIds = buyers.flatMap(b => b.subUsers || []);
  const subs = await User.find({ telegramId: { $in: allSubIds } }).select('telegramId downloadCount').lean();
  const subMap = new Map(subs.map(s => [s.telegramId, s.downloadCount || 0]));
  const stats = {
    totalUsers: await User.countDocuments(),
    buyers: buyers.length,
    subUsers: allSubIds.length,
    expiringSoon: await User.countDocuments({ expiryDate: { $lt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), $gt: new Date() }, role: { $in: ['buyer', 'sub'] } }),
    totalDownloads: buyers.reduce((s, b) => s + (b.downloadCount || 0), 0) + subs.reduce((s, u) => s + (u.downloadCount || 0), 0)
  };
  const enriched = buyers.map(b => {
    const subIds = b.subUsers || [];
    const subDownloads = subIds.reduce((sum, id) => sum + (subMap.get(id) || 0), 0);
    return { ...b, subDownloads, totalDownloads: (b.downloadCount || 0) + subDownloads };
  });
  res.render('dashboard', { stats, buyers: enriched, error: req.query.error });
});
app.get('/pending', requireWebAuth, async (req, res) => {
  const pending = await User.find({ role: 'pending' }).sort({ lastActive: -1 }).limit(50).lean();
  res.render('pending', { pending });
});
app.post('/add-buyer', requireWebAuth, async (req, res) => {
  const { telegramId, expiryDays = 30 } = req.body;
  if (!telegramId || !/^\d+$/.test(String(telegramId).trim())) {
    return res.redirect('/dashboard?error=invalid_id');
  }
  const tid = String(telegramId).trim();
  let user = await User.findOne({ telegramId: tid });
  if (!user || user.role === 'pending') {
    return res.redirect('/dashboard?error=user_must_start');
  }
  if (user.role === 'buyer' || user.role === 'admin') {
    return res.redirect('/dashboard?error=already_added');
  }
  if (user.addedBy) await User.updateOne({ telegramId: user.addedBy }, { $pull: { subUsers: tid } });
  const expiry = new Date();
  expiry.setDate(expiry.getDate() + parseInt(expiryDays) || 30);
  user.role = 'buyer';
  user.addedBy = undefined;
  user.expiryDate = expiry;
  user.subUsers = [];
  await user.save();
  try {
    await bot.telegram.sendMessage(tid, "✅ You've been added! Here's your menu:", { parse_mode: 'Markdown', ...getMainMenu('buyer') });
  } catch (e) {}
  res.redirect('/dashboard');
});
app.get('/buyer/:id', requireWebAuth, async (req, res) => {
  const buyer = await User.findOne({ telegramId: req.params.id });
  if (!buyer) return res.status(404).send('Not found');
  const subs = await User.find({ telegramId: { $in: buyer.subUsers || [] } }).lean();
  const subUsersTotal = subs.reduce((s, u) => s + (u.downloadCount || 0), 0);
  const totalDownloads = (buyer.downloadCount || 0) + subUsersTotal;
  res.render('buyer-detail', { buyer, subs, buyerOwn: buyer.downloadCount || 0, subUsersTotal, totalDownloads, error: req.query.error });
});
app.post('/buyer/:id/add-sub', requireWebAuth, async (req, res) => {
  const { identifier, expiryDays } = req.body;
  const tid = String(identifier).trim().replace(/\s/g, '');
  if (!/^\d+$/.test(tid)) return res.redirect(`/buyer/${req.params.id}?error=invalid_id`);
  const buyer = await User.findOne({ telegramId: req.params.id });
  if (!buyer) return res.redirect('/dashboard');
  let subUser = await User.findOne({ telegramId: tid });
  if (!subUser || subUser.role === 'pending') return res.redirect(`/buyer/${req.params.id}?error=must_start`);
  if ((buyer.subUsers || []).length >= 9) return res.redirect(`/buyer/${req.params.id}?error=full`);
  if ((buyer.subUsers || []).includes(tid)) return res.redirect(`/buyer/${req.params.id}?error=already`);
  buyer.subUsers = buyer.subUsers || [];
  buyer.subUsers.push(tid);
  await buyer.save();
  subUser.role = 'sub';
  subUser.addedBy = buyer.telegramId;
  subUser.expiryDate = buyer.expiryDate;
  await subUser.save();
  try {
    await bot.telegram.sendMessage(tid, "✅ You've been added! Here's your menu:", { parse_mode: 'Markdown', ...getMainMenu('sub') });
  } catch (e) {}
  res.redirect(`/buyer/${req.params.id}`);
});
app.post('/buyer/:buyerId/remove-sub/:subId', requireWebAuth, async (req, res) => {
  await User.updateOne({ telegramId: req.params.buyerId }, { $pull: { subUsers: req.params.subId } });
  await User.deleteOne({ telegramId: req.params.subId });
  res.redirect(`/buyer/${req.params.buyerId}`);
});
app.post('/buyer/:id/remove', requireWebAuth, async (req, res) => {
  const buyer = await User.findOne({ telegramId: req.params.id });
  if (!buyer) return res.redirect('/dashboard');
  buyer.role = 'pending';
  buyer.addedBy = undefined;
  buyer.expiryDate = undefined;
  buyer.subUsers = [];
  await buyer.save();
  await User.updateMany({ addedBy: req.params.id }, { role: 'pending', addedBy: undefined, expiryDate: undefined });
  res.redirect('/dashboard');
});
app.get('/export-users', requireWebAuth, async (req, res) => {
  const users = await User.find({});
  let csv = 'Telegram ID,Role,Name,Username,Expiry,Last Active,Downloads\n';
  users.forEach(u => {
    csv += `${u.telegramId},${u.role},${u.firstName || ''} ${u.lastName || ''},@${u.telegramUsername || ''},${u.expiryDate || ''},${u.lastActive || ''},${u.downloadCount || 0}\n`;
  });
  res.setHeader('Content-Type', 'text/csv');
  res.attachment('users.csv');
  res.send(csv);
});

// ---------- Constants ----------
const API_BASE = fayda.API_BASE;
const SITE_KEY = "6LcSAIwqAAAAAGsZElBPqf63_0fUtp17idU-SQYC";
const HEADERS = fayda.HEADERS;
const solver = new Captcha.Solver(process.env.CAPTCHA_KEY);
const PREFER_QUEUE_PDF = process.env.PREFER_QUEUE_PDF === 'true' || process.env.PREFER_QUEUE_PDF === '1';

// ---------- Error Handler Middleware ----------
bot.catch((err, ctx) => {
  // Ignore common Telegram errors that don't need action
  const ignorableErrors = [
    'bot was blocked by the user',
    'chat not found',
    'user is deactivated',
    'bot was kicked from the group',
    'message to delete not found',
    'message is not modified'
  ];
  
  const isIgnorable = ignorableErrors.some(msg => err.message?.toLowerCase().includes(msg.toLowerCase()));
  
  if (isIgnorable) {
    // Log but don't try to send message (user blocked bot or chat doesn't exist)
    logger.warn(`Ignoring Telegram error: ${err.message}`);
    return;
  }
  
  // Log other errors
  logger.error('Bot error:', {
    error: err.message,
    stack: err.stack,
    update: ctx.update
  });
  
  // Try to send error message only if we have a valid context and chat
  if (ctx && ctx.chat && ctx.from) {
    try {
      ctx.reply('❌ An error occurred. Please try again later or contact support.').catch(() => {
        // Silently ignore if we can't send (user blocked, etc.)
      });
    } catch (e) {
      // Silently ignore errors sending error messages
    }
  }
});

// ---------- Log User (upsert on every interaction so admins can add them) ----------
bot.use(async (ctx, next) => {
  if (ctx.from) {
    const telegramId = ctx.from.id.toString();
    try {
      await User.findOneAndUpdate(
        { telegramId },
        {
          $set: {
            firstName: ctx.from.first_name,
            lastName: ctx.from.last_name,
            telegramUsername: ctx.from.username,
            lastActive: new Date()
          },
          $setOnInsert: { role: 'pending', createdAt: new Date() }
        },
        { upsert: true }
      );
    } catch (e) {
      logger.warn('Failed to log user:', e.message);
    }
  }
  return next();
});

// ---------- Authorization Middleware with Rate Limiting ----------
bot.use(async (ctx, next) => {
  try {
    const telegramId = ctx.from.id.toString();
    
    const rateLimit = await checkUserRateLimit(telegramId, 30, 60000);
    if (!rateLimit.allowed) {
      const waitTime = rateLimit.resetTime ? Math.ceil((rateLimit.resetTime - Date.now()) / 1000) : 60;
      return ctx.reply(`⏳ Too many requests. Please wait ${waitTime} seconds.`);
    }
    
    const user = await auth.getUser(telegramId);
    
    if (!user || user.role === 'pending') {
      return ctx.reply('❌ You are not authorized to use this bot.\nContact admin to purchase access.');
    }
    
    if (user.role !== 'admin' && user.expiryDate && new Date(user.expiryDate) < new Date()) {
      return ctx.reply('❌ Your subscription has expired. Please renew.');
    }
    
    ctx.state.user = user;
    
    // Update user activity asynchronously (don't block)
    User.updateOne(
      { telegramId },
      { $set: { lastActive: new Date() }, $inc: { usageCount: 1 } }
    ).catch(err => logger.error('Failed to update user activity:', err));
    
    return next();
  } catch (error) {
    logger.error('Authorization middleware error:', error);
    return ctx.reply('❌ An error occurred. Please try again.');
  }
});

// ---------- Start Command – Show Main Menu ----------
bot.start(async (ctx) => {
  try {
    ctx.session = null;
    const user = ctx.state.user;
    const menu = getMainMenu(user.role);
    await ctx.reply('🏠 **Main Menu**\nChoose an option:', {
      parse_mode: 'Markdown',
      ...menu
    });
  } catch (error) {
    logger.error('Start command error:', error);
    ctx.reply('❌ Failed to load menu. Please try again.');
  }
});

// ---------- Cancel Command – Clear flow and return to Main Menu ----------
bot.command('cancel', async (ctx) => {
  try {
    ctx.session = null;
    const user = ctx.state.user;
    const menu = getMainMenu(user.role);
    await ctx.reply('❌ Cancelled. Back to **Main Menu**.', {
      parse_mode: 'Markdown',
      ...menu
    });
  } catch (error) {
    logger.error('Cancel command error:', error);
  }
});

// ---------- Download Action – Start Download Flow ----------
bot.action('download', async (ctx) => {
  try {
    await ctx.answerCbQuery();
    ctx.session = { step: 'ID' };
    const cancelBtn = Markup.inlineKeyboard([
      [Markup.button.callback('🔙 Cancel', 'main_menu')]
    ]);
    await ctx.editMessageText("🏁 Fayda ID Downloader\nPlease enter your **FCN/FIN number** (16 or 12 digits):\n\n_Or tap Cancel to return to menu._", {
      parse_mode: 'Markdown',
      ...cancelBtn
    });
  } catch (error) {
    logger.error('Download action error:', error);
    ctx.reply('❌ Failed to start download. Please try again.', { ...getMainMenu(ctx.state.user?.role) });
  }
});

// ---------- Back to Main Menu ----------
bot.action('main_menu', async (ctx) => {
  try {
    await ctx.answerCbQuery();
    ctx.session = null;
    const user = ctx.state.user;
    const menu = getMainMenu(user.role);
    await ctx.editMessageText('🏠 **Main Menu**\nChoose an option:', {
      parse_mode: 'Markdown',
      ...menu
    });
  } catch (error) {
    logger.error('Main menu action error:', error);
    try {
      ctx.reply('🏠 **Main Menu**\nChoose an option:', { parse_mode: 'Markdown', ...getMainMenu(ctx.state.user?.role) });
    } catch (_) {}
  }
});

// ---------- Super Admin: Dashboard ----------
bot.action('dashboard_super', async (ctx) => {
  try {
    await ctx.answerCbQuery();
    
    const buyers = await User.find({ role: 'buyer' })
      .sort({ createdAt: -1 })
      .lean()
      .exec();
    const allSubIds = buyers.flatMap(b => b.subUsers || []);
    const allSubs = await User.find({ telegramId: { $in: allSubIds } })
      .select('telegramId firstName telegramUsername downloadCount')
      .lean()
      .exec();
    const subMap = new Map(allSubs.map(s => [s.telegramId, s]));
    
    const admin = ctx.state.user;
    let text = '📊 **YOUR ADMIN DASHBOARD**\n\n';
    text += `Admin: ${admin.firstName || 'N/A'} (@${admin.telegramUsername || 'N/A'})\n`;
    text += `ID: \`${admin.telegramId}\`\n\n`;
    text += '**Admins (Buyers):**\n\n';
    
    const buttons = [];
    for (const buyer of buyers) {
      const subIds = buyer.subUsers || [];
      const subDownloads = subIds.reduce((sum, id) => sum + ((subMap.get(id) || {}).downloadCount || 0), 0);
      const total = (buyer.downloadCount || 0) + subDownloads;
      text += `**${buyer.firstName || 'N/A'}** (@${buyer.telegramUsername || 'N/A'})\n`;
      text += `ID: \`${buyer.telegramId}\`\n`;
      text += `Work Summary:\n`;
      text += `PDFs: ${buyer.downloadCount || 0}\n`;
      text += `Users: ${subIds.length}\n`;
      text += `Users' PDFs: ${subDownloads}\n`;
      text += `Total: ${total}\n`;
      buttons.push([Markup.button.callback(`Sub Users (${subIds.length})`, `subusers_${buyer.telegramId}`)]);
      text += '\n';
    }
    buttons.push([Markup.button.callback('👥 Manage Users', 'manage_users')], [Markup.button.callback('🔙 Main Menu', 'main_menu')]);
    await ctx.editMessageText(text, { parse_mode: 'Markdown', reply_markup: { inline_keyboard: buttons } });
  } catch (error) {
    logger.error('Dashboard super error:', error);
    ctx.reply('❌ Failed to load dashboard. Please try again.', { ...getMainMenu(ctx.state.user?.role) });
  }
});

// ---------- Super Admin: View Sub Users for a Buyer ----------
bot.action(/subusers_(\d+)/, async (ctx) => {
  try {
    await ctx.answerCbQuery();
    const buyerId = ctx.match[1];
    const buyer = await User.findOne({ telegramId: buyerId }).lean();
    if (!buyer) {
      return ctx.editMessageText('❌ User not found.', Markup.inlineKeyboard([[Markup.button.callback('🔙 Back', 'dashboard_super')]]));
    }
    const subs = await User.find({ telegramId: { $in: buyer.subUsers || [] } })
      .select('telegramId firstName telegramUsername downloadCount')
      .lean()
      .exec();
    
    let text = `**Sub Users**\n`;
    text += `_${buyer.firstName || buyer.telegramId} (@${buyer.telegramUsername || 'N/A'})_\n\n`;
    subs.forEach((sub, i) => {
      text += `${i + 1}. **${sub.firstName || sub.telegramUsername || sub.telegramId}** (@${sub.telegramUsername || 'N/A'})\n`;
      text += `   ID: \`${sub.telegramId}\` | PDFs: ${sub.downloadCount || 0}\n`;
    });
    
    const buttons = subs.map(sub => [Markup.button.callback(`❌ Remove ${sub.firstName || sub.telegramUsername || sub.telegramId}`, `remove_sub_${buyerId}_${sub.telegramId}`)]);
    buttons.push([Markup.button.callback('🔙 Back to Dashboard', 'dashboard_super')]);
    await ctx.editMessageText(text, { parse_mode: 'Markdown', reply_markup: { inline_keyboard: buttons } });
  } catch (error) {
    logger.error('Sub users view error:', error);
    ctx.reply('❌ Failed. Please try again.', { ...getMainMenu(ctx.state.user?.role) });
  }
});

// ---------- Buyer Dashboard (Optimized) ----------
bot.action('dashboard_buyer', async (ctx) => {
  try {
    await ctx.answerCbQuery();
    const buyer = ctx.state.user;
    
    // Optimized: fetch sub-users in one query
    const subs = await User.find({ telegramId: { $in: buyer.subUsers || [] } })
      .select('telegramId firstName telegramUsername downloadCount')
      .lean()
      .exec();
    
    const subDownloads = subs.reduce((sum, sub) => sum + (sub.downloadCount || 0), 0);
    const buyerOwn = buyer.downloadCount || 0;
    const total = buyerOwn + subDownloads;

    let text = '📊 **YOUR ADMIN DASHBOARD**\n\n';
    text += `Admin: ${buyer.firstName || 'N/A'} (@${buyer.telegramUsername || 'N/A'})\n`;
    text += `ID: \`${buyer.telegramId}\`\n\n`;
    text += '**Work Summary:**\n';
    text += `Your Own PDFs: ${buyerOwn}\n`;
    text += `Your Users: ${subs.length}\n`;
    text += `Users' PDFs: ${subDownloads}\n`;
    text += `Total PDFs: ${total}\n\n`;
    text += `**Your Users (Page 1/1):**\n`;
    subs.forEach((sub, i) => {
      text += `${i + 1}. **${sub.firstName || sub.telegramUsername || sub.telegramId}** (@${sub.telegramUsername || 'N/A'})\n`;
      text += `   ID: \`${sub.telegramId}\` | PDFs: ${sub.downloadCount || 0}\n`;
    });

    const keyboard = Markup.inlineKeyboard([
      [Markup.button.callback('👥 Manage Sub‑Users', 'manage_subs')],
      [Markup.button.callback('🔙 Main Menu', 'main_menu')]
    ]);
    await ctx.editMessageText(text, { parse_mode: 'Markdown', ...keyboard });
  } catch (error) {
    logger.error('Dashboard buyer error:', error);
    ctx.reply('❌ Failed to load dashboard. Please try again.', { ...getMainMenu(ctx.state.user?.role) });
  }
});

// ---------- Super Admin: Manage Users ----------
bot.action('manage_users', async (ctx) => {
  try {
    await ctx.answerCbQuery();
    const buyers = await User.find({ role: 'buyer' })
      .sort({ createdAt: -1 })
      .select('telegramId firstName telegramUsername subUsers')
      .lean()
      .exec();
    const pendingCount = await User.countDocuments({ role: 'pending' });
    
    let text = '👥 **Manage Users**\n\n';
    if (pendingCount) text += `📋 ${pendingCount} pending (sent /start, not added yet)\n\n`;
    text += '**Buyers:**\n\n';
    const buttons = [[Markup.button.callback('➕ Add Buyer', 'add_buyer')]];
    for (const buyer of buyers) {
      const subsCount = (buyer.subUsers || []).length;
      const label = `${buyer.firstName || 'N/A'} (@${buyer.telegramUsername || 'N/A'}) – ${subsCount} users`;
      buttons.push([Markup.button.callback(label, `select_admin_${buyer.telegramId}`)]);
    }
    if (pendingCount) buttons.push([Markup.button.callback('📋 View Pending Users', 'view_pending')]);
    buttons.push([Markup.button.callback('🔙 Main Menu', 'main_menu')]);
    await ctx.editMessageText(text, {
      parse_mode: 'Markdown',
      reply_markup: { inline_keyboard: buttons }
    });
  } catch (error) {
    logger.error('Manage users error:', error);
    ctx.reply('❌ Failed to load users. Please try again.', { ...getMainMenu(ctx.state.user?.role) });
  }
});

// ---------- Super Admin: Add Buyer ----------
bot.action('add_buyer', async (ctx) => {
  try {
    await ctx.answerCbQuery();
    ctx.session = { ...ctx.session, step: 'AWAITING_BUYER_ID' };
    const keyboard = Markup.inlineKeyboard([[Markup.button.callback('🔙 Cancel', 'main_menu')]]);
    await ctx.editMessageText(
      '📝 **Add Buyer**\n\nSend the **Telegram ID** of the person (e.g. \`5434080792\`).\n\n_They must have sent /start first. Default 30 days access. Cancel to go back._',
      { parse_mode: 'Markdown', ...keyboard }
    );
  } catch (error) {
    logger.error('Add buyer error:', error);
    ctx.reply('❌ Failed. Please try again.', { ...getMainMenu(ctx.state.user?.role) });
  }
});

// ---------- Super Admin: View Pending Users ----------
bot.action('view_pending', async (ctx) => {
  try {
    await ctx.answerCbQuery();
    const pending = await User.find({ role: 'pending' })
      .sort({ lastActive: -1 })
      .limit(30)
      .select('telegramId firstName telegramUsername lastActive')
      .lean()
      .exec();
    
    let text = '📋 **Pending Users** (sent /start, not added yet)\n\n';
    if (!pending.length) {
      text += 'No pending users.';
    } else {
      pending.forEach((u, i) => {
        const name = u.firstName || u.telegramUsername || u.telegramId;
        const uname = u.telegramUsername ? `@${u.telegramUsername}` : '–';
        text += `${i + 1}. **${name}** (${uname})\n   ID: \`${u.telegramId}\`\n`;
      });
      text += `\n_Use Add Buyer and enter their Telegram ID to add them._`;
    }
    const keyboard = Markup.inlineKeyboard([
      [Markup.button.callback('➕ Add Buyer', 'add_buyer')],
      [Markup.button.callback('🔙 Back to Users', 'manage_users')]
    ]);
    await ctx.editMessageText(text, { parse_mode: 'Markdown', ...keyboard });
  } catch (error) {
    logger.error('View pending error:', error);
    ctx.reply('❌ Failed. Please try again.', { ...getMainMenu(ctx.state.user?.role) });
  }
});

// ---------- Super Admin: Manage a specific buyer ----------
bot.action(/select_admin_(\d+)/, async (ctx) => {
  try {
    await ctx.answerCbQuery();
    const adminId = ctx.match[1];
    const admin = await User.findOne({ telegramId: adminId }).lean();
    
    if (!admin) {
      return ctx.editMessageText('❌ User not found.', Markup.inlineKeyboard([
        [Markup.button.callback('🔙 Back', 'manage_users')]
      ]));
    }

    const subs = await User.find({ telegramId: { $in: admin.subUsers || [] } })
      .select('telegramId firstName telegramUsername downloadCount')
      .lean()
      .exec();
    
    let text = `**Managing:** ${admin.firstName || 'N/A'} (@${admin.telegramUsername || 'N/A'})\n`;
    text += `ID: \`${admin.telegramId}\`\n`;
    text += `PDFs: ${admin.downloadCount || 0} | Users: ${subs.length}\n\n`;
    text += `**Sub‑Users:**\n`;
    subs.forEach((sub, i) => {
      text += `${i+1}. **${sub.firstName || sub.telegramUsername || sub.telegramId}** (@${sub.telegramUsername || 'N/A'})\n`;
      text += `   ID: \`${sub.telegramId}\` | PDFs: ${sub.downloadCount || 0}\n`;
    });

    const buttons = [
      [Markup.button.callback('➕ Add Sub‑User', `add_sub_admin_${adminId}`)],
      [Markup.button.callback('❌ Remove Sub‑User', `remove_sub_admin_${adminId}`)],
      [Markup.button.callback('🗑 Remove Admin', `remove_buyer_${adminId}`)],
      [Markup.button.callback('🔙 Back to Users', 'manage_users')],
      [Markup.button.callback('🏠 Main Menu', 'main_menu')]
    ];
    await ctx.editMessageText(text, {
      parse_mode: 'Markdown',
      reply_markup: { inline_keyboard: buttons }
    });
  } catch (error) {
    logger.error('Select admin error:', error);
    ctx.reply('❌ Failed to load user details. Please try again.', { ...getMainMenu(ctx.state.user?.role) });
  }
});

// ---------- Super Admin: Add Sub‑User ----------
bot.action(/add_sub_admin_(\d+)/, async (ctx) => {
  try {
    await ctx.answerCbQuery();
    const adminId = ctx.match[1];
    ctx.session = {
      ...ctx.session,
      step: 'AWAITING_SUB_IDENTIFIER',
      adminForAdd: adminId
    };
    const keyboard = Markup.inlineKeyboard([
      [Markup.button.callback('🔙 Cancel', `cancel_add_sub_${adminId}`)]
    ]);
    await ctx.editMessageText(
      '📝 **Add Sub‑User**\n\nSend the **Telegram ID** of the person (e.g. \`5434080792\`).\n\n_They must have sent /start to the bot first. Tap Cancel to go back._',
      { parse_mode: 'Markdown', ...keyboard }
    );
  } catch (error) {
    logger.error('Add sub admin error:', error);
    ctx.reply('❌ Failed. Please try again.', { ...getMainMenu(ctx.state.user?.role) });
  }
});

// ---------- Super Admin: Remove Sub‑User selection ----------
bot.action(/remove_sub_admin_(\d+)/, async (ctx) => {
  try {
    await ctx.answerCbQuery();
    const adminId = ctx.match[1];
    const admin = await User.findOne({ telegramId: adminId }).lean();
    const subs = await User.find({ telegramId: { $in: admin.subUsers || [] } })
      .select('telegramId firstName telegramUsername downloadCount')
      .lean()
      .exec();
    
    if (!subs.length) {
      return ctx.editMessageText('❌ This user has no sub‑users.', Markup.inlineKeyboard([
        [Markup.button.callback('🔙 Back', `select_admin_${adminId}`)]
      ]));
    }

    let text = `**Select a sub‑user to remove from ${admin.firstName || admin.telegramUsername || adminId}:**\n\n`;
    const buttons = [];
    subs.forEach(sub => {
      const label = `${sub.firstName || sub.telegramUsername || sub.telegramId} (PDFs: ${sub.downloadCount || 0})`;
      buttons.push([Markup.button.callback(`❌ ${label}`, `remove_sub_${adminId}_${sub.telegramId}`)]);
    });
    buttons.push([Markup.button.callback('🔙 Back', `select_admin_${adminId}`)]);
    await ctx.editMessageText(text, {
      parse_mode: 'Markdown',
      reply_markup: { inline_keyboard: buttons }
    });
  } catch (error) {
    logger.error('Remove sub admin error:', error);
    ctx.reply('❌ Failed to load sub-users. Please try again.', { ...getMainMenu(ctx.state.user?.role) });
  }
});

// ---------- Super Admin: Remove Buyer (demote to pending) ----------
bot.action(/remove_buyer_(\d+)/, async (ctx) => {
  try {
    await ctx.answerCbQuery();
    const buyerId = ctx.match[1];
    const buyer = await User.findOne({ telegramId: buyerId });
    if (!buyer) {
      return ctx.editMessageText('❌ User not found.', Markup.inlineKeyboard([[Markup.button.callback('🔙 Main Menu', 'main_menu')]]));
    }
    buyer.role = 'pending';
    buyer.addedBy = undefined;
    buyer.expiryDate = undefined;
    buyer.subUsers = [];
    await buyer.save();
    await User.updateMany({ addedBy: buyerId }, { role: 'pending', addedBy: undefined, expiryDate: undefined });
    await ctx.editMessageText(`✅ Admin removed. They can be added again later.`, Markup.inlineKeyboard([
      [Markup.button.callback('🔙 Back to Users', 'manage_users')],
      [Markup.button.callback('🏠 Main Menu', 'main_menu')]
    ]));
  } catch (error) {
    logger.error('Remove buyer error:', error);
    ctx.reply('❌ Failed. Please try again.', { ...getMainMenu(ctx.state.user?.role) });
  }
});

// ---------- Super Admin: Execute removal ----------
bot.action(/remove_sub_(\d+)_(\d+)/, async (ctx) => {
  try {
    await ctx.answerCbQuery();
    const adminId = ctx.match[1];
    const subId = ctx.match[2];

    const admin = await User.findOne({ telegramId: adminId });
    if (!admin) {
      return ctx.editMessageText('❌ Admin not found.', Markup.inlineKeyboard([
        [Markup.button.callback('🔙 Main Menu', 'main_menu')]
      ]));
    }

    admin.subUsers = (admin.subUsers || []).filter(id => id !== subId);
    await admin.save();
    await User.deleteOne({ telegramId: subId });

    await ctx.editMessageText(`✅ Sub‑user removed successfully.`, Markup.inlineKeyboard([
      [Markup.button.callback('🔙 Back to Admin', `select_admin_${adminId}`)],
      [Markup.button.callback('🏠 Main Menu', 'main_menu')]
    ]));
  } catch (error) {
    logger.error('Remove sub error:', error);
    ctx.reply('❌ Failed to remove sub-user. Please try again.', { ...getMainMenu(ctx.state.user?.role) });
  }
});

// ---------- Buyer: Manage Own Sub‑Users ----------
bot.action('manage_subs', async (ctx) => {
  try {
    await ctx.answerCbQuery();
    const buyer = ctx.state.user;
    const subs = await User.find({ telegramId: { $in: buyer.subUsers || [] } })
      .select('telegramId firstName telegramUsername downloadCount')
      .lean()
      .exec();

    let text = '👥 **Your Sub‑Users**\n\n';
    if (!subs.length) {
      text += 'You have no sub‑users yet.';
    } else {
      subs.forEach((sub, i) => {
        text += `${i+1}. **${sub.firstName || sub.telegramUsername || sub.telegramId}** (@${sub.telegramUsername || 'N/A'})\n`;
        text += `   ID: \`${sub.telegramId}\` | PDFs: ${sub.downloadCount || 0}\n`;
      });
    }

    const buttons = [
      [Markup.button.callback('➕ Add Sub‑User', 'add_sub_self')]
    ];
    if (subs.length) {
      subs.forEach(sub => {
        buttons.push([Markup.button.callback(`❌ Remove ${sub.firstName || sub.telegramUsername || sub.telegramId}`, `remove_my_sub_${sub.telegramId}`)]);
      });
    }
    buttons.push([Markup.button.callback('🔙 Main Menu', 'main_menu')]);

    await ctx.editMessageText(text, {
      parse_mode: 'Markdown',
      reply_markup: { inline_keyboard: buttons }
    });
  } catch (error) {
    logger.error('Manage subs error:', error);
    ctx.reply('❌ Failed to load sub-users. Please try again.', { ...getMainMenu(ctx.state.user?.role) });
  }
});

// ---------- Buyer: Add Sub‑User (self) ----------
bot.action('add_sub_self', async (ctx) => {
  try {
    await ctx.answerCbQuery();
    ctx.session = { ...ctx.session, step: 'AWAITING_SUB_IDENTIFIER' };
    const keyboard = Markup.inlineKeyboard([
      [Markup.button.callback('🔙 Cancel', 'cancel_add_sub')]
    ]);
    await ctx.editMessageText(
      '📝 **Add Sub‑User**\n\nSend the **Telegram ID** of the person (e.g. \`5434080792\`).\n\n_They must have sent /start to the bot first. Tap Cancel to go back._',
      { parse_mode: 'Markdown', ...keyboard }
    );
  } catch (error) {
    logger.error('Add sub self error:', error);
    ctx.reply('❌ Failed. Please try again.', { ...getMainMenu(ctx.state.user?.role) });
  }
});

// ---------- Cancel Add Sub (buyer: back to Main Menu; admin: back to that buyer) ----------
bot.action('cancel_add_sub', async (ctx) => {
  try {
    await ctx.answerCbQuery();
    ctx.session = null;
    const user = ctx.state.user;
    const menu = getMainMenu(user.role);
    await ctx.editMessageText('❌ Cancelled. Back to **Main Menu**.', {
      parse_mode: 'Markdown',
      ...menu
    });
  } catch (error) {
    logger.error('Cancel add sub error:', error);
  }
});

bot.action(/cancel_add_sub_(\d+)/, async (ctx) => {
  try {
    await ctx.answerCbQuery();
    const adminId = ctx.match[1];
    ctx.session = null;
    const admin = await User.findOne({ telegramId: adminId }).lean();
    if (!admin) {
      const menu = getMainMenu(ctx.state.user?.role);
      return ctx.editMessageText('❌ Cancelled. Back to **Main Menu**.', { parse_mode: 'Markdown', ...menu });
    }
    const subs = await User.find({ telegramId: { $in: admin.subUsers || [] } })
      .select('telegramId firstName telegramUsername downloadCount')
      .lean()
      .exec();
    let text = `**Managing:** ${admin.firstName || 'N/A'} (@${admin.telegramUsername || 'N/A'})\n`;
    text += `ID: \`${admin.telegramId}\`\n`;
    text += `PDFs: ${admin.downloadCount || 0} | Users: ${subs.length}\n\n`;
    text += `**Sub‑Users:**\n`;
    subs.forEach((sub, i) => {
      text += `${i+1}. **${sub.firstName || sub.telegramUsername || sub.telegramId}** (@${sub.telegramUsername || 'N/A'})\n`;
      text += `   ID: \`${sub.telegramId}\` | PDFs: ${sub.downloadCount || 0}\n`;
    });
    const buttons = [
      [Markup.button.callback('➕ Add Sub‑User', `add_sub_admin_${adminId}`)],
      [Markup.button.callback('❌ Remove Sub‑User', `remove_sub_admin_${adminId}`)],
      [Markup.button.callback('🔙 Back to Users', 'manage_users')],
      [Markup.button.callback('🏠 Main Menu', 'main_menu')]
    ];
    await ctx.editMessageText(text, { parse_mode: 'Markdown', reply_markup: { inline_keyboard: buttons } });
  } catch (e) {
    logger.error('Cancel add sub admin error:', e);
  }
});

// ---------- Buyer: Remove Own Sub‑User ----------
bot.action(/remove_my_sub_(\d+)/, async (ctx) => {
  try {
    await ctx.answerCbQuery();
    const subId = ctx.match[1];
    const buyer = ctx.state.user;

    buyer.subUsers = (buyer.subUsers || []).filter(id => id !== subId);
    await buyer.save();
    await User.deleteOne({ telegramId: subId });

    await ctx.editMessageText(`✅ Sub‑user removed.`, Markup.inlineKeyboard([
      [Markup.button.callback('👥 Manage Sub‑Users', 'manage_subs')],
      [Markup.button.callback('🏠 Main Menu', 'main_menu')]
    ]));
  } catch (error) {
    logger.error('Remove my sub error:', error);
    ctx.reply('❌ Failed to remove sub-user. Please try again.', { ...getMainMenu(ctx.state.user?.role) });
  }
});

// ---------- Text Handler – Download Flow & Add Sub‑User ----------
bot.on('text', async (ctx) => {
  try {
    const state = ctx.session;
    if (!state) {
      return;
    }

    const text = ctx.message.text.trim();

    // ----- Add Buyer Flow (Super Admin) -----
    if (state.step === 'AWAITING_BUYER_ID') {
      const telegramId = text.trim().replace(/\s/g, '');
      if (!/^\d+$/.test(telegramId)) {
        const menu = getMainMenu(ctx.state.user?.role);
        return ctx.reply('❌ Please enter a numeric Telegram ID (e.g. 5434080792).', { ...menu });
      }
      try {
        let user = await User.findOne({ telegramId });
        if (!user || user.role === 'pending') {
          ctx.session = null;
          const menu = getMainMenu(ctx.state.user?.role);
          return ctx.reply('⚠️ This user hasn\'t started the bot yet. Ask them to send /start first.', { ...menu });
        }
        if (user.role === 'buyer' || user.role === 'admin') {
          ctx.session = null;
          const menu = getMainMenu(ctx.state.user?.role);
          return ctx.reply('❌ This user is already a buyer or admin.', { ...menu });
        }
        // If they were a sub, remove from old buyer
        if (user.addedBy) {
          await User.updateOne({ telegramId: user.addedBy }, { $pull: { subUsers: user.telegramId } });
        }
        const expiryDate = new Date();
        expiryDate.setDate(expiryDate.getDate() + 30);
        user.role = 'buyer';
        user.addedBy = undefined;
        user.expiryDate = expiryDate;
        user.subUsers = [];
        await user.save();
        ctx.session = null;
        const menu = getMainMenu(ctx.state.user?.role);
        await ctx.reply(`✅ **${user.firstName || user.telegramUsername || user.telegramId}** added as buyer (30 days).`, {
          parse_mode: 'Markdown',
          ...menu
        });
        try {
          await bot.telegram.sendMessage(user.telegramId, "✅ You've been added! Here's your menu:", {
            parse_mode: 'Markdown',
            ...getMainMenu('buyer')
          });
        } catch (e) {
          logger.warn('Could not send menu to new buyer:', e.message);
        }
      } catch (error) {
        logger.error('Add buyer error:', error);
        ctx.session = null;
        ctx.reply('❌ Failed to add buyer. Please try again.', { ...getMainMenu(ctx.state.user?.role) });
      }
      return;
    }

    // ----- Add Sub‑User Flow -----
    if (state.step === 'AWAITING_SUB_IDENTIFIER') {
      const buyerId = state.adminForAdd || ctx.from.id.toString();
      const buyer = await User.findOne({ telegramId: buyerId });
      
      if (!buyer) {
        ctx.session = null;
        return ctx.reply('❌ Buyer not found. Please try again.', { ...getMainMenu(ctx.state.user?.role) });
      }

      const telegramId = text.trim().replace(/\s/g, '');
      if (!/^\d+$/.test(telegramId)) {
        const menu = getMainMenu(ctx.state.user?.role);
        return ctx.reply('❌ Please enter a numeric Telegram ID (e.g. 5434080792).', { ...menu });
      }

      const statusMsg = await ctx.reply('🔍 Looking up user...');
      
      try {
        let subUser = await User.findOne({ telegramId });
        if (!subUser || subUser.role === 'pending') {
          ctx.session = null;
          const menu = getMainMenu(ctx.state.user?.role);
          return ctx.reply(
            "⚠️ This user hasn't started the bot yet.\n\nAsk them to send /start to the bot first.",
            { ...menu }
          );
        }

        if ((buyer.subUsers || []).length >= 9) {
          ctx.session = null;
          const menu = getMainMenu(ctx.state.user?.role);
          return ctx.reply('❌ This buyer already has 9 employees.', { ...menu });
        }
        if ((buyer.subUsers || []).includes(subUser.telegramId)) {
          ctx.session = null;
          const menu = getMainMenu(ctx.state.user?.role);
          return ctx.reply('❌ This user is already an employee of this buyer.', { ...menu });
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

        ctx.session = null;
        const user = ctx.state.user;
        const menu = getMainMenu(user.role);
        await ctx.reply('🏠 **Main Menu**\nChoose an option:', {
          parse_mode: 'Markdown',
          ...menu
        });
        try {
          await bot.telegram.sendMessage(subUser.telegramId, "✅ You've been added! Here's your menu:", {
            parse_mode: 'Markdown',
            ...getMainMenu('sub')
          });
        } catch (e) {
          logger.warn('Could not send menu to new sub-user:', e.message);
        }
      } catch (error) {
        logger.error('Add sub error:', error);
        ctx.session = null;
        ctx.reply('❌ Failed to add employee. Please try again.', { ...getMainMenu(ctx.state.user?.role) });
      }
      return;
    }

    // ----- Download Flow: ID Step -----
    if (state.step === 'ID') {
      const validation = validateFaydaId(text);
      if (!validation.valid) {
        return ctx.reply(`❌ ${validation.error}`, { parse_mode: 'Markdown' });
      }

      const status = await ctx.reply("⏳ Loading...");
      
      let verified = false;
      let lastErr;
      for (let attempt = 1; attempt <= CAPTCHA_VERIFY_ATTEMPTS && !verified; attempt++) {
        try {
          const result = await solver.recaptcha(SITE_KEY, 'https://resident.fayda.et/');
          const res = await fayda.api.post('/verify', {
            idNumber: validation.value,
            verificationMethod: validation.type || 'FCN',
            captchaValue: result.data
          }, { timeout: 35000 });

          ctx.session.tempJwt = res.data.token;
          ctx.session.id = validation.value;
          ctx.session.verificationMethod = validation.type || 'FCN';
          ctx.session.step = 'OTP';
          verified = true;
          await ctx.telegram.editMessageText(ctx.chat.id, status.message_id, null, "Enter the OTP sent to your phone:\n_Send /cancel to return to menu._");
        } catch (e) {
          lastErr = e;
          const errMsg = e.response?.data?.message || e.message || 'Verification failed';
          logger.warn(`ID verification attempt ${attempt}/${CAPTCHA_VERIFY_ATTEMPTS} failed:`, errMsg);
          if (attempt < CAPTCHA_VERIFY_ATTEMPTS) {
            await ctx.telegram.editMessageText(ctx.chat.id, status.message_id, null, `⏳ Loading... retrying (${attempt}/${CAPTCHA_VERIFY_ATTEMPTS})`);
            await new Promise(r => setTimeout(r, CAPTCHA_VERIFY_RETRY_DELAY_MS));
          }
        }
      }
      if (!verified) {
        const rawMsg = lastErr?.response?.data?.message || lastErr?.message || '';
        const userMsg = /invalid|limit/i.test(rawMsg) ? 'Invalid ID' : (rawMsg || 'Verification failed');
        logger.error("ID verification error after retries:", { error: rawMsg, stack: lastErr?.stack });
        ctx.reply(`❌ Error: ${userMsg}\nTry /start again.`);
        ctx.session = null;
      }
      return;
    }

    // ----- Download Flow: OTP Step -----
    if (state.step === 'OTP') {
      // Prevent duplicate processing
      if (state.processingOTP) {
        return; // Already processing, ignore duplicate
      }
      state.processingOTP = true;

      const validation = validateOTP(text);
      if (!validation.valid) {
        state.processingOTP = false;
        return ctx.reply(`❌ ${validation.error}. Please enter a valid OTP.`);
      }

      const status = await ctx.reply("⏳ Verifying OTP and generating document...");
      const authHeader = { ...HEADERS, 'Authorization': `Bearer ${state.tempJwt}` };

      let otpResponse;
      let otpAttempts = 2;
      for (let attempt = 1; attempt <= otpAttempts; attempt++) {
        try {
          otpResponse = await fayda.api.post('/validateOtp', {
            otp: validation.value,
            uniqueId: state.id,
            verificationMethod: state.verificationMethod || 'FCN'
          }, {
            headers: authHeader,
            timeout: 35000
          });
          break;
        } catch (e) {
          const isRetryable = !e.response || (e.response.status >= 500 && e.response.status < 600) || ['ECONNABORTED', 'ETIMEDOUT', 'ECONNRESET'].includes(e.code);
          if (attempt === otpAttempts || !isRetryable) throw e;
          logger.warn(`validateOtp attempt ${attempt} failed, retrying:`, e.message);
          await new Promise(r => setTimeout(r, 2000));
        }
      }

      try {
        const { signature, uin, fullName } = otpResponse.data;
        if (!signature || !uin) {
          throw new Error('Missing signature or uin in OTP response');
        }

        await ctx.telegram.editMessageText(ctx.chat.id, status.message_id, null, "⏳ OTP Verified. Fetching ID file...");

        // Under heavy load (PREFER_QUEUE_PDF=true) skip sync and always queue for controlled concurrency
        let pdfSent = false;
        if (!PREFER_QUEUE_PDF) {
        for (let attempt = 1; attempt <= PDF_SYNC_ATTEMPTS && !pdfSent; attempt++) {
          try {
            const pdfResponse = await fayda.api.post('/printableCredentialRoute', { uin, signature }, {
              headers: authHeader,
              responseType: 'text',
              timeout: 25000
            });
            const { buffer: pdfBuffer } = parsePdfResponse(pdfResponse.data);
            const safeName = (fullName?.eng || 'Fayda_Card').replace(/[^a-zA-Z0-9]/g, '_');
            const filename = `${safeName}.pdf`;

            await ctx.replyWithDocument({
              source: pdfBuffer,
              filename: filename
            }, { caption: "✨ Your Digital ID is ready!" });

            await User.updateOne(
              { telegramId: ctx.from.id.toString() },
              { $inc: { downloadCount: 1 }, $set: { lastDownload: new Date() } }
            );
            ctx.session = null;
            pdfSent = true;

            const user = ctx.state.user;
            const menu = getMainMenu(user.role);
            await ctx.reply('🏠 **Main Menu**\nChoose an option:', {
              parse_mode: 'Markdown',
              ...menu
            });
          } catch (syncErr) {
            lastSyncError = syncErr;
            if (attempt < PDF_SYNC_ATTEMPTS) {
              logger.warn(`Sync PDF attempt ${attempt} failed, retrying:`, syncErr.message);
              await ctx.telegram.editMessageText(ctx.chat.id, status.message_id, null, "⏳ Retrying PDF fetch...");
              await new Promise(r => setTimeout(r, PDF_SYNC_RETRY_DELAY_MS));
            }
          }
        }
        }

        if (pdfSent) {
          // Done
        } else {
          // Sync failed (or PREFER_QUEUE_PDF) — enqueue for background retries
          try {
            const job = await pdfQueue.add({
              chatId: ctx.chat.id,
              userId: ctx.from.id.toString(),
              userRole: ctx.state.user?.role || 'sub',
              authHeader,
              pdfPayload: { uin, signature },
              fullName
            }, {
              priority: 1,
              timeout: 60000
            });
            logger.info(`PDF job ${job.id} queued (sync failed) for user ${ctx.from.id.toString()}`);
          } catch (queueError) {
            logger.error('Queue add failed, trying sync once more:', queueError);
            await ctx.telegram.editMessageText(ctx.chat.id, status.message_id, null, "⏳ Processing PDF directly...");
            try {
              const pdfResponse = await fayda.api.post('/printableCredentialRoute', { uin, signature }, {
                headers: authHeader,
                responseType: 'text',
                timeout: 25000
              });
              const { buffer: pdfBuffer } = parsePdfResponse(pdfResponse.data);
              const safeName = (fullName?.eng || 'Fayda_Card').replace(/[^a-zA-Z0-9]/g, '_');
              await ctx.replyWithDocument({
                source: pdfBuffer,
                filename: `${safeName}.pdf`
              }, { caption: "✨ Your Digital ID is ready!" });
              await User.updateOne(
                { telegramId: ctx.from.id.toString() },
                { $inc: { downloadCount: 1 }, $set: { lastDownload: new Date() } }
              );
              ctx.session = null;
              pdfSent = true;
              const user = ctx.state.user;
              const menu = getMainMenu(user.role);
              await ctx.reply('🏠 **Main Menu**\nChoose an option:', { parse_mode: 'Markdown', ...menu });
            } catch (syncError2) {
              logger.error('Synchronous PDF processing failed:', {
                error: syncError2.message,
                response: safeResponseForLog(syncError2.response?.data)
              });
              await ctx.reply(`❌ Could not generate PDF: ${syncError2.response?.data?.message || syncError2.message}. Please try /start again.`);
              ctx.session = null;
            }
          }

          // Only show "queued" message if we didn't send PDF (queue was used)
          if (!pdfSent) {
            ctx.session = null;
            const user = ctx.state.user;
            const menu = getMainMenu(user.role);
            await ctx.reply('✅ Your request has been queued. You will receive your PDF shortly.\n\n🏠 **Main Menu**\nChoose an option:', {
              parse_mode: 'Markdown',
              ...menu
            });
          }
        }
      } catch (e) {
        logger.error("OTP/PDF Error:", {
          error: e.message,
          stack: e.stack,
          response: safeResponseForLog(e.response?.data)
        });
        try {
          await ctx.reply(`❌ Failed: ${e.response?.data?.message || e.message || 'Unknown error. Please try again.'}`);
        } catch (replyError) {
          logger.error('Failed to send error message:', replyError);
        }
        ctx.session = null;
      } finally {
        // Always clear processing flag
        if (state) {
          state.processingOTP = false;
        }
      }
      return;
    }
  } catch (error) {
    logger.error('Text handler error:', error);
    ctx.reply('❌ An error occurred. Please try again.');
  }
});

// ---------- Graceful Shutdown ----------
async function gracefulShutdown(signal) {
  logger.info(`${signal} received, starting graceful shutdown...`);
  
  try {
    await bot.stop(signal);
    await disconnectDB();
    await pdfQueue.close();
    process.exit(0);
  } catch (error) {
    logger.error('Error during shutdown:', error);
    process.exit(1);
  }
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// ---------- Start Server ----------
async function startServer() {
  try {
    // Connect to database
    await connectDB();

    // Set webhook
    const webhookPath = '/webhook';
    // Ensure WEBHOOK_DOMAIN has https:// prefix
    let webhookDomain = process.env.WEBHOOK_DOMAIN || '';
    if (webhookDomain && !webhookDomain.startsWith('http')) {
      webhookDomain = `https://${webhookDomain}`;
      logger.warn(`⚠️ WEBHOOK_DOMAIN missing protocol, added https://`);
    }
    const webhookUrl = `${webhookDomain}${webhookPath}`;
    await bot.telegram.setWebhook(webhookUrl);
    app.use(bot.webhookCallback(webhookPath));

    // Warn if WEBHOOK_DOMAIN looks like a placeholder
    if (/your-app-name|example\.com|localhost/.test(process.env.WEBHOOK_DOMAIN || '')) {
      logger.warn('⚠️ WEBHOOK_DOMAIN looks like a placeholder. Update it in your deployment Variables to your real URL (e.g. https://fayda-bot.onrender.com) or the bot will not receive messages.');
    }

    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
      logger.info(`🚀 Server running on port ${PORT}`);
      logger.info(`🤖 Webhook active at ${webhookUrl}`);
    });
  } catch (err) {
    logger.error("❌ Failed to start server:", err);
    process.exit(1);
  }
}

startServer();
