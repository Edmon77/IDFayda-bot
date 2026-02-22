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
const crypto = require('crypto');
const helmet = require('helmet');
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
const { validateFaydaId, validateOTP, escMd, displayName } = require('./utils/validators');
const { parsePdfResponse } = require('./utils/pdfHelper');
const { getMainMenu, getPanelTitle, paginate } = require('./utils/menu');
const { migrateRoles } = require('./utils/migrateRoles');
const pdfQueue = require('./queue');
const { safeResponseForLog } = require('./utils/logger');

const PDF_SYNC_ATTEMPTS = 2;
const PDF_SYNC_RETRY_DELAY_MS = 1500;
const CAPTCHA_VERIFY_ATTEMPTS = 3;
const CAPTCHA_VERIFY_RETRY_DELAY_MS = 3000;

// ---------- Express App ----------
const app = express();
app.set('trust proxy', 1); // Trust first proxy (Railway / reverse proxy)

// Security headers
app.use(helmet({ contentSecurityPolicy: false })); // CSP disabled for EJS inline styles
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

// Simple session-based CSRF protection (no third-party library needed)
function csrfToken(req) {
  if (!req.session._csrf) {
    req.session._csrf = crypto.randomBytes(32).toString('hex');
  }
  return req.session._csrf;
}
function csrfProtection(req, res, next) {
  if (req.path === '/webhook') return next(); // Telegram webhook excluded
  if (req.method === 'POST') {
    const token = req.body._csrf || req.headers['x-csrf-token'];
    if (!token || token !== req.session._csrf) {
      return res.status(403).send('Invalid or missing CSRF token. Please refresh the page and try again.');
    }
  }
  next();
}
app.use(csrfProtection);
// Make CSRF token available to all EJS views
app.use((req, res, next) => {
  res.locals.csrfToken = csrfToken(req);
  next();
});

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

// Login brute-force protection (5 attempts per 15 min per IP)
const loginLimiter = require('express-rate-limit')({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Too many login attempts. Please try again later.',
  standardHeaders: true,
  legacyHeaders: false
});

// ---------- Web Dashboard (Admin Management) ----------
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
app.post('/login', loginLimiter, (req, res) => {
  if (!process.env.ADMIN_USER || !process.env.ADMIN_PASS) {
    return res.status(503).send('Admin dashboard not configured.');
  }
  const { username, password } = req.body;
  // Timing-safe comparison to prevent timing attacks
  const userBuf = Buffer.from(String(username || ''));
  const passBuf = Buffer.from(String(password || ''));
  const expectedUserBuf = Buffer.from(process.env.ADMIN_USER);
  const expectedPassBuf = Buffer.from(process.env.ADMIN_PASS);
  const userMatch = userBuf.length === expectedUserBuf.length && crypto.timingSafeEqual(userBuf, expectedUserBuf);
  const passMatch = passBuf.length === expectedPassBuf.length && crypto.timingSafeEqual(passBuf, expectedPassBuf);
  if (userMatch && passMatch) {
    // Regenerate session to prevent session fixation
    req.session.regenerate((err) => {
      if (err) {
        logger.error('Session regeneration failed:', err);
        return res.render('login', { error: 'Server error. Try again.' });
      }
      req.session.admin = true;
      res.redirect('/dashboard');
    });
  } else {
    res.render('login', { error: 'Invalid credentials' });
  }
});
app.get('/logout', (req, res) => {
  req.session.admin = false;
  res.redirect('/login');
});
app.get('/dashboard', requireWebAuth, async (req, res) => {
  const admins = await User.find({ role: 'admin' }).sort({ createdAt: -1 }).lean();
  const allSubIds = admins.flatMap(b => b.subUsers || []);
  const subs = await User.find({ telegramId: { $in: allSubIds } }).select('telegramId downloadCount').lean();
  const subMap = new Map(subs.map(s => [s.telegramId, s.downloadCount || 0]));
  const stats = {
    totalUsers: await User.countDocuments(),
    admins: admins.length,
    subUsers: allSubIds.length,
    expiringSoon: await User.countDocuments({ expiryDate: { $lt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), $gt: new Date() }, role: { $in: ['admin', 'user'] } }),
    totalDownloads: admins.reduce((s, b) => s + (b.downloadCount || 0), 0) + subs.reduce((s, u) => s + (u.downloadCount || 0), 0)
  };
  const enriched = admins.map(b => {
    const subIds = b.subUsers || [];
    const subDownloads = subIds.reduce((sum, id) => sum + (subMap.get(id) || 0), 0);
    return { ...b, subDownloads, totalDownloads: (b.downloadCount || 0) + subDownloads };
  });
  res.render('dashboard', { stats, admins: enriched, error: req.query.error });
});
app.get('/pending', requireWebAuth, async (req, res) => {
  const pending = await User.find({ role: 'unauthorized' }).sort({ lastActive: -1 }).limit(50).lean();
  res.render('pending', { pending });
});
app.post('/add-buyer', requireWebAuth, async (req, res) => {
  const { telegramId, expiryDays = 30 } = req.body;
  if (!telegramId || !/^\d+$/.test(String(telegramId).trim())) {
    return res.redirect('/dashboard?error=invalid_id');
  }
  const tid = String(telegramId).trim();
  let user = await User.findOne({ telegramId: tid });
  if (!user) {
    return res.redirect('/dashboard?error=user_must_start');
  }
  if (user.role === 'admin') {
    return res.redirect('/dashboard?error=already_added');
  }
  if (user.addedBy) await User.updateOne({ telegramId: user.addedBy }, { $pull: { subUsers: tid } });
  const expiry = new Date();
  expiry.setDate(expiry.getDate() + parseInt(expiryDays) || 30);
  user.role = 'admin';
  user.addedBy = undefined;
  user.expiryDate = expiry;
  user.subUsers = [];
  await user.save();
  try {
    await bot.telegram.sendMessage(tid, "✅ Your access has been activated!", { parse_mode: 'Markdown' });
    await bot.telegram.sendMessage(tid, getPanelTitle('admin') + '\n\nChoose an option:', { parse_mode: 'Markdown', ...getMainMenu('admin') });
  } catch (e) { }
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
  if (!subUser) return res.redirect(`/buyer/${req.params.id}?error=must_start`);
  if (subUser.role === 'admin') return res.redirect(`/buyer/${req.params.id}?error=already_admin`);
  if ((buyer.subUsers || []).length >= 9) return res.redirect(`/buyer/${req.params.id}?error=full`);
  if ((buyer.subUsers || []).includes(tid)) return res.redirect(`/buyer/${req.params.id}?error=already`);
  buyer.subUsers = buyer.subUsers || [];
  buyer.subUsers.push(tid);
  await buyer.save();
  subUser.role = 'user';
  subUser.addedBy = buyer.telegramId;
  subUser.parentAdmin = buyer.telegramId;
  subUser.expiryDate = buyer.expiryDate;
  await subUser.save();
  try {
    await bot.telegram.sendMessage(tid, "✅ Your access has been activated!", { parse_mode: 'Markdown' });
    await bot.telegram.sendMessage(tid, getPanelTitle('user') + '\n\nChoose an option:', { parse_mode: 'Markdown', ...getMainMenu('user') });
  } catch (e) { }
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
  buyer.role = 'unauthorized';
  buyer.addedBy = undefined;
  buyer.expiryDate = undefined;
  buyer.subUsers = [];
  await buyer.save();
  await User.updateMany({ addedBy: req.params.id }, { role: 'unauthorized', addedBy: undefined, parentAdmin: undefined, expiryDate: undefined });
  res.redirect('/dashboard');
});
app.get('/export-users', requireWebAuth, async (req, res) => {
  const users = await User.find({}).lean();
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

// ---------- Upsert User + Authorization + Rate Limiting (single DB query) ----------
bot.use(async (ctx, next) => {
  if (!ctx.from) return next();
  try {
    const telegramId = ctx.from.id.toString();

    // Rate limit check
    const rateLimit = await checkUserRateLimit(telegramId, 30, 60000);
    if (!rateLimit.allowed) {
      const waitTime = rateLimit.resetTime ? Math.ceil((rateLimit.resetTime - Date.now()) / 1000) : 60;
      return ctx.reply(`⏳ Too many requests. Please wait ${waitTime} seconds.`);
    }

    // Single DB call: upsert profile + return current doc (replaces two separate queries)
    const user = await User.findOneAndUpdate(
      { telegramId },
      {
        $set: {
          firstName: ctx.from.first_name,
          lastName: ctx.from.last_name,
          telegramUsername: ctx.from.username,
          lastActive: new Date()
        },
        $inc: { usageCount: 1 },
        $setOnInsert: { role: 'unauthorized', isWaitingApproval: true, createdAt: new Date() }
      },
      { upsert: true, new: true }
    );

    if (!user || user.role === 'unauthorized') {
      return ctx.reply(
        `❌ Access Denied\n\nYour Telegram ID: \`${telegramId}\`\n\nSend this ID to an admin to purchase access.`,
        { parse_mode: 'Markdown' }
      );
    }

    if (user.expiryDate && new Date(user.expiryDate) < new Date()) {
      return ctx.reply('❌ Your subscription has expired. Please renew.');
    }

    ctx.state.user = user;
    return next();
  } catch (error) {
    logger.error('Authorization middleware error:', error);
    return ctx.reply('❌ An error occurred. Please try again.');
  }
});

// ---------- Role Guard Helper ----------
function isAdmin(ctx) {
  return ctx.state.user && ctx.state.user.role === 'admin';
}
async function adminGuard(ctx) {
  if (!isAdmin(ctx)) {
    try { await ctx.answerCbQuery('❌ Access denied — admin only.'); } catch (_) { }
    return false;
  }
  return true;
}

// ---------- Start Command – Show Main Menu ----------
bot.start(async (ctx) => {
  try {
    ctx.session = null;
    const user = ctx.state.user;
    const menu = getMainMenu(user.role);
    const title = getPanelTitle(user.role);
    await ctx.reply(`${title}\n\nChoose an option:`, {
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
    const title = getPanelTitle(user.role);
    await ctx.reply('❌ Cancelled. Back to **Main Menu**.\n\n' + title + '\n\nChoose an option:', {
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
    const title = getPanelTitle(user.role);
    await ctx.editMessageText(`${title}\n\nChoose an option:`, {
      parse_mode: 'Markdown',
      ...menu
    });
  } catch (error) {
    logger.error('Main menu action error:', error);
    try {
      const title = getPanelTitle(ctx.state.user?.role);
      ctx.reply(`${title}\n\nChoose an option:`, { parse_mode: 'Markdown', ...getMainMenu(ctx.state.user?.role) });
    } catch (_) { }
  }
});



// ---------- Admin: View Admins (paginated 10 per page) ----------
bot.action(/view_admins_page_(\d+)/, async (ctx) => {
  try {
    await ctx.answerCbQuery();
    if (!(await adminGuard(ctx))) return;
    const page = parseInt(ctx.match[1], 10);
    const admins = await User.find({ role: 'admin' }).sort({ createdAt: -1 }).select('telegramId firstName telegramUsername subUsers').lean();
    const { items: pageAdmins, page: p, totalPages } = paginate(admins, page);
    let text = '👑 **Your Admins** (Page ' + p + '/' + totalPages + '):\n\n';
    pageAdmins.forEach((a, i) => {
      const count = (a.subUsers || []).length;
      text += `${(page - 1) * 10 + i + 1}. ${escMd(a.firstName) || 'N/A'} (@${escMd(a.telegramUsername) || 'N/A'})\n`;
      text += `   ID: \`${a.telegramId}\`\n   Users: ${count}\n\n`;
    });
    const btns = [];
    if (totalPages > 1) {
      const row = [];
      if (p > 1) row.push(Markup.button.callback('⏮️ Previous', `view_admins_page_${p - 1}`));
      if (p < totalPages) row.push(Markup.button.callback('⏭️ Next', `view_admins_page_${p + 1}`));
      if (row.length) btns.push(row);
    }
    btns.push([Markup.button.callback('🔙 Back', 'manage_users')]);
    await ctx.editMessageText(text, { parse_mode: 'Markdown', reply_markup: { inline_keyboard: btns } });
  } catch (error) {
    logger.error('View admins error:', error);
    ctx.reply('❌ Failed.', { ...getMainMenu(ctx.state.user?.role) });
  }
});

// ---------- Admin: View My Users (paginated 10 per page) ----------
bot.action(/view_my_users_page_(\d+)/, async (ctx) => {
  try {
    await ctx.answerCbQuery();
    const admin = ctx.state.user;
    const userIds = admin.subUsers || [];
    const users = await User.find({ telegramId: { $in: userIds } }).select('telegramId firstName telegramUsername downloadCount').lean();
    const page = parseInt(ctx.match[1], 10);
    const { items: pageUsers, page: p, totalPages } = paginate(users, page);
    let text = '🛠 **Your Users** (Page ' + p + '/' + totalPages + '):\n\n';
    pageUsers.forEach((u, i) => {
      text += `${(page - 1) * 10 + i + 1}. ${escMd(u.firstName) || 'N/A'} (@${escMd(u.telegramUsername) || 'N/A'})\n`;
      text += `   ID: \`${u.telegramId}\`\n   PDFs: ${u.downloadCount || 0}\n\n`;
    });
    const btns = [];
    if (totalPages > 1) {
      const row = [];
      if (p > 1) row.push(Markup.button.callback('⏮️ Previous', `view_my_users_page_${p - 1}`));
      if (p < totalPages) row.push(Markup.button.callback('⏭️ Next', `view_my_users_page_${p + 1}`));
      if (row.length) btns.push(row);
    }
    btns.push([Markup.button.callback('🔙 Back', 'manage_users')]);
    await ctx.editMessageText(text, { parse_mode: 'Markdown', reply_markup: { inline_keyboard: btns } });
  } catch (error) {
    logger.error('View my users error:', error);
    ctx.reply('❌ Failed.', { ...getMainMenu(ctx.state.user?.role) });
  }
});

// ---------- Admin: Remove Admin list (paginated) ----------
bot.action(/remove_admin_list_(\d+)/, async (ctx) => {
  try {
    await ctx.answerCbQuery();
    if (!(await adminGuard(ctx))) return;
    const page = parseInt(ctx.match[1], 10);
    const admins = await User.find({ role: 'admin' }).sort({ createdAt: -1 }).select('telegramId firstName telegramUsername subUsers').lean();
    const { items: pageAdmins, page: p, totalPages } = paginate(admins, page);
    if (!pageAdmins.length) {
      await ctx.editMessageText('❌ No admins to remove.', Markup.inlineKeyboard([[Markup.button.callback('🔙 Back', 'manage_users')]]));
      return;
    }
    let text = '**Select an admin to remove:**\n\n';
    pageAdmins.forEach((a, i) => {
      text += `${(page - 1) * 10 + i + 1}. ${escMd(a.firstName) || 'N/A'} (@${escMd(a.telegramUsername) || 'N/A'}) – ID: \`${a.telegramId}\`\n`;
    });
    const btns = pageAdmins.map(a => [Markup.button.callback(`❌ Remove ${escMd(a.firstName) || a.telegramId}`, `remove_buyer_${a.telegramId}`)]);
    if (totalPages > 1) {
      const row = [];
      if (p > 1) row.push(Markup.button.callback('⏮️ Previous', `remove_admin_list_${p - 1}`));
      if (p < totalPages) row.push(Markup.button.callback('⏭️ Next', `remove_admin_list_${p + 1}`));
      btns.push(row);
    }
    btns.push([Markup.button.callback('🔙 Back', 'manage_users')]);
    await ctx.editMessageText(text, { parse_mode: 'Markdown', reply_markup: { inline_keyboard: btns } });
  } catch (error) {
    logger.error('Remove admin list error:', error);
    ctx.reply('❌ Failed.', { ...getMainMenu(ctx.state.user?.role) });
  }
});

// ---------- Admin: Remove User list (paginated) ----------
bot.action(/remove_my_user_list_(\d+)/, async (ctx) => {
  try {
    await ctx.answerCbQuery();
    const admin = ctx.state.user;
    const userIds = admin.subUsers || [];
    const users = await User.find({ telegramId: { $in: userIds } }).select('telegramId firstName telegramUsername').lean();
    const page = parseInt(ctx.match[1], 10);
    const { items: pageUsers, page: p, totalPages } = paginate(users, page);
    if (!pageUsers.length) {
      await ctx.editMessageText('❌ No users to remove.', Markup.inlineKeyboard([[Markup.button.callback('🔙 Back', 'manage_users')]]));
      return;
    }
    let text = '**Select a user to remove:**\n\n';
    pageUsers.forEach((u, i) => {
      text += `${(page - 1) * 10 + i + 1}. ${escMd(u.firstName) || 'N/A'} (@${escMd(u.telegramUsername) || 'N/A'}) – ID: \`${u.telegramId}\`\n`;
    });
    const btns = pageUsers.map(u => [Markup.button.callback(`❌ Remove ${escMd(u.firstName) || u.telegramId}`, `remove_my_sub_${u.telegramId}`)]);
    if (totalPages > 1) {
      const row = [];
      if (p > 1) row.push(Markup.button.callback('⏮️ Previous', `remove_my_user_list_${p - 1}`));
      if (p < totalPages) row.push(Markup.button.callback('⏭️ Next', `remove_my_user_list_${p + 1}`));
      btns.push(row);
    }
    btns.push([Markup.button.callback('🔙 Back', 'manage_users')]);
    await ctx.editMessageText(text, { parse_mode: 'Markdown', reply_markup: { inline_keyboard: btns } });
  } catch (error) {
    logger.error('Remove my user list error:', error);
    ctx.reply('❌ Failed.', { ...getMainMenu(ctx.state.user?.role) });
  }
});

// ---------- Admin: Add User Under Admin (start flow) ----------
bot.action('add_user_under_admin', async (ctx) => {
  try {
    await ctx.answerCbQuery();
    if (!(await adminGuard(ctx))) return;
    ctx.session = { ...ctx.session, step: 'AWAITING_ADMIN_ID_FOR_USER' };
    await ctx.editMessageText(
      '📝 **Add User Under Admin**\n\nSend the **Telegram ID** of the **admin** (e.g. \`358404165\`).\n\n_They must already be an admin._',
      { parse_mode: 'Markdown', ...Markup.inlineKeyboard([[Markup.button.callback('🔙 Cancel', 'main_menu')]]) }
    );
  } catch (error) {
    logger.error('Add user under admin error:', error);
    ctx.reply('❌ Failed.', { ...getMainMenu(ctx.state.user?.role) });
  }
});

// ---------- Admin: Remove User Under Admin (list admins, then pick user) ----------
bot.action('remove_user_under_admin', async (ctx) => {
  try {
    await ctx.answerCbQuery();
    if (!(await adminGuard(ctx))) return;
    const admins = await User.find({ role: 'admin' }).sort({ createdAt: -1 }).select('telegramId firstName telegramUsername subUsers').lean();
    const { items: pageAdmins, page: p, totalPages } = paginate(admins, 1);
    if (!pageAdmins.length) {
      await ctx.editMessageText('❌ No admins.', Markup.inlineKeyboard([[Markup.button.callback('🔙 Back', 'manage_users')]]));
      return;
    }
    let text = '**Select the admin whose user you want to remove:**\n\n';
    pageAdmins.forEach((a, i) => {
      text += `${i + 1}. ${escMd(a.firstName) || 'N/A'} (@${escMd(a.telegramUsername) || 'N/A'}) – ID: \`${a.telegramId}\`\n`;
    });
    const btns = pageAdmins.map(a => [Markup.button.callback(`${a.firstName || a.telegramId}`, `remove_under_admin_${a.telegramId}_1`)]);
    if (totalPages > 1) btns.push([Markup.button.callback('⏭️ Next', `remove_under_admin_list_2`)]);
    btns.push([Markup.button.callback('🔙 Back', 'manage_users')]);
    await ctx.editMessageText(text, { parse_mode: 'Markdown', reply_markup: { inline_keyboard: btns } });
  } catch (error) {
    logger.error('Remove user under admin error:', error);
    ctx.reply('❌ Failed.', { ...getMainMenu(ctx.state.user?.role) });
  }
});

bot.action(/remove_under_admin_(\d+)_(\d+)/, async (ctx) => {
  try {
    await ctx.answerCbQuery();
    if (!(await adminGuard(ctx))) return;
    const adminId = ctx.match[1];
    const page = parseInt(ctx.match[2], 10);
    const admin = await User.findOne({ telegramId: adminId }).lean();
    if (!admin) {
      return ctx.editMessageText('❌ Admin not found.', Markup.inlineKeyboard([[Markup.button.callback('🔙 Back', 'manage_users')]]));
    }
    const userIds = admin.subUsers || [];
    const users = await User.find({ telegramId: { $in: userIds } }).select('telegramId firstName telegramUsername').lean();
    const { items: pageUsers, page: p, totalPages } = paginate(users, page);
    if (!pageUsers.length) {
      return ctx.editMessageText('❌ This admin has no users.', Markup.inlineKeyboard([[Markup.button.callback('🔙 Back', 'remove_user_under_admin')]]));
    }
    let text = `**Remove user under ${escMd(admin.firstName) || admin.telegramId}:**\n\n`;
    pageUsers.forEach((u, i) => {
      text += `${(page - 1) * 10 + i + 1}. ${escMd(u.firstName) || 'N/A'} (@${escMd(u.telegramUsername) || 'N/A'}) – ID: \`${u.telegramId}\`\n`;
    });
    const btns = pageUsers.map(u => [Markup.button.callback(`❌ ${escMd(u.firstName) || u.telegramId}`, `remove_sub_${adminId}_${u.telegramId}`)]);
    if (totalPages > 1) {
      const row = [];
      if (p > 1) row.push(Markup.button.callback('⏮️ Previous', `remove_under_admin_${adminId}_${p - 1}`));
      if (p < totalPages) row.push(Markup.button.callback('⏭️ Next', `remove_under_admin_${adminId}_${p + 1}`));
      btns.push(row);
    }
    btns.push([Markup.button.callback('🔙 Back', 'remove_user_under_admin')]);
    await ctx.editMessageText(text, { parse_mode: 'Markdown', reply_markup: { inline_keyboard: btns } });
  } catch (error) {
    logger.error('Remove under admin error:', error);
    ctx.reply('❌ Failed.', { ...getMainMenu(ctx.state.user?.role) });
  }
});

bot.action(/remove_under_admin_list_(\d+)/, async (ctx) => {
  try {
    await ctx.answerCbQuery();
    if (!(await adminGuard(ctx))) return;
    const page = parseInt(ctx.match[1], 10);
    const admins = await User.find({ role: 'admin' }).sort({ createdAt: -1 }).select('telegramId firstName telegramUsername').lean();
    const { items: pageAdmins, page: p, totalPages } = paginate(admins, page);
    let text = '**Select the admin whose user you want to remove:**\n\n';
    pageAdmins.forEach((a, i) => {
      text += `${(page - 1) * 10 + i + 1}. ${escMd(a.firstName) || 'N/A'} (@${escMd(a.telegramUsername) || 'N/A'}) – ID: \`${a.telegramId}\`\n`;
    });
    const btns = pageAdmins.map(a => [Markup.button.callback(`${a.firstName || a.telegramId}`, `remove_under_admin_${a.telegramId}_1`)]);
    if (totalPages > 1) {
      const row = [];
      if (p > 1) row.push(Markup.button.callback('⏮️ Previous', `remove_under_admin_list_${p - 1}`));
      if (p < totalPages) row.push(Markup.button.callback('⏭️ Next', `remove_under_admin_list_${p + 1}`));
      btns.push(row);
    }
    btns.push([Markup.button.callback('🔙 Back', 'manage_users')]);
    await ctx.editMessageText(text, { parse_mode: 'Markdown', reply_markup: { inline_keyboard: btns } });
  } catch (e) {
    logger.error('Remove under admin list error:', e);
  }
});

// ---------- Admin: View Sub Users for an Admin ----------
bot.action(/subusers_(\d+)/, async (ctx) => {
  try {
    await ctx.answerCbQuery();
    if (!(await adminGuard(ctx))) return;
    const buyerId = ctx.match[1];
    const buyer = await User.findOne({ telegramId: buyerId }).lean();
    if (!buyer) {
      return ctx.editMessageText('❌ User not found.', Markup.inlineKeyboard([[Markup.button.callback('🔙 Back', 'dashboard_buyer')]]));
    }
    const subs = await User.find({ telegramId: { $in: buyer.subUsers || [] } })
      .select('telegramId firstName telegramUsername downloadCount')
      .lean()
      .exec();

    let text = `**Sub Users**\n`;
    text += `_${escMd(buyer.firstName) || buyer.telegramId} (@${escMd(buyer.telegramUsername) || 'N/A'})_\n\n`;
    subs.forEach((sub, i) => {
      text += `${i + 1}. **${displayName(sub)}** (@${escMd(sub.telegramUsername) || 'N/A'})\n`;
      text += `   ID: \`${sub.telegramId}\` | PDFs: ${sub.downloadCount || 0}\n`;
    });

    const buttons = subs.map(sub => [Markup.button.callback(`❌ Remove ${displayName(sub)}`, `remove_sub_${buyerId}_${sub.telegramId}`)]);
    buttons.push([Markup.button.callback('🔙 Back to Dashboard', 'dashboard_buyer')]);
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
    const { items: pageSubs, page: p, totalPages } = paginate(subs, 1);

    let text = '📊 **YOUR ADMIN DASHBOARD**\n\n';
    text += `Admin: ${escMd(buyer.firstName) || 'N/A'} (@${escMd(buyer.telegramUsername) || 'N/A'})\n`;
    text += `ID: \`${buyer.telegramId}\`\n\n`;
    text += '**Work Summary:**\n';
    text += `Your Own PDFs: ${buyerOwn}\n`;
    text += `Your Users: ${subs.length}\n`;
    text += `Users' PDFs: ${subDownloads}\n`;
    text += `Total PDFs: ${total}\n\n`;
    text += `**Your Users** (Page ${p}/${totalPages})\n\n`;
    pageSubs.forEach((sub, i) => {
      text += `${(p - 1) * 10 + i + 1}. ${escMd(sub.firstName) || 'N/A'} (@${escMd(sub.telegramUsername) || 'N/A'})\n`;
      text += `   ID: \`${sub.telegramId}\`\n   PDFs: ${sub.downloadCount || 0}\n\n`;
    });

    const keyboard = [];
    if (totalPages > 1) {
      const row = [];
      if (p > 1) row.push(Markup.button.callback('⏮️ Previous', `dashboard_buyer_page_${p - 1}`));
      if (p < totalPages) row.push(Markup.button.callback('⏭️ Next', `dashboard_buyer_page_${p + 1}`));
      keyboard.push(row);
    }
    keyboard.push([Markup.button.callback('👥 Manage Users', 'manage_users')], [Markup.button.callback('🔙 Main Menu', 'main_menu')]);
    await ctx.editMessageText(text, { parse_mode: 'Markdown', reply_markup: { inline_keyboard: keyboard } });
  } catch (error) {
    logger.error('Dashboard buyer error:', error);
    ctx.reply('❌ Failed to load dashboard. Please try again.', { ...getMainMenu(ctx.state.user?.role) });
  }
});

bot.action(/dashboard_buyer_page_(\d+)/, async (ctx) => {
  try {
    await ctx.answerCbQuery();
    const page = parseInt(ctx.match[1], 10);
    const buyer = ctx.state.user;
    const subs = await User.find({ telegramId: { $in: buyer.subUsers || [] } })
      .select('telegramId firstName telegramUsername downloadCount')
      .lean()
      .exec();
    const subDownloads = subs.reduce((sum, sub) => sum + (sub.downloadCount || 0), 0);
    const buyerOwn = buyer.downloadCount || 0;
    const total = buyerOwn + subDownloads;
    const { items: pageSubs, page: p, totalPages } = paginate(subs, page);
    let text = '📊 **YOUR ADMIN DASHBOARD**\n\n';
    text += `Admin: ${escMd(buyer.firstName) || 'N/A'} (@${escMd(buyer.telegramUsername) || 'N/A'})\n`;
    text += `ID: \`${buyer.telegramId}\`\n\n`;
    text += '**Work Summary:**\n';
    text += `Your Own PDFs: ${buyerOwn}\nYour Users: ${subs.length}\nUsers' PDFs: ${subDownloads}\nTotal PDFs: ${total}\n\n`;
    text += `**Your Users** (Page ${p}/${totalPages})\n\n`;
    pageSubs.forEach((sub, i) => {
      text += `${(p - 1) * 10 + i + 1}. ${escMd(sub.firstName) || 'N/A'} (@${escMd(sub.telegramUsername) || 'N/A'})\n`;
      text += `   ID: \`${sub.telegramId}\`\n   PDFs: ${sub.downloadCount || 0}\n\n`;
    });
    const keyboard = [];
    if (totalPages > 1) {
      const row = [];
      if (p > 1) row.push(Markup.button.callback('⏮️ Previous', `dashboard_buyer_page_${p - 1}`));
      if (p < totalPages) row.push(Markup.button.callback('⏭️ Next', `dashboard_buyer_page_${p + 1}`));
      keyboard.push(row);
    }
    keyboard.push([Markup.button.callback('👥 Manage Users', 'manage_users')], [Markup.button.callback('🔙 Main Menu', 'main_menu')]);
    await ctx.editMessageText(text, { parse_mode: 'Markdown', reply_markup: { inline_keyboard: keyboard } });
  } catch (e) {
    logger.error('Dashboard buyer page error:', e);
    ctx.reply('❌ Failed.', { ...getMainMenu(ctx.state.user?.role) });
  }
});

// ---------- Manage Users (Admin) ----------
bot.action('manage_users', async (ctx) => {
  try {
    await ctx.answerCbQuery();
    const user = ctx.state.user;
    if (!user || !user.role) {
      return ctx.reply('❌ Session error. Send /start again.', { ...getMainMenu('user') });
    }

    const sendScreen = async (text, keyboard) => {
      try {
        await ctx.editMessageText(text, { parse_mode: 'Markdown', ...keyboard });
      } catch (editErr) {
        logger.warn('manage_users editMessageText failed, sending new message:', editErr.message);
        await ctx.reply(text, { parse_mode: 'Markdown', ...keyboard });
      }
    };



    if (user.role === 'admin') {
      const title = '🛠 **ADMIN USER MANAGEMENT**\n\n';
      const sub = `Admin: ${escMd(user.firstName) || 'N/A'} (@${escMd(user.telegramUsername) || 'N/A'})\nID: \`${user.telegramId}\`\n\n`;
      const keyboard = Markup.inlineKeyboard([
        [Markup.button.callback('1️⃣ View My Users', 'view_my_users_page_1')],
        [Markup.button.callback('2️⃣ Add User', 'add_sub_self')],
        [Markup.button.callback('3️⃣ Remove User', 'remove_my_user_list_1')],
        [Markup.button.callback('4️⃣ 🔙 Back to Main Menu', 'main_menu')]
      ]);
      await sendScreen(title + sub, keyboard);
      return;
    }

    await sendScreen(getPanelTitle(user.role) + '\n\nChoose an option:', getMainMenu(user.role));
  } catch (error) {
    logger.error('Manage users error:', error?.message || error, error?.stack);
    try {
      ctx.reply('❌ Failed to load users. Please try again.', { ...getMainMenu(ctx.state.user?.role || 'user') });
    } catch (_) { }
  }
});

// ---------- Admin: Add Buyer ----------
bot.action('add_buyer', async (ctx) => {
  try {
    await ctx.answerCbQuery();
    if (!(await adminGuard(ctx))) return;
    ctx.session = { ...ctx.session, step: 'AWAITING_BUYER_ID' };
    const keyboard = Markup.inlineKeyboard([[Markup.button.callback('🔙 Cancel', 'main_menu')]]);
    await ctx.editMessageText(
      '📝 **Add Admin**\n\nSend the **Telegram ID** of the person (e.g. \`5434080792\`).\n\n_They must have sent /start first. Default 30 days access. Cancel to go back._',
      { parse_mode: 'Markdown', ...keyboard }
    );
  } catch (error) {
    logger.error('Add buyer error:', error);
    ctx.reply('❌ Failed. Please try again.', { ...getMainMenu(ctx.state.user?.role) });
  }
});

// ---------- Admin: View Pending Users ----------
bot.action('view_pending', async (ctx) => {
  try {
    await ctx.answerCbQuery();
    if (!(await adminGuard(ctx))) return;
    const pending = await User.find({ role: 'unauthorized' })
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
        const name = escMd(u.firstName) || escMd(u.telegramUsername) || u.telegramId;
        const uname = u.telegramUsername ? `@${escMd(u.telegramUsername)}` : '–';
        text += `${i + 1}. **${name}** (${uname})\n   ID: \`${u.telegramId}\`\n`;
      });
      text += `\n_Use Add Buyer and enter their Telegram ID to add them._`;
    }
    const keyboard = Markup.inlineKeyboard([
      [Markup.button.callback('➕ Add Admin', 'add_buyer')],
      [Markup.button.callback('🔙 Back to Users', 'manage_users')]
    ]);
    await ctx.editMessageText(text, { parse_mode: 'Markdown', ...keyboard });
  } catch (error) {
    logger.error('View pending error:', error);
    ctx.reply('❌ Failed. Please try again.', { ...getMainMenu(ctx.state.user?.role) });
  }
});

// ---------- Admin: Manage a specific buyer ----------
bot.action(/select_admin_(\d+)/, async (ctx) => {
  try {
    await ctx.answerCbQuery();
    if (!(await adminGuard(ctx))) return;
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

    let text = `**Managing:** ${escMd(admin.firstName) || 'N/A'} (@${escMd(admin.telegramUsername) || 'N/A'})\n`;
    text += `ID: \`${admin.telegramId}\`\n`;
    text += `PDFs: ${admin.downloadCount || 0} | Users: ${subs.length}\n\n`;
    text += `**Sub‑Users:**\n`;
    subs.forEach((sub, i) => {
      text += `${i + 1}. **${displayName(sub)}** (@${escMd(sub.telegramUsername) || 'N/A'})\n`;
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

// ---------- Admin: Add Sub‑User ----------
bot.action(/add_sub_admin_(\d+)/, async (ctx) => {
  try {
    await ctx.answerCbQuery();
    if (!(await adminGuard(ctx))) return;
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

// ---------- Admin: Remove Sub‑User selection ----------
bot.action(/remove_sub_admin_(\d+)/, async (ctx) => {
  try {
    await ctx.answerCbQuery();
    if (!(await adminGuard(ctx))) return;
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

    let text = `**Select a sub‑user to remove from ${escMd(admin.firstName) || escMd(admin.telegramUsername) || adminId}:**\n\n`;
    const buttons = [];
    subs.forEach(sub => {
      const label = `${displayName(sub)} (PDFs: ${sub.downloadCount || 0})`;
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

// ---------- Admin: Remove Buyer (demote to pending) ----------
bot.action(/remove_buyer_(\d+)/, async (ctx) => {
  try {
    await ctx.answerCbQuery();
    if (!(await adminGuard(ctx))) return;
    const buyerId = ctx.match[1];
    const buyer = await User.findOne({ telegramId: buyerId });
    if (!buyer) {
      return ctx.editMessageText('❌ User not found.', Markup.inlineKeyboard([[Markup.button.callback('🔙 Main Menu', 'main_menu')]]));
    }
    buyer.role = 'unauthorized';
    buyer.addedBy = undefined;
    buyer.expiryDate = undefined;
    buyer.subUsers = [];
    await buyer.save();
    await User.updateMany({ addedBy: buyerId }, { role: 'unauthorized', addedBy: undefined, parentAdmin: undefined, expiryDate: undefined });
    await ctx.editMessageText(`✅ Admin removed. They can be added again later.`, Markup.inlineKeyboard([
      [Markup.button.callback('🔙 Back to Users', 'manage_users')],
      [Markup.button.callback('🏠 Main Menu', 'main_menu')]
    ]));
  } catch (error) {
    logger.error('Remove buyer error:', error);
    ctx.reply('❌ Failed. Please try again.', { ...getMainMenu(ctx.state.user?.role) });
  }
});

// ---------- Admin: Execute removal ----------
bot.action(/remove_sub_(\d+)_(\d+)/, async (ctx) => {
  try {
    await ctx.answerCbQuery();
    if (!(await adminGuard(ctx))) return;
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
        text += `${i + 1}. **${displayName(sub)}** (@${escMd(sub.telegramUsername) || 'N/A'})\n`;
        text += `   ID: \`${sub.telegramId}\` | PDFs: ${sub.downloadCount || 0}\n`;
      });
    }

    const buttons = [
      [Markup.button.callback('➕ Add Sub‑User', 'add_sub_self')]
    ];
    if (subs.length) {
      subs.forEach(sub => {
        buttons.push([Markup.button.callback(`❌ Remove ${displayName(sub)}`, `remove_my_sub_${sub.telegramId}`)]);
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
    const title = getPanelTitle(user.role);
    await ctx.editMessageText('❌ Cancelled. Back to **Main Menu**.\n\n' + title + '\n\nChoose an option:', {
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
      const title = getPanelTitle(ctx.state.user?.role);
      return ctx.editMessageText('❌ Cancelled. Back to **Main Menu**.\n\n' + title + '\n\nChoose an option:', { parse_mode: 'Markdown', ...menu });
    }
    const subs = await User.find({ telegramId: { $in: admin.subUsers || [] } })
      .select('telegramId firstName telegramUsername downloadCount')
      .lean()
      .exec();
    let text = `**Managing:** ${escMd(admin.firstName) || 'N/A'} (@${escMd(admin.telegramUsername) || 'N/A'})\n`;
    text += `ID: \`${admin.telegramId}\`\n`;
    text += `PDFs: ${admin.downloadCount || 0} | Users: ${subs.length}\n\n`;
    text += `**Sub‑Users:**\n`;
    subs.forEach((sub, i) => {
      text += `${i + 1}. **${displayName(sub)}** (@${escMd(sub.telegramUsername) || 'N/A'})\n`;
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

    // ----- Add Buyer Flow (Admin) -----
    if (state.step === 'AWAITING_BUYER_ID') {
      const telegramId = text.trim().replace(/\s/g, '');
      if (!/^\d+$/.test(telegramId)) {
        const menu = getMainMenu(ctx.state.user?.role);
        return ctx.reply('❌ Please enter a numeric Telegram ID (e.g. 5434080792).', { ...menu });
      }
      try {
        let user = await User.findOne({ telegramId });
        if (!user || user.role === 'unauthorized') {
          ctx.session = null;
          const menu = getMainMenu(ctx.state.user?.role);
          return ctx.reply('⚠️ This user hasn\'t started the bot yet. Ask them to send /start first.', { ...menu });
        }
        if (user.role === 'admin') {
          ctx.session = null;
          const menu = getMainMenu(ctx.state.user?.role);
          return ctx.reply('❌ This user is already an admin.', { ...menu });
        }
        if (user.addedBy) {
          await User.updateOne({ telegramId: user.addedBy }, { $pull: { subUsers: user.telegramId } });
        }
        const expiryDate = new Date();
        expiryDate.setDate(expiryDate.getDate() + 30);
        user.role = 'admin';
        user.addedBy = undefined;
        user.expiryDate = expiryDate;
        user.subUsers = [];
        await user.save();
        ctx.session = null;
        const menu = getMainMenu(ctx.state.user?.role);
        await ctx.reply(`✅ **${displayName(user)}** added as admin (30 days).`, {
          parse_mode: 'Markdown',
          ...menu
        });
        try {
          await bot.telegram.sendMessage(user.telegramId, "✅ Your access has been activated!", { parse_mode: 'Markdown' });
          await bot.telegram.sendMessage(user.telegramId, getPanelTitle('admin') + '\n\nChoose an option:', { parse_mode: 'Markdown', ...getMainMenu('admin') });
        } catch (e) {
          logger.warn('Could not send menu to new admin:', e.message);
        }
      } catch (error) {
        logger.error('Add buyer error:', error);
        ctx.session = null;
        ctx.reply('❌ Failed to add buyer. Please try again.', { ...getMainMenu(ctx.state.user?.role) });
      }
      return;
    }

    // ----- Add User Under Admin: step 1 – admin ID -----
    if (state.step === 'AWAITING_ADMIN_ID_FOR_USER') {
      const adminId = text.trim().replace(/\s/g, '');
      if (!/^\d+$/.test(adminId)) {
        return ctx.reply('❌ Please enter a numeric Telegram ID for the admin.');
      }
      const admin = await User.findOne({ telegramId: adminId, role: 'admin' });
      if (!admin) {
        return ctx.reply('❌ No admin found with that ID. They must already be an admin.');
      }
      ctx.session.step = 'AWAITING_USER_ID_UNDER_ADMIN';
      ctx.session.adminIdForUser = adminId;
      await ctx.reply(
        `✅ Admin found: ${escMd(admin.firstName) || escMd(admin.telegramUsername) || adminId}.\n\nNow send the **Telegram ID** of the **user** to add under this admin.`,
        { parse_mode: 'Markdown', ...Markup.inlineKeyboard([[Markup.button.callback('🔙 Cancel', 'main_menu')]]) }
      );
      return;
    }

    // ----- Add User Under Admin: step 2 – user ID, then confirm and save -----
    if (state.step === 'AWAITING_USER_ID_UNDER_ADMIN') {
      const userId = text.trim().replace(/\s/g, '');
      if (!/^\d+$/.test(userId)) {
        return ctx.reply('❌ Please enter a numeric Telegram ID for the user.');
      }
      const adminId = state.adminIdForUser;
      const admin = await User.findOne({ telegramId: adminId });
      if (!admin) {
        ctx.session = null;
        return ctx.reply('❌ Admin no longer found. Cancelled.', { ...getMainMenu(ctx.state.user?.role) });
      }
      const targetUser = await User.findOne({ telegramId: userId });
      if (!targetUser) {
        return ctx.reply('❌ That user has not started the bot yet. Ask them to send /start first.');
      }
      if (targetUser.role === 'admin') {
        return ctx.reply('❌ That ID belongs to an admin. Choose a regular user.');
      }
      if ((admin.subUsers || []).includes(userId)) {
        ctx.session = null;
        return ctx.reply('❌ This user is already under this admin.', { ...getMainMenu(ctx.state.user?.role) });
      }
      if ((admin.subUsers || []).length >= 9) {
        return ctx.reply('❌ This admin already has 9 users.');
      }
      if (targetUser.addedBy) {
        await User.updateOne({ telegramId: targetUser.addedBy }, { $pull: { subUsers: userId } });
      }
      admin.subUsers = admin.subUsers || [];
      admin.subUsers.push(userId);
      await admin.save();
      targetUser.role = 'user';
      targetUser.addedBy = adminId;
      targetUser.parentAdmin = adminId;
      targetUser.expiryDate = admin.expiryDate;
      await targetUser.save();
      ctx.session = null;
      await ctx.reply(`✅ **${escMd(targetUser.firstName) || targetUser.telegramId}** added under admin **${escMd(admin.firstName) || adminId}**.`, {
        parse_mode: 'Markdown',
        ...getMainMenu(ctx.state.user?.role)
      });
      try {
        await bot.telegram.sendMessage(userId, "✅ Your access has been activated!", { parse_mode: 'Markdown' });
        await bot.telegram.sendMessage(userId, getPanelTitle('user') + '\n\nChoose an option:', { parse_mode: 'Markdown', ...getMainMenu('user') });
      } catch (e) {
        logger.warn('Could not send activation to user:', e.message);
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
        if (!subUser) {
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

        buyer.subUsers = buyer.subUsers || [];
        buyer.subUsers.push(subUser.telegramId);
        await buyer.save();

        subUser.role = 'user';
        subUser.addedBy = buyer.telegramId;
        subUser.parentAdmin = buyer.telegramId;
        subUser.expiryDate = buyer.expiryDate;
        await subUser.save();

        await ctx.telegram.editMessageText(
          ctx.chat.id,
          statusMsg.message_id,
          null,
          `✅ User added successfully!\n\nThey can now use the bot.`
        );

        ctx.session = null;
        const user = ctx.state.user;
        const menu = getMainMenu(user.role);
        const title = getPanelTitle(user.role);
        await ctx.reply(title + '\n\nChoose an option:', {
          parse_mode: 'Markdown',
          ...menu
        });
        try {
          await bot.telegram.sendMessage(subUser.telegramId, "✅ Your access has been activated!", { parse_mode: 'Markdown' });
          await bot.telegram.sendMessage(subUser.telegramId, getPanelTitle('user') + '\n\nChoose an option:', { parse_mode: 'Markdown', ...getMainMenu('user') });
        } catch (e) {
          logger.warn('Could not send menu to new user:', e.message);
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
          await ctx.telegram.editMessageText(ctx.chat.id, status.message_id, null, "Enter the OTP sent to your phone:\n_Send /cancel to return to menu._", { parse_mode: 'Markdown' });
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
        let lastSyncError;
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
              const title = getPanelTitle(user.role);
              await ctx.reply(title + '\n\nChoose an option:', {
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
              userRole: ctx.state.user?.role || 'user',
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
              const title = getPanelTitle(user.role);
              await ctx.reply(title + '\n\nChoose an option:', { parse_mode: 'Markdown', ...menu });
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
            const title = getPanelTitle(user.role);
            await ctx.reply('✅ Your request has been queued. You will receive your PDF shortly.\n\n' + title + '\n\nChoose an option:', {
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
    await migrateRoles();

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
