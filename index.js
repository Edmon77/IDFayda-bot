// Environment validation and configuration
const { validateEnv } = require('./config/env');
validateEnv();

const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const axios = require('axios');
const Captcha = require('2captcha');
const { Markup } = require('telegraf');

const bot = require('./bot');
const User = require('./models/User');
const auth = require('./middleware/auth');
const logger = require('./utils/logger');
const { connectDB, disconnectDB } = require('./config/database');
const { apiLimiter, checkUserRateLimit } = require('./utils/rateLimiter');
const { validateFaydaId, validateOTP } = require('./utils/validators');
const pdfQueue = require('./queue');

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

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// Apply rate limiting to API routes
app.use('/api', apiLimiter);

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

// ---------- Helper: Generate main menu based on role ----------
function getMainMenu(role) {
  if (role === 'admin') {
    return Markup.inlineKeyboard([
      [Markup.button.callback('📥 Download ID', 'download')],
      [Markup.button.callback('📊 Dashboard', 'dashboard_super')],
      [Markup.button.callback('👥 Manage Users', 'manage_users')]
    ]).resize();
  } else if (role === 'buyer') {
    return Markup.inlineKeyboard([
      [Markup.button.callback('📥 Download ID', 'download')],
      [Markup.button.callback('📊 Dashboard', 'dashboard_buyer')],
      [Markup.button.callback('👥 Manage Sub‑Users', 'manage_subs')]
    ]).resize();
  } else {
    return Markup.inlineKeyboard([
      [Markup.button.callback('📥 Download ID', 'download')]
    ]).resize();
  }
}

// ---------- Error Handler Middleware ----------
bot.catch((err, ctx) => {
  logger.error('Bot error:', {
    error: err.message,
    stack: err.stack,
    update: ctx.update
  });
  
  try {
    ctx.reply('❌ An error occurred. Please try again later or contact support.');
  } catch (e) {
    logger.error('Failed to send error message:', e);
  }
});

// ---------- Authorization Middleware with Rate Limiting ----------
bot.use(async (ctx, next) => {
  try {
    const telegramId = ctx.from.id.toString();
    
    // Check user rate limit
    const rateLimit = checkUserRateLimit(telegramId, 30, 60000); // 30 requests per minute
    if (!rateLimit.allowed) {
      const waitTime = Math.ceil((rateLimit.resetTime - Date.now()) / 1000);
      return ctx.reply(`⏳ Too many requests. Please wait ${waitTime} seconds.`);
    }
    
    const user = await auth.getUser(telegramId);
    
    if (!user) {
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

// ---------- Download Action – Start Download Flow ----------
bot.action('download', async (ctx) => {
  try {
    await ctx.answerCbQuery();
    ctx.session = { step: 'ID' };
    await ctx.editMessageText("🏁 Fayda ID Downloader\nPlease enter your **16-digit Fayda Number**:", {
      parse_mode: 'Markdown'
    });
  } catch (error) {
    logger.error('Download action error:', error);
    ctx.reply('❌ Failed to start download. Please try again.');
  }
});

// ---------- Back to Main Menu ----------
bot.action('main_menu', async (ctx) => {
  try {
    await ctx.answerCbQuery();
    const user = ctx.state.user;
    const menu = getMainMenu(user.role);
    await ctx.editMessageText('🏠 **Main Menu**\nChoose an option:', {
      parse_mode: 'Markdown',
      ...menu
    });
  } catch (error) {
    logger.error('Main menu action error:', error);
  }
});

// ---------- Super Admin: Dashboard (Optimized) ----------
bot.action('dashboard_super', async (ctx) => {
  try {
    await ctx.answerCbQuery();
    
    // Optimized query: get buyers with populated sub-users in one query
    const buyers = await User.find({ role: 'buyer' })
      .sort({ createdAt: -1 })
      .lean()
      .exec();
    
    // Get all sub-user IDs
    const allSubIds = buyers.flatMap(b => b.subUsers || []);
    
    // Fetch all sub-users in one query
    const allSubs = await User.find({ telegramId: { $in: allSubIds } })
      .select('telegramId downloadCount')
      .lean()
      .exec();
    
    // Create a map for quick lookup
    const subMap = new Map(allSubs.map(s => [s.telegramId, s.downloadCount || 0]));
    
    let text = '📊 **Super Admin Dashboard**\n\n';
    for (const buyer of buyers) {
      const subIds = buyer.subUsers || [];
      const subDownloads = subIds.reduce((sum, id) => sum + (subMap.get(id) || 0), 0);
      const total = (buyer.downloadCount || 0) + subDownloads;
      text += `**${buyer.firstName || 'N/A'}** (@${buyer.telegramUsername || 'N/A'})\n`;
      text += `ID: \`${buyer.telegramId}\`\n`;
      text += `PDFs: ${buyer.downloadCount || 0} | Users: ${subIds.length} | Users PDFs: ${subDownloads} | Total: ${total}\n\n`;
    }
    
    const keyboard = Markup.inlineKeyboard([
      [Markup.button.callback('🔙 Main Menu', 'main_menu')]
    ]);
    await ctx.editMessageText(text, { parse_mode: 'Markdown', ...keyboard });
  } catch (error) {
    logger.error('Dashboard super error:', error);
    ctx.reply('❌ Failed to load dashboard. Please try again.');
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

    let text = `📊 **Your Dashboard**\n\n`;
    text += `**${buyer.firstName || 'N/A'}** (@${buyer.telegramUsername || 'N/A'})\n`;
    text += `ID: \`${buyer.telegramId}\`\n\n`;
    text += `**Work Summary:**\n`;
    text += `Your Own PDFs: ${buyerOwn}\n`;
    text += `Your Users: ${subs.length}\n`;
    text += `Users' PDFs: ${subDownloads}\n`;
    text += `Total PDFs: ${total}\n\n`;
    text += `**Your Users (Page 1/1):**\n`;
    subs.forEach((sub, i) => {
      text += `${i+1}. **${sub.firstName || sub.telegramUsername || sub.telegramId}** (@${sub.telegramUsername || 'N/A'})\n`;
      text += `   ID: \`${sub.telegramId}\` | PDFs: ${sub.downloadCount || 0}\n`;
    });

    const keyboard = Markup.inlineKeyboard([
      [Markup.button.callback('🔙 Main Menu', 'main_menu')]
    ]);
    await ctx.editMessageText(text, { parse_mode: 'Markdown', ...keyboard });
  } catch (error) {
    logger.error('Dashboard buyer error:', error);
    ctx.reply('❌ Failed to load dashboard. Please try again.');
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
    
    let text = '👥 **Manage Users**\n\nSelect a user to manage:\n\n';
    const buttons = [];
    for (const buyer of buyers) {
      const subsCount = (buyer.subUsers || []).length;
      const label = `${buyer.firstName || 'N/A'} (@${buyer.telegramUsername || 'N/A'}) – ${subsCount} users`;
      buttons.push([Markup.button.callback(label, `select_admin_${buyer.telegramId}`)]);
    }
    buttons.push([Markup.button.callback('🔙 Main Menu', 'main_menu')]);
    await ctx.editMessageText(text, {
      parse_mode: 'Markdown',
      reply_markup: { inline_keyboard: buttons }
    });
  } catch (error) {
    logger.error('Manage users error:', error);
    ctx.reply('❌ Failed to load users. Please try again.');
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
      [Markup.button.callback('🔙 Back to Users', 'manage_users')],
      [Markup.button.callback('🏠 Main Menu', 'main_menu')]
    ];
    await ctx.editMessageText(text, {
      parse_mode: 'Markdown',
      reply_markup: { inline_keyboard: buttons }
    });
  } catch (error) {
    logger.error('Select admin error:', error);
    ctx.reply('❌ Failed to load user details. Please try again.');
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
    await ctx.editMessageText(
      '📝 **Add a Sub‑User**\n\nPlease send me the Telegram **ID**, **Username** (with @), or **Phone Number** (with +) of the person you want to add.',
      { parse_mode: 'Markdown' }
    );
  } catch (error) {
    logger.error('Add sub admin error:', error);
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
    ctx.reply('❌ Failed to load sub-users. Please try again.');
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
    ctx.reply('❌ Failed to remove sub-user. Please try again.');
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
    ctx.reply('❌ Failed to load sub-users. Please try again.');
  }
});

// ---------- Buyer: Add Sub‑User (self) ----------
bot.action('add_sub_self', async (ctx) => {
  try {
    await ctx.answerCbQuery();
    ctx.session = { ...ctx.session, step: 'AWAITING_SUB_IDENTIFIER' };
    await ctx.editMessageText(
      '📝 **Add a Sub‑User**\n\nPlease send me the Telegram **ID**, **Username** (with @), or **Phone Number** (with +) of the person you want to add.',
      { parse_mode: 'Markdown' }
    );
  } catch (error) {
    logger.error('Add sub self error:', error);
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
    ctx.reply('❌ Failed to remove sub-user. Please try again.');
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

    // ----- Add Sub‑User Flow -----
    if (state.step === 'AWAITING_SUB_IDENTIFIER') {
      const buyerId = state.adminForAdd || ctx.from.id.toString();
      const buyer = await User.findOne({ telegramId: buyerId });
      
      if (!buyer) {
        return ctx.reply('❌ Buyer not found. Please try again.');
      }

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
          return ctx.reply('❌ This buyer already has 9 employees.');
        }
        if ((buyer.subUsers || []).includes(subUser.telegramId)) {
          return ctx.reply('❌ This user is already an employee of this buyer.');
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
      } catch (error) {
        logger.error('Add sub error:', error);
        ctx.reply('❌ Failed to add employee. Please try again.');
      }
      return;
    }

    // ----- Download Flow: ID Step -----
    if (state.step === 'ID') {
      const validation = validateFaydaId(text);
      if (!validation.valid) {
        return ctx.reply(`❌ ${validation.error}. Please enter exactly **16 digits**.`, { parse_mode: 'Markdown' });
      }

      const status = await ctx.reply("⏳ Solving Captcha...");
      
      try {
        const result = await solver.recaptcha(SITE_KEY, 'https://resident.fayda.et/');
        const res = await axios.post(`${API_BASE}/verify`, {
          idNumber: validation.value,
          verificationMethod: "FCN",
          captchaValue: result.data
        }, { 
          headers: HEADERS,
          timeout: 30000
        });

        ctx.session.tempJwt = res.data.token;
        ctx.session.id = validation.value;
        ctx.session.step = 'OTP';

        await ctx.telegram.editMessageText(ctx.chat.id, status.message_id, null, "✅ Captcha Solved!\n\nEnter the OTP sent to your phone:");
      } catch (e) {
        const errMsg = e.response?.data?.message || e.message || "Verification failed.";
        logger.error("ID verification error:", { error: errMsg, stack: e.stack });
        ctx.reply(`❌ Error: ${errMsg}\nTry /start again.`);
        ctx.session = null;
      }
      return;
    }

    // ----- Download Flow: OTP Step -----
    if (state.step === 'OTP') {
      const validation = validateOTP(text);
      if (!validation.valid) {
        return ctx.reply(`❌ ${validation.error}. Please enter a valid OTP.`);
      }

      const status = await ctx.reply("⏳ Verifying OTP and generating document...");
      const authHeader = { ...HEADERS, 'Authorization': `Bearer ${state.tempJwt}` };

      try {
        const otpResponse = await axios.post(`${API_BASE}/validateOtp`, {
          otp: validation.value,
          uniqueId: state.id,
          verificationMethod: "FCN"
        }, { 
          headers: authHeader,
          timeout: 30000
        });

        const { signature, uin, fullName } = otpResponse.data;
        if (!signature || !uin) {
          throw new Error('Missing signature or uin in OTP response');
        }

        await ctx.telegram.editMessageText(ctx.chat.id, status.message_id, null, "⏳ OTP Verified. Queueing PDF generation...");

        // Add job to queue for async processing
        await pdfQueue.add({
          chatId: ctx.chat.id,
          userId: ctx.from.id.toString(),
          authHeader,
          pdfPayload: { uin, signature },
          fullName
        }, {
          priority: 1,
          timeout: 60000 // 60 second timeout for job
        });

        ctx.session = null;

        // Show main menu
        const user = ctx.state.user;
        const menu = getMainMenu(user.role);
        await ctx.reply('✅ Your request has been queued. You will receive your PDF shortly.\n\n🏠 **Main Menu**\nChoose an option:', {
          parse_mode: 'Markdown',
          ...menu
        });
      } catch (e) {
        logger.error("OTP/PDF Error:", {
          error: e.message,
          stack: e.stack,
          response: e.response?.data
        });
        ctx.reply(`❌ Failed: ${e.response?.data?.message || e.message}`);
        ctx.session = null;
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
    await bot.telegram.setWebhook(`${process.env.WEBHOOK_DOMAIN}${webhookPath}`);
    app.use(bot.webhookCallback(webhookPath));

    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
      logger.info(`🚀 Server running on port ${PORT}`);
      logger.info(`🤖 Webhook active at ${process.env.WEBHOOK_DOMAIN}${webhookPath}`);
    });
  } catch (err) {
    logger.error("❌ Failed to start server:", err);
    process.exit(1);
  }
}

startServer();
