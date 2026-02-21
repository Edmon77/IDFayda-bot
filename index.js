require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const axios = require('axios');
const Captcha = require('2captcha');
const mongoose = require('mongoose');
const { Markup } = require('telegraf');

const bot = require('./bot');
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
  cookie: { maxAge: 1000 * 60 * 60 * 24 }
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

// ---------- Helper: Generate main menu based on role ----------
function getMainMenu(role) {
  if (role === 'admin') { // Super admin
    return Markup.inlineKeyboard([
      [Markup.button.callback('📥 Download ID', 'download')],
      [Markup.button.callback('📊 Dashboard', 'dashboard_super')],
      [Markup.button.callback('👥 Manage Users', 'manage_users')]
    ]).resize();
  } else if (role === 'buyer') { // Admin (buyer)
    return Markup.inlineKeyboard([
      [Markup.button.callback('📥 Download ID', 'download')],
      [Markup.button.callback('📊 Dashboard', 'dashboard_buyer')],
      [Markup.button.callback('👥 Manage Sub‑Users', 'manage_subs')]
    ]).resize();
  } else { // Sub‑user
    return Markup.inlineKeyboard([
      [Markup.button.callback('📥 Download ID', 'download')]
    ]).resize();
  }
}

// ---------- Authorization Middleware ----------
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

// ---------- Start Command – Show Main Menu ----------
bot.start(async (ctx) => {
  const user = ctx.state.user;
  const menu = getMainMenu(user.role);
  await ctx.reply('🏠 **Main Menu**\nChoose an option:', {
    parse_mode: 'Markdown',
    ...menu
  });
});

// ---------- Download Action – Start Download Flow ----------
bot.action('download', async (ctx) => {
  await ctx.answerCbQuery();
  ctx.session = { step: 'ID' };
  await ctx.editMessageText("🏁 Fayda ID Downloader\nPlease enter your **16-digit Fayda Number**:", {
    parse_mode: 'Markdown'
  });
});

// ---------- Back to Main Menu ----------
bot.action('main_menu', async (ctx) => {
  await ctx.answerCbQuery();
  const user = ctx.state.user;
  const menu = getMainMenu(user.role);
  await ctx.editMessageText('🏠 **Main Menu**\nChoose an option:', {
    parse_mode: 'Markdown',
    ...menu
  });
});

// ---------- Super Admin: Dashboard ----------
bot.action('dashboard_super', async (ctx) => {
  await ctx.answerCbQuery();
  const buyers = await User.find({ role: 'buyer' }).sort({ createdAt: -1 });
  let text = '📊 **Super Admin Dashboard**\n\n';
  for (const buyer of buyers) {
    const subs = await User.find({ telegramId: { $in: buyer.subUsers || [] } });
    const subDownloads = subs.reduce((sum, sub) => sum + (sub.downloadCount || 0), 0);
    const total = (buyer.downloadCount || 0) + subDownloads;
    text += `**${buyer.firstName || 'N/A'}** (@${buyer.telegramUsername || 'N/A'})\n`;
    text += `ID: \`${buyer.telegramId}\`\n`;
    text += `PDFs: ${buyer.downloadCount || 0} | Users: ${subs.length} | Users PDFs: ${subDownloads} | Total: ${total}\n\n`;
  }
  const keyboard = Markup.inlineKeyboard([
    [Markup.button.callback('🔙 Main Menu', 'main_menu')]
  ]);
  await ctx.editMessageText(text, { parse_mode: 'Markdown', ...keyboard });
});

// ---------- Buyer Dashboard ----------
bot.action('dashboard_buyer', async (ctx) => {
  await ctx.answerCbQuery();
  const buyer = ctx.state.user;
  const subs = await User.find({ telegramId: { $in: buyer.subUsers || [] } });
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
});

// ---------- Super Admin: Manage Users (list all buyers) ----------
bot.action('manage_users', async (ctx) => {
  await ctx.answerCbQuery();
  const buyers = await User.find({ role: 'buyer' }).sort({ createdAt: -1 });
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
});

// ---------- Super Admin: Manage a specific buyer ----------
bot.action(/select_admin_(\d+)/, async (ctx) => {
  await ctx.answerCbQuery();
  const adminId = ctx.match[1];
  const admin = await User.findOne({ telegramId: adminId });
  if (!admin) {
    return ctx.editMessageText('❌ User not found.', Markup.inlineKeyboard([
      [Markup.button.callback('🔙 Back', 'manage_users')]
    ]));
  }

  const subs = await User.find({ telegramId: { $in: admin.subUsers || [] } });
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
});

// ---------- Super Admin: Add Sub‑User to a buyer ----------
bot.action(/add_sub_admin_(\d+)/, async (ctx) => {
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
});

// ---------- Super Admin: Remove Sub‑User selection (list subs) ----------
bot.action(/remove_sub_admin_(\d+)/, async (ctx) => {
  await ctx.answerCbQuery();
  const adminId = ctx.match[1];
  const admin = await User.findOne({ telegramId: adminId });
  const subs = await User.find({ telegramId: { $in: admin.subUsers || [] } });
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
});

// ---------- Super Admin: Execute removal of a sub‑user ----------
bot.action(/remove_sub_(\d+)_(\d+)/, async (ctx) => {
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
});

// ---------- Buyer: Manage Own Sub‑Users ----------
bot.action('manage_subs', async (ctx) => {
  await ctx.answerCbQuery();
  const buyer = ctx.state.user;
  const subs = await User.find({ telegramId: { $in: buyer.subUsers || [] } });

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
    // Add remove buttons for each sub
    subs.forEach(sub => {
      buttons.push([Markup.button.callback(`❌ Remove ${sub.firstName || sub.telegramUsername || sub.telegramId}`, `remove_my_sub_${sub.telegramId}`)]);
    });
  }
  buttons.push([Markup.button.callback('🔙 Main Menu', 'main_menu')]);

  await ctx.editMessageText(text, {
    parse_mode: 'Markdown',
    reply_markup: { inline_keyboard: buttons }
  });
});

// ---------- Buyer: Add Sub‑User (self) ----------
bot.action('add_sub_self', async (ctx) => {
  await ctx.answerCbQuery();
  ctx.session = { ...ctx.session, step: 'AWAITING_SUB_IDENTIFIER' }; // No adminForAdd needed
  await ctx.editMessageText(
    '📝 **Add a Sub‑User**\n\nPlease send me the Telegram **ID**, **Username** (with @), or **Phone Number** (with +) of the person you want to add.',
    { parse_mode: 'Markdown' }
  );
});

// ---------- Buyer: Remove Own Sub‑User ----------
bot.action(/remove_my_sub_(\d+)/, async (ctx) => {
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
});

// ---------- Original Commands (kept for compatibility, but can be removed) ----------
// ... (existing commands like /mysubs, /addsub, /removesub are still here but may be unused)
// We'll keep them as fallback, but users will use the menu.

// ---------- Text Handler – Download Flow & Add Sub‑User ----------
bot.on('text', async (ctx) => {
  const state = ctx.session;
  if (!state) {
    // No active session, maybe show menu? But we'll ignore.
    return;
  }

  const text = ctx.message.text.trim();

  // ----- Add Sub‑User (either from super admin or buyer) -----
  if (state.step === 'AWAITING_SUB_IDENTIFIER') {
    const buyerId = state.adminForAdd || ctx.from.id.toString(); // if adminForAdd exists, it's super admin adding to another
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

      // Clear session and show appropriate menu
      ctx.session = null;
      const user = ctx.state.user; // current user (who added)
      const menu = getMainMenu(user.role);
      await ctx.reply('🏠 **Main Menu**\nChoose an option:', {
        parse_mode: 'Markdown',
        ...menu
      });
    } catch (error) {
      console.error('Add sub error:', error);
      ctx.reply('❌ Failed to add employee. Please try again.');
    }
    return;
  }

  // ----- Download Flow Steps -----
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

      await ctx.telegram.editMessageText(ctx.chat.id, status.message_id, null, "⏳ OTP Verified. Fetching ID file...");

      const pdfPayload = { uin, signature };
      const pdfResponse = await axios.post(`${API_BASE}/printableCredentialRoute`, pdfPayload, {
        headers: authHeader,
        responseType: 'text'
      });

      let base64Pdf = pdfResponse.data.trim();
      if (base64Pdf.startsWith('{') && base64Pdf.includes('"pdf"')) {
        try {
          const parsed = JSON.parse(base64Pdf);
          if (parsed.pdf) base64Pdf = parsed.pdf.trim();
        } catch (e) {}
      }

      if (!base64Pdf.startsWith('JVBERi0')) {
        console.error('Base64 does not start with PDF header!');
      }

      const pdfBuffer = Buffer.from(base64Pdf, 'base64');
      const safeName = (fullName?.eng || 'Fayda_Card').replace(/[^a-zA-Z0-9]/g, '_');
      const filename = `${safeName}.pdf`;

      await ctx.replyWithDocument({
        source: pdfBuffer,
        filename: filename
      }, { caption: "✨ Your Digital ID is ready!" });

      // Increment download count
      await User.updateOne(
        { telegramId: ctx.from.id.toString() },
        { $inc: { downloadCount: 1 }, $set: { lastDownload: new Date() } }
      );

      ctx.session = null;

      // Show main menu again
      const user = ctx.state.user;
      const menu = getMainMenu(user.role);
      await ctx.reply('🏠 **Main Menu**\nChoose an option:', {
        parse_mode: 'Markdown',
        ...menu
      });
    } catch (e) {
      console.error("OTP/PDF Error:", e.response?.data || e.message);
      ctx.reply(`❌ Failed: ${e.message}`);
      ctx.session = null;
    }
    return;
  }
});

// ---------- Admin Dashboard Routes (unchanged) ----------
// ... (keep all your existing Express routes for web dashboard)
// They are already in your code, so we won't repeat them here.

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
    });
  } catch (err) {
    console.error("❌ Failed to start server:", err);
    process.exit(1);
  }
}

startServer();