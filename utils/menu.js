const { Markup } = require('telegraf');

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

module.exports = { getMainMenu };
