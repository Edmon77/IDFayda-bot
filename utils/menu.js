const { Markup } = require('telegraf');

const PER_PAGE = 10;

// Reply keyboard button labels (used for text matching in the text handler)
const BTN = {
  START: '🚀 START',
  MANAGE: '👥 Manage Users',
  DASHBOARD: '📊 Dashboard',
  CANCEL: '❌ Cancel'
};

// Persistent reply keyboard at bottom of chat
function getReplyKeyboard(role) {
  if (role === 'admin') {
    return Markup.keyboard([
      [BTN.START, BTN.MANAGE],
      [BTN.DASHBOARD, BTN.CANCEL]
    ]).resize();
  }
  // user
  return Markup.keyboard([
    [BTN.START, BTN.CANCEL]
  ]).resize();
}

// Inline keyboard for editMessageText calls (sub-menus, status updates)
function getMainMenu(role) {
  if (role === 'admin') {
    return Markup.inlineKeyboard([
      [Markup.button.callback('🚀 START', 'download')],
      [Markup.button.callback('👥 Manage Users', 'manage_users')],
      [Markup.button.callback('📊 Dashboard', 'dashboard_buyer')]
    ]).resize();
  }
  // user
  return Markup.inlineKeyboard([
    [Markup.button.callback('🚀 START', 'download')]
  ]).resize();
}

function getPanelTitle(role) {
  const roleLabel = role === 'admin' ? '_Admin_' : '_User_';
  return `📌 **WELCOME TO FAYDA BOT**\n${roleLabel} ・ Choose an option:`;
}

function paginate(items, page) {
  const total = items.length;
  const totalPages = Math.max(1, Math.ceil(total / PER_PAGE));
  const p = Math.max(1, Math.min(page, totalPages));
  const start = (p - 1) * PER_PAGE;
  const slice = items.slice(start, start + PER_PAGE);
  return { items: slice, page: p, totalPages, total };
}

module.exports = { BTN, getReplyKeyboard, getMainMenu, getPanelTitle, PER_PAGE, paginate };
