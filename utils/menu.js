const { Markup } = require('telegraf');

const PER_PAGE = 10;

function getMainMenu(role) {
  if (role === 'superadmin') {
    return Markup.inlineKeyboard([
      [Markup.button.callback('1️⃣ Download PDF', 'download')],
      [Markup.button.callback('2️⃣ Manage Users', 'manage_users')],
      [Markup.button.callback('3️⃣ Dashboard', 'dashboard_super')]
    ]).resize();
  }
  if (role === 'admin') {
    return Markup.inlineKeyboard([
      [Markup.button.callback('1️⃣ Download PDF', 'download')],
      [Markup.button.callback('2️⃣ Manage Users', 'manage_users')],
      [Markup.button.callback('3️⃣ Dashboard', 'dashboard_buyer')]
    ]).resize();
  }
  // user
  return Markup.inlineKeyboard([
    [Markup.button.callback('1️⃣ Download PDF', 'download')]
  ]).resize();
}

function getPanelTitle(role) {
  if (role === 'superadmin') return '📌 SUPER ADMIN PANEL';
  if (role === 'admin') return '📌 ADMIN PANEL';
  return '📌 USER PANEL';
}

function paginate(items, page) {
  const total = items.length;
  const totalPages = Math.max(1, Math.ceil(total / PER_PAGE));
  const p = Math.max(1, Math.min(page, totalPages));
  const start = (p - 1) * PER_PAGE;
  const slice = items.slice(start, start + PER_PAGE);
  return { items: slice, page: p, totalPages, total };
}

module.exports = { getMainMenu, getPanelTitle, PER_PAGE, paginate };
