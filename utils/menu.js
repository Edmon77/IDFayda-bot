const { Markup } = require('telegraf');
const { t } = require('./i18n');

const PER_PAGE = 10;

// Persistent reply keyboard at bottom of chat
function getReplyKeyboard(role, lang = 'en') {
  const buttons = [
    [t('btn_start', lang), t('btn_manage', lang)],
    [t('btn_dashboard', lang), t('btn_language', lang)]
  ];

  if (role !== 'admin') {
    // user — only START, DASHBOARD, LANGUAGE
    return Markup.keyboard([
      [t('btn_start', lang), t('btn_dashboard', lang)],
      [t('btn_language', lang)]
    ]).resize();
  }

  return Markup.keyboard(buttons).resize();
}

// Inline keyboard for editMessageText calls (sub-menus, status updates)
function getMainMenu(role, lang = 'en') {
  if (role === 'admin') {
    return Markup.inlineKeyboard([
      [Markup.button.callback(t('btn_start', lang), 'download')],
      [Markup.button.callback(t('btn_manage', lang), 'manage_users')],
      [Markup.button.callback(t('btn_dashboard', lang), 'dashboard_buyer')],
      [Markup.button.callback(t('btn_language', lang), 'select_language')]
    ]).resize();
  }
  // user
  return Markup.inlineKeyboard([
    [Markup.button.callback(t('btn_start', lang), 'download')],
    [Markup.button.callback(t('btn_dashboard', lang), 'dashboard_user')],
    [Markup.button.callback(t('btn_language', lang), 'select_language')]
  ]).resize();
}

function getPanelTitle(role, lang = 'en') {
  const roleLabel = role === 'admin' ? t('role_admin', lang) : t('role_user', lang);
  return `${t('welcome', lang)}\n${roleLabel} ・ ${t('choose_option', lang)}`;
}

function paginate(items, page) {
  const total = items.length;
  const totalPages = Math.max(1, Math.ceil(total / PER_PAGE));
  const p = Math.max(1, Math.min(page, totalPages));
  const start = (p - 1) * PER_PAGE;
  const slice = items.slice(start, start + PER_PAGE);
  return { items: slice, page: p, totalPages, total };
}

module.exports = { getReplyKeyboard, getMainMenu, getPanelTitle, PER_PAGE, paginate };
