require('dotenv').config();
const { Telegraf, session } = require('telegraf');

const bot = new Telegraf(process.env.BOT_TOKEN, {
  handlerTimeout: 180000 // 180 seconds (3 minutes)
});
bot.use(session());

module.exports = bot;