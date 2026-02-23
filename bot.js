require('dotenv').config();
const { Telegraf } = require('telegraf');
const IORedis = require('ioredis');
const logger = require('./utils/logger');

const bot = new Telegraf(process.env.BOT_TOKEN, {
  handlerTimeout: 180000 // 180 seconds (3 minutes)
});

// Redis-backed session so download/OTP flows survive restarts
const redisSession = new IORedis(process.env.REDIS_URL, {
  maxRetriesPerRequest: null,
  enableReadyCheck: false,
  retryStrategy: (times) => Math.min(times * 100, 3000)
});

const SESSION_TTL = 3600; // 1 hour (covers longest possible download flow)

function redisSessionMiddleware() {
  return async (ctx, next) => {
    const key = ctx.from ? `session:${ctx.from.id}` : null;
    if (!key) return next();

    // Load session from Redis
    try {
      const data = await redisSession.get(key);
      ctx.session = data ? JSON.parse(data) : {};
    } catch (e) {
      ctx.session = {};
    }

    // Save original to detect changes
    const before = JSON.stringify(ctx.session);

    await next();

    // Save session back to Redis if changed
    try {
      const after = JSON.stringify(ctx.session);
      if (ctx.session === null || (typeof ctx.session === 'object' && Object.keys(ctx.session).length === 0)) {
        await redisSession.del(key);
      } else if (after !== before) {
        await redisSession.set(key, after, 'EX', SESSION_TTL);
      }
    } catch (e) {
      logger.warn('Redis session save/delete failed:', e.message);
    }
  };
}

bot.use(redisSessionMiddleware());

module.exports = bot;