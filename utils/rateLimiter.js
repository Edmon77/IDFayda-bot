const RateLimit = require('express-rate-limit');
const Redis = require('ioredis');

// Create Redis client for rate limiting
const redisClient = new Redis(process.env.REDIS_URL, {
  maxRetriesPerRequest: null,
  enableReadyCheck: false,
  retryStrategy: (times) => {
    const delay = Math.min(times * 50, 2000);
    return delay;
  }
});

// Simple Redis store for rate limiting
class RedisStore {
  constructor(client, prefix = 'rl:') {
    this.client = client;
    this.prefix = prefix;
  }

  async increment(key, cb) {
    const redisKey = this.prefix + key;
    const count = await this.client.incr(redisKey);
    if (count === 1) {
      await this.client.expire(redisKey, Math.ceil((cb.windowMs || 60000) / 1000));
    }
    return count;
  }

  async decrement(key) {
    const redisKey = this.prefix + key;
    await this.client.decr(redisKey);
  }

  async resetKey(key) {
    const redisKey = this.prefix + key;
    await this.client.del(redisKey);
  }
}

// Rate limiter for API endpoints
const apiLimiter = RateLimit({
  store: new RedisStore(redisClient, 'rl:api:'),
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => {
    // Skip rate limiting for health checks
    return req.path === '/health';
  }
});

// Stricter rate limiter for download endpoint
const downloadLimiter = RateLimit({
  store: new RedisStore(redisClient, 'rl:download:'),
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // Limit to 10 downloads per hour per IP
  message: 'Too many download requests. Please try again later.',
  standardHeaders: true,
  legacyHeaders: false
});

// Telegram user rate limiter (using Redis for distributed rate limiting)
async function checkUserRateLimit(telegramId, maxRequests = 30, windowMs = 60000) {
  const key = `rl:user:${telegramId}`;
  const now = Date.now();
  
  try {
    const count = await redisClient.incr(key);
    if (count === 1) {
      await redisClient.expire(key, Math.ceil(windowMs / 1000));
    }
    
    const ttl = await redisClient.ttl(key);
    // TTL can be -1 (no expiry) or -2 (key doesn't exist), handle these cases
    const validTtl = ttl > 0 ? ttl : Math.ceil(windowMs / 1000);
    const resetTime = now + (validTtl * 1000);
    
    if (count > maxRequests) {
      return { allowed: false, remaining: 0, resetTime };
    }
    
    return { allowed: true, remaining: Math.max(0, maxRequests - count), resetTime };
  } catch (error) {
    // If Redis fails, allow the request (fail open)
    console.error('Rate limit check error:', error);
    return { allowed: true, remaining: maxRequests, resetTime: now + windowMs };
  }
}

module.exports = {
  apiLimiter,
  downloadLimiter,
  checkUserRateLimit,
  redisClient
};
