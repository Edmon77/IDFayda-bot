require('dotenv').config();
const logger = require('../utils/logger');

const requiredEnvVars = [
  'BOT_TOKEN',
  'CAPTCHA_KEY',
  'MONGODB_URI',
  'SESSION_SECRET',
  'REDIS_URL',
  'WEBHOOK_DOMAIN'
];

function validateEnv() {
  const missing = [];
  
  for (const envVar of requiredEnvVars) {
    if (!process.env[envVar]) {
      missing.push(envVar);
    }
  }

  if (missing.length > 0) {
    logger.error(`Missing required environment variables: ${missing.join(', ')}`);
    throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
  }

  // Validate formats
  if (process.env.MONGODB_URI && !process.env.MONGODB_URI.startsWith('mongodb')) {
    throw new Error('MONGODB_URI must be a valid MongoDB connection string');
  }

  if (process.env.REDIS_URL && !process.env.REDIS_URL.startsWith('redis')) {
    throw new Error('REDIS_URL must be a valid Redis connection string');
  }

  logger.info('✅ Environment variables validated');
}

module.exports = { validateEnv };
