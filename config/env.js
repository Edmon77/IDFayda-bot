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
    const msg = [
      `Missing required environment variables: ${missing.join(', ')}.`,
      'Add them in your deployment platform:',
      '  Railway: Project → Variables tab',
      '  Render: Dashboard → Your Service → Environment',
      '  See ENV_SETUP.md for step-by-step instructions.'
    ].join('\n');
    logger.error(`Missing required environment variables: ${missing.join(', ')}`);
    throw new Error(msg);
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
