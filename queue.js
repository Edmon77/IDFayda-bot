require('dotenv').config();
const Queue = require('bull');

if (!process.env.REDIS_URL) {
  console.error('❌ REDIS_URL is not set');
  process.exit(1);
}

console.log('🔍 REDIS_URL (first 30 chars):', process.env.REDIS_URL.substring(0, 30) + '...');

// Redis options for Bull (with IPv4 and TLS)
const redisOptions = {
  redis: {
    url: process.env.REDIS_URL,
    tls: process.env.REDIS_URL.startsWith('rediss://') ? {} : undefined,
    connectTimeout: 20000,
    family: 4, // force IPv4
    retryStrategy: (times) => {
      console.log(`🔄 Redis retry attempt #${times}`);
      if (times > 10) {
        console.error('❌ Redis: Max retries reached');
        return null;
      }
      return Math.min(times * 2000, 30000);
    }
  },
  defaultJobOptions: {
    attempts: 3,
    backoff: { type: 'exponential', delay: 5000 },
    removeOnComplete: true,
    removeOnFail: false
  }
};

const pdfQueue = new Queue('pdf generation', redisOptions);

pdfQueue.on('error', (err) => {
  console.error('❌ Bull queue error:', err.message);
});

pdfQueue.on('ready', () => {
  console.log('✅ Redis connection ready');
});

pdfQueue.on('reconnecting', () => {
  console.log('🔄 Redis reconnecting...');
});

pdfQueue.on('close', () => {
  console.log('🔴 Redis connection closed');
});

module.exports = pdfQueue;