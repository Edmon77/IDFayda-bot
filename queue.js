require('dotenv').config();
const Queue = require('bull');

const redisOptions = {
  maxRetriesPerRequest: null
};

// Detect Upstash TLS automatically
if (process.env.REDIS_URL && process.env.REDIS_URL.startsWith('rediss://')) {
  redisOptions.tls = {};
}

const pdfQueue = new Queue('pdf generation', process.env.REDIS_URL, {
  redis: redisOptions,

  defaultJobOptions: {
    attempts: 3,

    backoff: {
      type: 'exponential',
      delay: 5000
    },

    removeOnComplete: true,
    removeOnFail: false
  }
});

// Logging
pdfQueue.on('error', (err) => {
  console.error('❌ Redis error:', err.message);
});

pdfQueue.on('failed', (job, err) => {
  console.error('❌ Job failed:', job?.id, err.message);
});

pdfQueue.on('completed', (job) => {
  console.log('✅ Job completed:', job?.id);
});

module.exports = pdfQueue;