require('dotenv').config();
const Queue = require('bull');

const pdfQueue = new Queue('pdf generation', process.env.REDIS_URL, {
  redis: {
    maxRetriesPerRequest: null
  },
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

pdfQueue.on('error', (err) => {
  console.error('❌ Redis error:', err);
});

pdfQueue.on('failed', (job, err) => {
  console.error(`❌ Job ${job.id} failed:`, err.message);
});

module.exports = pdfQueue;