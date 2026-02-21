const Queue = require('bull');
const axios = require('axios');
const bot = require('./bot');
const User = require('./models/User');
const logger = require('./utils/logger');
const { sanitizeFilename } = require('./utils/validators');

const API_BASE = "https://api-resident.fayda.et";

// Create Redis connection for Bull queue
const Redis = require('ioredis');
const redis = new Redis(process.env.REDIS_URL, {
  maxRetriesPerRequest: null,
  enableReadyCheck: false
});

// Bull queue configuration - use Redis URL directly
const pdfQueue = new Queue('pdf generation', process.env.REDIS_URL, {
  defaultJobOptions: {
    attempts: 3,
    backoff: {
      type: 'exponential',
      delay: 5000
    },
    removeOnComplete: {
      age: 3600, // Keep completed jobs for 1 hour
      count: 1000 // Keep max 1000 completed jobs
    },
    removeOnFail: {
      age: 24 * 3600 // Keep failed jobs for 24 hours
    }
  },
  settings: {
    maxStalledCount: 1,
    retryProcessDelay: 5000
  }
});

// Queue event handlers
pdfQueue.on('completed', (job) => {
  logger.info(`PDF job completed for user ${job.data.userId}`);
});

pdfQueue.on('failed', (job, err) => {
  logger.error(`PDF job failed for user ${job.data.userId}:`, err.message);
});

pdfQueue.on('stalled', (job) => {
  logger.warn(`PDF job stalled for user ${job.data.userId}`);
});

// Worker: processes jobs concurrently (10 concurrent jobs for better throughput)
pdfQueue.process(10, async (job) => {
  const { chatId, userId, authHeader, pdfPayload, fullName } = job.data;

  try {
    // 1. Fetch PDF from Fayda with timeout
    const pdfResponse = await axios.post(`${API_BASE}/printableCredentialRoute`, pdfPayload, {
      headers: authHeader,
      responseType: 'text',
      timeout: 30000 // 30 second timeout
    });

    let base64Pdf = pdfResponse.data.trim();
    // If response is JSON with a pdf field, extract it
    if (base64Pdf.startsWith('{') && base64Pdf.includes('"pdf"')) {
      try {
        const parsed = JSON.parse(base64Pdf);
        if (parsed.pdf) base64Pdf = parsed.pdf.trim();
      } catch (e) {
        logger.warn('Failed to parse JSON response, using raw data');
      }
    }

    // Validate base64 header
    if (!base64Pdf.startsWith('JVBERi0')) {
      throw new Error('Invalid PDF header - response is not a valid PDF');
    }

    // 2. Convert to buffer
    const pdfBuffer = Buffer.from(base64Pdf, 'base64');

    // 3. Generate filename from fullName (sanitize)
    const filename = `${sanitizeFilename(fullName?.eng)}.pdf`;

    // 4. Send PDF via Telegram
    await bot.telegram.sendDocument(chatId, {
      source: pdfBuffer,
      filename: filename
    }, { caption: "✨ Your Digital ID is ready!" });

    // 5. Increment download count for the user
    await User.updateOne(
      { telegramId: userId },
      { $inc: { downloadCount: 1 }, $set: { lastDownload: new Date() } }
    );

    logger.info(`PDF sent successfully to user ${userId}`);
    return { success: true };
  } catch (error) {
    logger.error(`Job failed for user ${userId}:`, {
      message: error.message,
      stack: error.stack,
      response: error.response?.data
    });
    // Rethrow so Bull retries
    throw error;
  }
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  logger.info('SIGTERM received, closing queue...');
  await pdfQueue.close();
  await redis.quit();
});

module.exports = pdfQueue;