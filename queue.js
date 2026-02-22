const Queue = require('bull');
const bot = require('./bot');
const User = require('./models/User');
const logger = require('./utils/logger');
const { safeResponseForLog } = require('./utils/logger');
const { sanitizeFilename } = require('./utils/validators');
const { parsePdfResponse } = require('./utils/pdfHelper');
const { getMainMenu } = require('./utils/menu');
const fayda = require('./utils/faydaClient');
const PDF_FETCH_ATTEMPTS = 3;
const PDF_FETCH_RETRY_DELAY_MS = 2000;
const PDF_QUEUE_CONCURRENCY = Math.min(Math.max(parseInt(process.env.PDF_QUEUE_CONCURRENCY, 10) || 10, 1), 50);

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

pdfQueue.on('failed', async (job, err) => {
  logger.error(`PDF job failed for user ${job.data.userId}:`, err.message);
  // Notify user so they know to try again
  try {
    const chatId = job?.data?.chatId;
    if (chatId) {
      await bot.telegram.sendMessage(
        chatId,
        '❌ We couldn\'t generate your PDF after several attempts. Please try again from the start (/start).'
      );
    }
  } catch (notifyErr) {
    logger.error('Failed to notify user of PDF job failure:', notifyErr.message);
  }
});

pdfQueue.on('stalled', (job) => {
  logger.warn(`PDF job stalled for user ${job.data.userId}`);
});

logger.info(`PDF queue worker started with concurrency ${PDF_QUEUE_CONCURRENCY}`);

// Worker: processes jobs concurrently (configurable for 100–300 users; default 10)
pdfQueue.process(PDF_QUEUE_CONCURRENCY, async (job) => {
  const { chatId, userId, userRole, authHeader, pdfPayload, fullName } = job.data;

  try {
    // 1. Fetch PDF from Fayda with retries for transient failures
    let pdfResponse;
    let lastError;
    for (let attempt = 1; attempt <= PDF_FETCH_ATTEMPTS; attempt++) {
      try {
        pdfResponse = await fayda.api.post('/printableCredentialRoute', pdfPayload, {
          headers: authHeader,
          responseType: 'text',
          timeout: 30000
        });
        lastError = null;
        break;
      } catch (err) {
        lastError = err;
        const isRetryable = !err.response || (err.response.status >= 500 && err.response.status < 600) || err.code === 'ECONNABORTED' || err.code === 'ETIMEDOUT' || err.code === 'ECONNRESET';
        if (attempt < PDF_FETCH_ATTEMPTS && isRetryable) {
          logger.warn(`PDF fetch attempt ${attempt} failed for user ${userId}, retrying in ${PDF_FETCH_RETRY_DELAY_MS}ms:`, err.message);
          await new Promise(r => setTimeout(r, PDF_FETCH_RETRY_DELAY_MS));
        } else {
          throw lastError;
        }
      }
    }

    const { buffer: pdfBuffer } = parsePdfResponse(pdfResponse.data);

    // 2. Generate filename from fullName (sanitize)
    const filename = `${sanitizeFilename(fullName?.eng)}.pdf`;

    // 3. Send PDF via Telegram
    await bot.telegram.sendDocument(chatId, {
      source: pdfBuffer,
      filename: filename
    }, { caption: "✨ Your Digital ID is ready!" });

    // 4. Send main menu so user can continue
    const menu = getMainMenu(userRole || 'user');
    await bot.telegram.sendMessage(chatId, '🏠 **Main Menu**\nChoose an option:', {
      parse_mode: 'Markdown',
      ...menu
    });

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
      status: error.response?.status,
      response: safeResponseForLog(error.response?.data)
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