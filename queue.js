// fayda-bot/queue.js
const Queue = require('bull');
const axios = require('axios');
const bot = require('./bot');
const User = require('./models/User');

const API_BASE = "https://api-resident.fayda.et";

if (!process.env.REDIS_URL) {
  console.error('❌ REDIS_URL is not set in environment variables!');
  process.exit(1);
}

console.log('🔍 REDIS_URL (first 30 chars):', process.env.REDIS_URL.substring(0, 30) + '...');

// ----- Bull + Upstash compatible options -----
const redisOptions = {
  redis: {
    url: process.env.REDIS_URL,
    lazyConnect: true,        // only connect when needed
    enableReadyCheck: false,  // must be false for serverless Redis
    maxRetriesPerRequest: null,
    tls: {},                  // force TLS if rediss://
    connectTimeout: 20000,
    family: 4
  },
  defaultJobOptions: {
    attempts: 3,
    backoff: 5000,
    removeOnComplete: true,
    removeOnFail: false
  }
};

// ----- Create the Bull queue -----
let pdfQueue;
try {
  pdfQueue = new Queue('pdf generation', redisOptions);
  console.log('✅ Bull queue created successfully');
} catch (err) {
  console.error('❌ Failed to create Bull queue:', err);
  process.exit(1);
}

// ----- Redis connection monitoring -----
pdfQueue.on('error', (err) => console.error('❌ Bull queue error:', err.message));
pdfQueue.on('ready', () => console.log('✅ Redis connection ready'));
pdfQueue.on('reconnecting', () => console.log('🔄 Redis reconnecting...'));
pdfQueue.on('close', () => console.log('🔴 Redis connection closed'));

// ----- Verify add method -----
if (typeof pdfQueue.add !== 'function') {
  console.error('❌ pdfQueue.add is not a function! pdfQueue =', pdfQueue);
  process.exit(1);
} else {
  console.log('✅ pdfQueue.add is available');
}

// ----- Worker: process jobs -----
pdfQueue.process(5, async (job) => {
  console.log(`🚀 Processing job ${job.id} for user ${job.data.userId}`);
  const { chatId, userId, authHeader, pdfPayload, id, fullName } = job.data;

  try {
    // Generate PDF from API
    const pdfResponse = await axios.post(`${API_BASE}/printableCredentialRoute`, pdfPayload, {
      headers: authHeader,
      responseType: 'text',
      timeout: 20000
    });

    let base64Pdf = pdfResponse.data.trim();
    if (base64Pdf.startsWith('{') && base64Pdf.includes('"pdf"')) {
      try {
        const parsed = JSON.parse(base64Pdf);
        if (parsed.pdf) base64Pdf = parsed.pdf.trim();
      } catch (e) {}
    }

    if (!base64Pdf.startsWith('JVBERi0')) {
      throw new Error('Invalid PDF header');
    }

    const pdfBuffer = Buffer.from(base64Pdf, 'base64');
    const safeName = (fullName?.eng || 'Fayda_Card').replace(/[^a-zA-Z0-9]/g, '_');
    const filename = `${safeName}.pdf`;

    await bot.telegram.sendDocument(chatId, {
      source: pdfBuffer,
      filename
    }, { caption: "✨ Your Digital ID is ready!" });

    await User.updateOne(
      { telegramId: userId },
      { $inc: { downloadCount: 1 }, $set: { lastDownload: new Date() } }
    );

    return { success: true };
  } catch (error) {
    console.error(`❌ Job failed for user ${userId}:`, error.message);
    throw error;
  }
});

console.log('✅ Queue worker started with concurrency 5');

module.exports = pdfQueue;