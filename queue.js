const Queue = require('bull');
const axios = require('axios');
const bot = require('./bot');
const User = require('./models/User');

const API_BASE = "https://api-resident.fayda.et";

if (!process.env.REDIS_URL) {
  console.error('❌ REDIS_URL is not set in environment variables!');
  process.exit(1);
}

let pdfQueue;
try {
  pdfQueue = new Queue('pdf generation', process.env.REDIS_URL, {
    redis: {
      connectTimeout: 10000, // 10 seconds connection timeout
      retryStrategy: (times) => Math.min(times * 100, 3000) // reconnect strategy
    },
    defaultJobOptions: {
      attempts: 3,
      backoff: 5000,
      removeOnComplete: true,
      removeOnFail: false
    }
  });
  console.log('✅ Bull queue created successfully');
} catch (err) {
  console.error('❌ Failed to create Bull queue:', err);
  process.exit(1);
}

pdfQueue.on('error', (err) => {
  console.error('❌ Bull queue error:', err);
});

if (typeof pdfQueue.add !== 'function') {
  console.error('❌ pdfQueue.add is not a function! pdfQueue =', pdfQueue);
  process.exit(1);
} else {
  console.log('✅ pdfQueue.add is available');
}

pdfQueue.process(5, async (job) => {
  console.log(`🚀 Processing job ${job.id} for user ${job.data.userId}`);
  const { chatId, userId, authHeader, pdfPayload, id, fullName } = job.data;

  try {
    const pdfResponse = await axios.post(`${API_BASE}/printableCredentialRoute`, pdfPayload, {
      headers: authHeader,
      responseType: 'text',
      timeout: 20000 // 20 seconds timeout for the HTTP request
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
      filename: filename
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