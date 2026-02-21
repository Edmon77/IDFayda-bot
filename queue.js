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

// Create the Bull queue directly with the Upstash URL
const pdfQueue = new Queue('pdf generation', process.env.REDIS_URL, {
  defaultJobOptions: {
    attempts: 3,
    backoff: 5000,
    removeOnComplete: true,
    removeOnFail: false
  }
});

pdfQueue.on('error', (err) => console.error('❌ Bull queue error:', err.message));
pdfQueue.on('ready', () => console.log('✅ Redis connection ready'));
pdfQueue.on('failed', (job, err) => console.error(`❌ Job ${job.id} failed:`, err.message));

// Worker: processes jobs concurrently
pdfQueue.process(5, async (job) => {
  console.log(`🚀 Processing job ${job.id} for user ${job.data.userId}`);
  const { chatId, userId, authHeader, pdfPayload, fullName } = job.data;

  try {
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
      } catch {}
    }

    if (!base64Pdf.startsWith('JVBERi0')) throw new Error('Invalid PDF header');

    const pdfBuffer = Buffer.from(base64Pdf, 'base64');
    const safeName = (fullName?.eng || 'Fayda_Card').replace(/[^a-zA-Z0-9]/g, '_');
    const filename = `${safeName}.pdf`;

    await bot.telegram.sendDocument(chatId, { source: pdfBuffer, filename }, { caption: "✨ Your Digital ID is ready!" });
    await User.updateOne({ telegramId: userId }, { $inc: { downloadCount: 1 }, $set: { lastDownload: new Date() } });

    return { success: true };
  } catch (err) {
    console.error(`❌ Job failed for user ${userId}:`, err.message);
    throw err;
  }
});

console.log('✅ Queue worker started with concurrency 5');

module.exports = pdfQueue;