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

// ---------- Create Bull Queue ----------
const pdfQueue = new Queue('pdf generation', process.env.REDIS_URL, {
  defaultJobOptions: {
    attempts: 3,           // retry 3 times on failure
    backoff: { type: 'exponential', delay: 5000 }, // exponential backoff
    removeOnComplete: true,
    removeOnFail: false
  }
});

// ---------- Queue Event Listeners ----------
pdfQueue.on('error', (err) => console.error('❌ Bull queue error:', err.message));
pdfQueue.on('ready', () => console.log('✅ Redis connection ready'));
pdfQueue.on('waiting', (jobId) => console.log(`⏳ Job ${jobId} is waiting in queue`));
pdfQueue.on('active', (job) => console.log(`🚀 Processing job ${job.id} for user ${job.data.userId}`));
pdfQueue.on('completed', (job) => console.log(`✅ Job ${job.id} completed successfully`));
pdfQueue.on('failed', (job, err) => console.error(`❌ Job ${job.id} failed:`, err.message));

// ---------- Queue Worker ----------
pdfQueue.process(5, async (job) => {
  const { chatId, userId, authHeader, pdfPayload, fullName } = job.data;

  try {
    // Call API to generate PDF
    const pdfResponse = await axios.post(`${API_BASE}/printableCredentialRoute`, pdfPayload, {
      headers: authHeader,
      responseType: 'text',
      timeout: 20000
    });

    let base64Pdf = pdfResponse.data.trim();

    // Handle JSON wrapper if returned
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

    // Send PDF via Telegram
    await bot.telegram.sendDocument(chatId, { source: pdfBuffer, filename }, { caption: "✨ Your Digital ID is ready!" });

    // Update user stats
    await User.updateOne(
      { telegramId: userId },
      { $inc: { downloadCount: 1 }, $set: { lastDownload: new Date() } }
    );

    return { success: true };
  } catch (err) {
    console.error(`❌ Job failed for user ${userId}:`, err.message);
    throw err; // Bull will handle retries
  }
});

console.log('✅ Queue worker started with concurrency 5');

module.exports = pdfQueue;