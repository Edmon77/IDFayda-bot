const Queue = require('bull');
const axios = require('axios');
const bot = require('./bot');
const User = require('./models/User');

const API_BASE = "https://api-resident.fayda.et";

// Validate Redis URL
if (!process.env.REDIS_URL) {
  console.error('❌ REDIS_URL is not set in environment variables!');
  process.exit(1);
}

let pdfQueue;
try {
  pdfQueue = new Queue('pdf generation', process.env.REDIS_URL, {
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

// Verify that pdfQueue has the add method
if (typeof pdfQueue.add !== 'function') {
  console.error('❌ pdfQueue.add is not a function! pdfQueue =', pdfQueue);
  process.exit(1);
} else {
  console.log('✅ pdfQueue.add is available');
}

// Worker: processes jobs concurrently
pdfQueue.process(5, async (job) => {
  const { chatId, userId, authHeader, pdfPayload, id, fullName } = job.data;

  try {
    // 1. Fetch PDF from Fayda
    const pdfResponse = await axios.post(`${API_BASE}/printableCredentialRoute`, pdfPayload, {
      headers: authHeader,
      responseType: 'text'
    });

    let base64Pdf = pdfResponse.data.trim();
    // If response is JSON with a pdf field, extract it
    if (base64Pdf.startsWith('{') && base64Pdf.includes('"pdf"')) {
      try {
        const parsed = JSON.parse(base64Pdf);
        if (parsed.pdf) base64Pdf = parsed.pdf.trim();
      } catch (e) {
        // ignore, keep original
      }
    }

    // Validate base64 header
    if (!base64Pdf.startsWith('JVBERi0')) {
      throw new Error('Invalid PDF header');
    }

    // 2. Convert to buffer
    const pdfBuffer = Buffer.from(base64Pdf, 'base64');

    // 3. Generate filename from fullName (sanitize)
    const safeName = (fullName?.eng || 'Fayda_Card').replace(/[^a-zA-Z0-9]/g, '_');
    const filename = `${safeName}.pdf`;

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

    return { success: true };
  } catch (error) {
    console.error(`Job failed for user ${userId}:`, error.message);
    // Rethrow so Bull retries
    throw error;
  }
});

console.log('✅ Queue worker started with concurrency 5');

module.exports = pdfQueue;