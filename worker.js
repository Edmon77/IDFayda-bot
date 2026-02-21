require('dotenv').config();
const mongoose = require('mongoose');
const axios = require('axios');
const bot = require('./bot');
const pdfQueue = require('./queue');
const User = require('./models/User');

const API_BASE = "https://api-resident.fayda.et";

// Connect MongoDB
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅ Worker MongoDB connected'))
  .catch(err => {
    console.error('❌ Worker Mongo error:', err);
    process.exit(1);
  });

// Process jobs
pdfQueue.process(2, async (job) => {
  const { chatId, userId, authHeader, pdfPayload, fullName } = job.data;

  try {
    console.log(`📄 Processing job ${job.id} for user ${userId}`);

    const pdfResponse = await axios.post(
      `${API_BASE}/printableCredentialRoute`,
      pdfPayload,
      { headers: authHeader, responseType: 'text' }
    );

    let base64Pdf = pdfResponse.data.trim();

    // Handle JSON wrapped PDF
    if (base64Pdf.startsWith('{')) {
      const parsed = JSON.parse(base64Pdf);
      if (parsed.pdf) base64Pdf = parsed.pdf.trim();
    }

    if (!base64Pdf.startsWith('JVBERi0')) {
      throw new Error('Invalid PDF header');
    }

    const pdfBuffer = Buffer.from(base64Pdf, 'base64');

    const safeName = (fullName?.eng || 'Fayda_Card')
      .replace(/[^a-zA-Z0-9]/g, '_');

    await bot.telegram.sendDocument(
      chatId,
      { source: pdfBuffer, filename: `${safeName}.pdf` },
      { caption: "✨ Your Digital ID is ready!" }
    );

    await User.updateOne(
      { telegramId: userId },
      { 
        $inc: { downloadCount: 1 },
        $set: { lastDownload: new Date() }
      }
    );

    console.log(`✅ Job ${job.id} completed`);
    return { success: true };

  } catch (error) {
    console.error(`❌ Worker job error:`, error.message);
    throw error;
  }
});

console.log("🚀 Worker started and waiting for jobs...");