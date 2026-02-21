const { Queue, Worker, QueueScheduler } = require('bullmq');
const Redis = require('ioredis');
const axios = require('axios');
const bot = require('./bot');
const User = require('./models/User');

const API_BASE = "https://api-resident.fayda.et";

if (!process.env.REDIS_URL) {
  console.error('❌ REDIS_URL is not set in environment variables!');
  process.exit(1);
}

// Redis connection with IPv4 and TLS
const connection = new Redis(process.env.REDIS_URL, {
  tls: {},               // required for rediss://
  connectTimeout: 20000,
  enableReadyCheck: false,
  family: 4               // force IPv4
});

connection.on('error', (err) => {
  console.error('❌ Redis connection error:', err.message);
});

connection.on('ready', () => {
  console.log('✅ Redis connection ready');
});

connection.on('reconnecting', () => {
  console.log('🔄 Redis reconnecting...');
});

connection.on('close', () => {
  console.log('🔴 Redis connection closed');
});

// QueueScheduler handles retries, delayed jobs, etc.
new QueueScheduler('pdf generation', { connection });

// Create the BullMQ queue
const pdfQueue = new Queue('pdf generation', {
  connection,
  defaultJobOptions: {
    attempts: 3,
    backoff: { type: 'exponential', delay: 5000 },
    removeOnComplete: true,
    removeOnFail: false
  }
});

console.log('✅ BullMQ queue created');

// Worker to process PDF jobs
const worker = new Worker('pdf generation', async (job) => {
  const { chatId, userId, authHeader, pdfPayload, fullName } = job.data;
  console.log(`🚀 Processing job ${job.id} for user ${userId}`);

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

    await bot.telegram.sendDocument(chatId, {
      source: pdfBuffer,
      filename
    }, { caption: "✨ Your Digital ID is ready!" });

    await User.updateOne(
      { telegramId: userId },
      { $inc: { downloadCount: 1 }, $set: { lastDownload: new Date() } }
    );

    return { success: true };
  } catch (err) {
    console.error(`❌ Job failed for user ${userId}:`, err.message);
    throw err;
  }
}, { connection, concurrency: 5 });

worker.on('error', (err) => console.error('❌ BullMQ Worker error:', err));

console.log('✅ BullMQ Worker started with concurrency 5');

module.exports = pdfQueue;