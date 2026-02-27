const Queue = require('bull');
const bot = require('../bot');
const logger = require('./logger');

// Broadcast queue for mass messaging with strict rate limiting
const broadcastQueue = new Queue('broadcast-messages', process.env.REDIS_URL, {
    defaultJobOptions: {
        attempts: 5,
        backoff: {
            type: 'exponential',
            delay: 5000
        },
        removeOnComplete: true,
        removeOnFail: {
            age: 24 * 3600 // Keep failed broadcast jobs for 24h for debugging
        }
    },
    settings: {
        maxStalledCount: 1
    }
});

// Telegram rate limits: ~30 messages per second globally.
// We'll be conservative and use a concurrency and rate limiter in Bull.
// This worker will process jobs one at a time with a delay.
broadcastQueue.process(1, async (job) => {
    const { telegramId, message, parseMode = 'Markdown' } = job.data;

    try {
        await bot.telegram.sendMessage(telegramId, message, { parse_mode: parseMode });
        // Artificial delay to respect Telegram rate limits (approx 20-30 msgs/sec for simple text)
        // Using 100ms between attempts for safety (10 msgs/sec)
        await new Promise(r => setTimeout(r, 100));
        return { success: true };
    } catch (err) {
        const isBlocked = err.message && (err.message.includes('blocked') || err.message.includes('deactivated') || err.message.includes('chat not found'));

        if (isBlocked) {
            logger.warn(`Skipping broadcast to user ${telegramId}: Bot was blocked or account deleted.`);
            return { success: false, reason: 'blocked' };
        }

        if (err.description && err.description.includes('retry after')) {
            const waitTime = parseInt(err.parameters?.retry_after, 10) || 5;
            logger.error(`Telegram Rate Limit hit during broadcast. Retrying in ${waitTime}s...`);
            // Throwing error will trigger Bull's backoff and retry
            throw err;
        }

        logger.error(`Broadcast failed for user ${telegramId}:`, err.message);
        throw err;
    }
});

broadcastQueue.on('stalled', (job) => {
    logger.warn(`Broadcast job ${job.id} stalled.`);
});

broadcastQueue.on('failed', (job, err) => {
    // We don't want to spam logs for every single block, but we track errors
    if (!err.message.includes('blocked')) {
        logger.error(`Broadcast job to ${job.data.telegramId} failed permanently:`, err.message);
    }
});

module.exports = broadcastQueue;
