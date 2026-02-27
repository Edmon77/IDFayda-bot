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

const Announcement = require('../models/Announcement');

// Broadcast queue for mass messaging and remote deletions
// This worker will process jobs one at a time with a strict delay.
broadcastQueue.process(1, async (job) => {
    const { type = 'send', telegramId, message, announcementId, messageId: targetMessageId, parseMode = 'Markdown' } = job.data;
    logger.info(`Processing broadcast job: type=${type}, user=${telegramId}, announcement=${announcementId}`);

    try {
        if (type === 'send') {
            const sentMsg = await bot.telegram.sendMessage(telegramId, message, { parse_mode: parseMode });

            // Update the Announcement record with this messageId for later deletion
            if (announcementId && sentMsg.message_id) {
                await Announcement.findByIdAndUpdate(announcementId, {
                    $push: { sentMessages: { chatId: telegramId, messageId: sentMsg.message_id } },
                    $inc: { sentCount: 1 }
                });
            }
        } else if (type === 'delete') {
            // Remote deletion logic
            if (targetMessageId) {
                await bot.telegram.deleteMessage(telegramId, targetMessageId).catch(() => {
                    // Ignore errors like "message not found" or "too old to delete"
                });
            }
        }

        // Artificial delay to respect Telegram rate limits
        // Reducing to 50ms for approx 20 messages per second (safe and faster)
        await new Promise(r => setTimeout(r, 50));
        return { success: true };
    } catch (err) {
        const isBlocked = err.message && (err.message.includes('blocked') || err.message.includes('deactivated') || err.message.includes('chat not found'));

        if (isBlocked) {
            if (announcementId) {
                await Announcement.findByIdAndUpdate(announcementId, { $inc: { failedCount: 1 } });
            }
            return { success: false, reason: 'blocked' };
        }

        if (err.description && err.description.includes('retry after')) {
            const waitTime = parseInt(err.parameters?.retry_after, 10) || 5;
            logger.error(`Telegram Rate Limit hit during broadcast ${type}. Retrying after ${waitTime}s...`);
            throw err;
        }

        logger.error(`Broadcast ${type} failed for user ${telegramId}:`, err.message);
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
