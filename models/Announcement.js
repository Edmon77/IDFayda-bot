const mongoose = require('mongoose');

const announcementSchema = new mongoose.Schema({
    message: { type: String, required: true },
    sentAt: { type: Date, default: Date.now, index: true },
    recipientsCount: { type: Number, default: 0 },
    // 'pending', 'completed', 'deleted'
    status: { type: String, enum: ['pending', 'completed', 'deleted'], default: 'pending' },
    // Array of { chatId, messageId } for remote deletion
    sentMessages: [{
        chatId: { type: String },
        messageId: { type: Number }
    }],
    // For 'delete for everyone' progress tracking
    deletedAt: { type: Date }
});

module.exports = mongoose.model('Announcement', announcementSchema);
