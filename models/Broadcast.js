const mongoose = require('mongoose');

const Schema = new mongoose.Schema({
    message: {
        type: String,
        required: true
    },
    templateKey: {
        type: String
    },
    sentBy: {
        type: String,
        required: true
    },
    sentAt: {
        type: Date,
        default: Date.now
    },
    totalRecipients: {
        type: Number,
        default: 0
    },
    delivered: {
        type: Number,
        default: 0
    },
    failed: {
        type: Number,
        default: 0
    },
    status: {
        type: String,
        enum: ['sending', 'completed', 'failed'],
        default: 'sending'
    },
    failedUserIds: [{
        type: String
    }],
    messageIds: [{
        telegramId: String,
        messageId: Number
    }]
});

module.exports = mongoose.model('Broadcast', Schema);
