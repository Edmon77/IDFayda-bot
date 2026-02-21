const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  telegramId: {
    type: String,
    required: true,
    unique: true,
    index: true
  },

  telegramUsername: {
    type: String,
    sparse: true
  },

  phoneNumber: {
    type: String,
    sparse: true
  },

  firstName: String,
  lastName: String,

  role: {
    type: String,
    enum: ['buyer', 'sub', 'admin'],
    default: 'sub'
  },

  addedBy: String,

  expiryDate: Date,

  subUsers: [{
    type: String
  }],

  createdAt: {
    type: Date,
    default: Date.now
  },

  lastActive: Date,

  usageCount: {
    type: Number,
    default: 0
  },

  downloadCount: {
    type: Number,
    default: 0
  },

  lastDownload: Date
});

module.exports = mongoose.model('User', userSchema);