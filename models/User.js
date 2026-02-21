const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  telegramId: { type: String, required: true, unique: true, index: true },
  telegramUsername: { type: String, sparse: true, index: true },
  phoneNumber: { type: String, sparse: true, index: true },
  firstName: String,
  lastName: String,
  role: { type: String, enum: ['buyer', 'sub', 'admin'], default: 'sub', index: true },
  addedBy: { type: String, index: true },
  expiryDate: { type: Date, index: true },
  subUsers: [{ type: String }], // for buyers only
  createdAt: { type: Date, default: Date.now, index: true },
  lastActive: { type: Date, index: true },
  usageCount: { type: Number, default: 0 },
  downloadCount: { type: Number, default: 0 },
  lastDownload: { type: Date }
});

// Compound indexes for common queries
userSchema.index({ role: 1, createdAt: -1 });
userSchema.index({ addedBy: 1, role: 1 });

module.exports = mongoose.model('User', userSchema);