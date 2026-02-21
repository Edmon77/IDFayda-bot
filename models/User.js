const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  telegramId: { type: String, required: true, unique: true },
  telegramUsername: { type: String, sparse: true },
  phoneNumber: { type: String, sparse: true },
  firstName: String,
  lastName: String,
  role: { type: String, enum: ['buyer', 'sub', 'admin'], default: 'sub' },
  addedBy: { type: String },
  expiryDate: { type: Date },
  subUsers: [{ type: String }], // for buyers only
  createdAt: { type: Date, default: Date.now },
  lastActive: { type: Date },
  usageCount: { type: Number, default: 0 },
  downloadCount: { type: Number, default: 0 },
  lastDownload: { type: Date }
});

module.exports = mongoose.model('User', userSchema);