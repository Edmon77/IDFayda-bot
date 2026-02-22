const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  telegramId: { type: String, required: true, unique: true, index: true },
  telegramUsername: { type: String, sparse: true, index: true },
  phoneNumber: { type: String, sparse: true, index: true },
  firstName: String,
  lastName: String,
  // admin | user | unauthorized
  role: { type: String, enum: ['admin', 'user', 'unauthorized'], default: 'unauthorized', index: true },
  // For users: telegramId of their admin. For admins: optional (set if added via web dashboard).
  parentAdmin: { type: String, index: true },
  // Legacy alias; we keep subUsers on admin for quick list
  addedBy: { type: String, index: true },
  expiryDate: { type: Date, index: true },
  subUsers: [{ type: String }],
  isWaitingApproval: { type: Boolean, default: false, index: true },
  createdAt: { type: Date, default: Date.now, index: true },
  lastActive: { type: Date, index: true },
  usageCount: { type: Number, default: 0 },
  downloadCount: { type: Number, default: 0 },
  lastDownload: { type: Date }
});

userSchema.index({ role: 1, createdAt: -1 });
userSchema.index({ addedBy: 1, role: 1 });
userSchema.index({ parentAdmin: 1, role: 1 });

module.exports = mongoose.model('User', userSchema);
