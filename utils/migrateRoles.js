/**
 * One-time migration: map old role names to new.
 * Old: admin (super), buyer, sub, pending
 * New: superadmin, admin, user, unauthorized
 */
const User = require('../models/User');
const logger = require('../utils/logger');

async function migrateRoles() {
  try {
    const r = await User.updateMany({ role: 'admin' }, { $set: { role: 'superadmin' } });
    if (r.modifiedCount) logger.info(`Migrated ${r.modifiedCount} admin → superadmin`);
    const r2 = await User.updateMany({ role: 'buyer' }, { $set: { role: 'admin' } });
    if (r2.modifiedCount) logger.info(`Migrated ${r2.modifiedCount} buyer → admin`);
    const r3 = await User.updateMany({ role: 'sub' }, { $set: { role: 'user' } });
    if (r3.modifiedCount) logger.info(`Migrated ${r3.modifiedCount} sub → user`);
    const r4 = await User.updateMany({ role: 'pending' }, { $set: { role: 'unauthorized', isWaitingApproval: true } });
    if (r4.modifiedCount) logger.info(`Migrated ${r4.modifiedCount} pending → unauthorized`);
    // Sync parentAdmin from addedBy for users
    const users = await User.find({ role: 'user', addedBy: { $exists: true, $ne: null, $ne: '' } }).select('telegramId addedBy').lean();
    for (const u of users) {
      await User.updateOne({ telegramId: u.telegramId }, { $set: { parentAdmin: u.addedBy } });
    }
    // Clean up unauthorized users older than 5 days
    const fiveDaysAgo = new Date(Date.now() - 5 * 24 * 60 * 60 * 1000);
    const del = await User.deleteMany({ role: 'unauthorized', lastActive: { $lt: fiveDaysAgo } });
    if (del.deletedCount) logger.info(`Cleaned up ${del.deletedCount} unauthorized users older than 5 days`);
  } catch (e) {
    logger.warn('Role migration warning:', e.message);
  }
}

module.exports = { migrateRoles };
