const User = require('../models/User');

async function isAuthorized(telegramId) {
  const user = await User.findOne({ telegramId });
  if (!user) return false;
  if (user.role === 'admin') return true;
  if (!user.expiryDate) return false;
  return new Date(user.expiryDate) > new Date();
}

async function getUser(telegramId) {
  return await User.findOne({ telegramId });
}

async function findUserByIdentifier(identifier) {
  if (/^\d+$/.test(identifier)) {
    return await User.findOne({ telegramId: identifier });
  }
  if (identifier.startsWith('@')) {
    const username = identifier.substring(1).toLowerCase();
    return await User.findOne({ telegramUsername: username });
  }
  if (identifier.startsWith('+')) {
    const phone = identifier.replace(/[\s\-]/g, '');
    return await User.findOne({ phoneNumber: phone });
  }
  return null;
}

module.exports = { isAuthorized, getUser, findUserByIdentifier };
