const User = require('../models/User');

async function isAuthorized(telegramId) {
  const user = await User.findOne({ telegramId });
  if (!user) return false;
  if (!user.expiryDate) return false;
  return new Date(user.expiryDate) > new Date();
}

module.exports = { isAuthorized };