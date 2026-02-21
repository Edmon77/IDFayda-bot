/**
 * Input validation utilities
 */

function validateFaydaId(id) {
  if (!id || typeof id !== 'string') {
    return { valid: false, error: 'ID must be a string' };
  }
  if (!/^\d{16}$/.test(id.trim())) {
    return { valid: false, error: 'ID must be exactly 16 digits' };
  }
  return { valid: true, value: id.trim() };
}

function validateOTP(otp) {
  if (!otp || typeof otp !== 'string') {
    return { valid: false, error: 'OTP must be a string' };
  }
  const cleaned = otp.trim();
  if (!/^\d{4,8}$/.test(cleaned)) {
    return { valid: false, error: 'OTP must be 4-8 digits' };
  }
  return { valid: true, value: cleaned };
}

function validateTelegramId(id) {
  if (!id || typeof id !== 'string') {
    return { valid: false, error: 'Telegram ID must be a string' };
  }
  if (!/^\d+$/.test(id.trim())) {
    return { valid: false, error: 'Invalid Telegram ID format' };
  }
  return { valid: true, value: id.trim() };
}

function sanitizeUsername(username) {
  if (!username) return null;
  return username.replace(/[^a-zA-Z0-9_]/g, '').substring(0, 32);
}

function sanitizeFilename(name) {
  if (!name) return 'Fayda_Card';
  return name.replace(/[^a-zA-Z0-9]/g, '_').substring(0, 100);
}

module.exports = {
  validateFaydaId,
  validateOTP,
  validateTelegramId,
  sanitizeUsername,
  sanitizeFilename
};
