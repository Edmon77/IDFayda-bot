/**
 * Input validation utilities
 */

// FCN = 16 digits, FIN = 12 digits (spaces allowed, e.g. 6320 7510 3126)
function validateFaydaId(id) {
  if (!id || typeof id !== 'string') {
    return { valid: false, error: 'ID must be a string' };
  }
  const cleaned = id.replace(/\s/g, ''); // strip spaces (FIN can be 6320 7510 3126)
  if (/^\d{16}$/.test(cleaned)) {
    return { valid: true, value: cleaned, type: 'FCN' };
  }
  if (/^\d{12}$/.test(cleaned)) {
    return { valid: true, value: cleaned, type: 'FIN' };
  }
  return { valid: false, error: 'Enter 16-digit FCN or 12-digit FIN (e.g. 8037042063274197 or 632075103126)' };
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

/**
 * Escape special characters for Telegram Markdown (v1).
 * Characters: _ * ` [
 */
function escMd(str) {
  if (!str) return '';
  return String(str).replace(/([_*`\[])/g, '\\$1');
}

/**
 * Safe display name for Markdown messages.
 * Falls back through firstName → username → telegramId → 'Unknown'.
 * Escapes Markdown and rejects "empty-looking" names (e.g. just dots/spaces).
 */
function displayName(user, fallback) {
  const raw = user?.firstName || user?.telegramUsername || fallback || user?.telegramId || 'Unknown';
  const cleaned = String(raw).replace(/[.\s]/g, '').length > 0 ? raw : (user?.telegramId || 'Unknown');
  return escMd(cleaned);
}

module.exports = {
  validateFaydaId,
  validateOTP,
  validateTelegramId,
  sanitizeUsername,
  sanitizeFilename,
  escMd,
  displayName
};
