const winston = require('winston');

/** Avoid logging huge bodies (e.g. 2MB base64 PDF response). */
function safeResponseForLog(data) {
  if (data === undefined || data === null) return data;
  if (typeof data === 'string') {
    return data.length > 500 ? data.substring(0, 500) + '...[truncated]' : data;
  }
  if (typeof data === 'object' && data !== null && data.message) return { message: data.message };
  const s = String(data);
  return s.length > 500 ? s.substring(0, 500) + '...[truncated]' : s;
}

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'fayda-bot' },
  transports: [
    // Console always on — Railway/Docker reads stdout
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        winston.format.json()
      )
    })
  ]
});

// File transports only when explicitly enabled (useless on ephemeral filesystems like Railway)
if (process.env.LOG_TO_FILE === 'true') {
  logger.add(new winston.transports.File({ filename: 'logs/error.log', level: 'error' }));
  logger.add(new winston.transports.File({ filename: 'logs/combined.log' }));
}

module.exports = logger;
module.exports.safeResponseForLog = safeResponseForLog;
