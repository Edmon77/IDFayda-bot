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
    winston.format.splat(),
    winston.format.json()
  ),
  defaultMeta: { service: 'fayda-bot' },
  transports: [
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' })
  ]
});

// Add console transport in development
if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.combine(
      winston.format.colorize(),
      winston.format.simple()
    )
  }));
}

module.exports = logger;
module.exports.safeResponseForLog = safeResponseForLog;
