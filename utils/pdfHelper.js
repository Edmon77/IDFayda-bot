/**
 * Shared PDF response parsing for Fayda API.
 * Handles raw base64, JSON-wrapped { "pdf": "..." }, and validates decoded PDF header.
 */

const logger = require('./logger');

const PDF_BASE64_HEADER = 'JVBERi0'; // %PDF- in base64
const PDF_BINARY_HEADER = '%PDF';
// Fayda returns ~1.8–2 MB base64; cap at 8 MB to avoid OOM from bad/malformed responses
const MAX_BASE64_LENGTH = 8 * 1024 * 1024;

/**
 * Normalize and validate Fayda API PDF response (text or JSON with "pdf" field).
 * @param {string} rawResponse - responseType: 'text' from printableCredentialRoute
 * @returns {{ buffer: Buffer }} - decoded PDF buffer
 * @throws {Error} if response is not a valid PDF
 */
function parsePdfResponse(rawResponse) {
  if (!rawResponse || typeof rawResponse !== 'string') {
    throw new Error('Invalid PDF response: empty or not a string');
  }

  if (rawResponse.length > MAX_BASE64_LENGTH) {
    throw new Error(`PDF response too large (${(rawResponse.length / 1024 / 1024).toFixed(1)} MB). Max allowed ${MAX_BASE64_LENGTH / 1024 / 1024} MB.`);
  }

  let base64Pdf = rawResponse.trim();

  // Strip any whitespace/newlines that might break base64
  base64Pdf = base64Pdf.replace(/\s+/g, '');

  // If API returns JSON with a "pdf" field, extract it
  if (base64Pdf.startsWith('{') && base64Pdf.includes('"pdf"')) {
    try {
      const parsed = JSON.parse(base64Pdf);
      if (parsed.pdf && typeof parsed.pdf === 'string') {
        base64Pdf = parsed.pdf.trim().replace(/\s+/g, '');
      }
    } catch (e) {
      logger.warn('PDF response looked like JSON but parse failed, using raw');
    }
  }

  if (!base64Pdf.length) {
    throw new Error('Invalid PDF response: no data after parse');
  }

  // Validate base64 prefix (PDF magic in base64)
  if (!base64Pdf.startsWith(PDF_BASE64_HEADER)) {
    logger.warn('PDF base64 did not start with expected header', {
      first50: base64Pdf.substring(0, 50)
    });
    throw new Error('Invalid PDF header - response is not a valid PDF');
  }

  let buffer;
  try {
    buffer = Buffer.from(base64Pdf, 'base64');
  } catch (e) {
    throw new Error('Invalid base64 in PDF response');
  }

  // Double-check decoded buffer has PDF magic (like old reliable code)
  const header = buffer.slice(0, 4).toString('ascii');
  if (header !== PDF_BINARY_HEADER) {
    logger.warn('Decoded PDF buffer header mismatch', { header });
    throw new Error('Decoded content is not a valid PDF');
  }

  return { buffer };
}

module.exports = { parsePdfResponse };
