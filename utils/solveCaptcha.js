const axios = require('axios');
const logger = require('./logger');

class SolveCaptcha {
    constructor(apiKey) {
        if (!apiKey) {
            throw new Error('SolveCaptcha API key is required');
        }
        this.apiKey = apiKey;
        this.pollIntervalMs = 5000; // 5 seconds as per docs
    }

    /**
     * Drop-in replacement for 2captcha's solver.recaptcha()
     * @param {string} siteKey - The Google reCAPTCHA sitekey
     * @param {string} pageUrl - The URL of the page containing the captcha
     * @param {object} options - Additional options like { version: 'v3', action: 'verify', min_score: 0.5 }
     * @returns {Promise<{ data: string }>} - Matches the { data: token } format of the previous library
     */
    async recaptcha(siteKey, pageUrl, options = {}) {
        try {
            // 1. Submit the CAPTCHA to SolveCaptcha
            const inParams = new URLSearchParams();
            inParams.append('key', this.apiKey);
            inParams.append('method', 'userrecaptcha');
            inParams.append('googlekey', siteKey);
            inParams.append('pageurl', pageUrl);
            inParams.append('json', '1');

            if (options.version === 'v3') {
                inParams.append('version', 'v3');
                if (options.action) {
                    inParams.append('action', options.action);
                }
                if (options.min_score) {
                    inParams.append('min_score', options.min_score);
                }
            }

            const inRes = await axios.post('https://api.solvecaptcha.com/in.php', inParams.toString(), {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
            });

            const inData = inRes.data;

            if (inData.status !== 1) {
                throw new Error(`SolveCaptcha submit failed: ${inData.request || JSON.stringify(inData)}`);
            }

            const captchaId = inData.request;
            // logger.info(`Submitted reCAPTCHA to SolveCaptcha, ID: ${captchaId}`);

            // 2. Poll for the result
            // "Make a 15-20 seconds timeout then submit a HTTP GET request to our API URL"
            await new Promise(resolve => setTimeout(resolve, 15000));

            const maxAttempts = 24; // ~2 minutes maximum polling
            for (let attempt = 0; attempt < maxAttempts; attempt++) {
                const resUrl = `https://api.solvecaptcha.com/res.php?key=${this.apiKey}&action=get&id=${captchaId}&json=1`;
                const outRes = await axios.get(resUrl);
                const outData = outRes.data;

                if (outData.status === 1) {
                    // Solved successfully
                    return { data: outData.request };
                } else if (outData.request === 'CAPCHA_NOT_READY') {
                    // Wait 5 seconds and poll again
                    await new Promise(resolve => setTimeout(resolve, this.pollIntervalMs));
                } else {
                    // Some other error
                    throw new Error(`SolveCaptcha poll failed: ${outData.request}`);
                }
            }

            throw new Error(`SolveCaptcha timed out waiting for solution for ID: ${captchaId}`);
        } catch (error) {
            logger.error('SolveCaptcha interaction error', { message: error.message });
            throw error;
        }
    }
}

module.exports = SolveCaptcha;
