/**
 * Captcha Pre-solve Pool
 * Maintains a background pool of pre-solved reCAPTCHA tokens so users
 * don't have to wait 5–26s for a fresh solve at download time.
 *
 * Token lifecycle:
 *   - reCAPTCHA v2 tokens are valid for ~120 seconds
 *   - We discard tokens older than TOKEN_TTL_MS (90s) to be safe
 *   - Pool refills automatically in the background
 *   - If pool is empty, falls back to on-demand solving (no breakage)
 */

const logger = require('./logger');

const POOL_SIZE = parseInt(process.env.CAPTCHA_POOL_SIZE, 10) || 3;
const TOKEN_TTL_MS = 90_000;           // discard tokens older than 90s
const REFILL_INTERVAL_MS = 30_000;     // check pool every 30s
const SOLVE_TIMEOUT_MS = 120_000;      // give up on a single solve after 120s (solves can take up to 90s)

class CaptchaPool {
    /**
     * @param {import('2captcha').Solver} solver - 2captcha Solver instance
     * @param {string} siteKey - reCAPTCHA site key
     * @param {string} pageUrl - page URL for the captcha
     */
    constructor(solver, siteKey, pageUrl) {
        this.solver = solver;
        this.siteKey = siteKey;
        this.pageUrl = pageUrl;

        /** @type {Array<{ token: string, solvedAt: number }>} */
        this.tokens = [];
        this.filling = false;
        this._interval = null;
        this._stopped = false;
    }

    /** Start background refill loop. Call once at boot. */
    start() {
        logger.info(`Captcha pool starting (size=${POOL_SIZE}, ttl=${TOKEN_TTL_MS}ms)`);
        // Initial fill
        this._refill();
        // Periodic refill
        this._interval = setInterval(() => this._refill(), REFILL_INTERVAL_MS);
        // Don't prevent Node from exiting
        if (this._interval.unref) this._interval.unref();
    }

    /** Stop the background refill loop. For graceful shutdown. */
    stop() {
        this._stopped = true;
        if (this._interval) {
            clearInterval(this._interval);
            this._interval = null;
        }
        this.tokens = [];
        logger.info('Captcha pool stopped');
    }

    /**
     * Get a pre-solved token from the pool.
     * Returns instantly if a fresh token is available, else falls back to on-demand solving.
     * @returns {Promise<string>} reCAPTCHA token value
     */
    async get() {
        // Prune expired tokens first
        this._prune();

        if (this.tokens.length > 0) {
            const entry = this.tokens.shift();
            const ageMs = Date.now() - entry.solvedAt;
            logger.info('Captcha token served from pool', {
                poolRemaining: this.tokens.length,
                tokenAgeMs: ageMs
            });
            // Trigger background refill (non-blocking)
            this._refill();
            return entry.token;
        }

        // Pool empty — fall back to on-demand solve (same as before)
        logger.warn('Captcha pool empty, solving on-demand');
        return this._solveOne();
    }

    /**
     * Solve a single captcha and return the token (not pooled).
     * @returns {Promise<string>}
     */
    async _solveOne() {
        const result = await this.solver.recaptcha(this.siteKey, this.pageUrl);
        return result.data;
    }

    /** Prune expired tokens from the pool. */
    _prune() {
        const now = Date.now();
        const before = this.tokens.length;
        this.tokens = this.tokens.filter(t => (now - t.solvedAt) < TOKEN_TTL_MS);
        const pruned = before - this.tokens.length;
        if (pruned > 0) {
            logger.info(`Captcha pool pruned ${pruned} expired token(s), ${this.tokens.length} remaining`);
        }
    }

    /** Fill pool to target size. Runs in background, non-blocking. */
    async _refill() {
        if (this.filling || this._stopped) return;
        this._prune();

        const needed = POOL_SIZE - this.tokens.length;
        if (needed <= 0) return;

        this.filling = true;
        logger.info(`Captcha pool refilling: need ${needed} token(s)`);

        // Solve in parallel for speed
        const promises = [];
        for (let i = 0; i < needed; i++) {
            promises.push(
                Promise.race([
                    this._solveOne(),
                    new Promise((_, reject) =>
                        setTimeout(() => reject(new Error('Captcha solve timeout')), SOLVE_TIMEOUT_MS)
                    )
                ])
                    .then(token => {
                        if (!this._stopped) {
                            this.tokens.push({ token, solvedAt: Date.now() });
                        }
                    })
                    .catch(err => {
                        logger.warn('Captcha pool solve failed', { error: err.message });
                    })
            );
        }

        await Promise.allSettled(promises);
        this.filling = false;
        logger.info(`Captcha pool refilled: ${this.tokens.length}/${POOL_SIZE} tokens ready`);
    }
}

module.exports = { CaptchaPool };
