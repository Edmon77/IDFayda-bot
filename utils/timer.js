/**
 * Download flow timing utility.
 * Tracks per-step durations across the entire FCN → OTP → PDF flow
 * with a single requestId for full end-to-end visibility.
 *
 * Usage:
 *   const timer = new DownloadTimer(userId);
 *   timer.startStep('captchaSolve');
 *   // ... do work ...
 *   timer.endStep('captchaSolve');
 *   timer.report();          // logs structured JSON summary
 *   timer.toSession();       // serialize for Redis session persistence
 *   DownloadTimer.fromSession(data, userId); // restore in OTP step
 */

const crypto = require('crypto');
const logger = require('./logger');

const SLOW_THRESHOLD_MS = 60000;

class DownloadTimer {
    /**
     * @param {string} userId - Telegram user ID (safe to log)
     * @param {string} [requestId] - Reuse existing ID when restoring from session
     */
    constructor(userId, requestId) {
        this.requestId = requestId || crypto.randomBytes(8).toString('hex');
        this.userId = userId;
        this.steps = {};          // { name: { start, end, durationMs } }
        this.flowStart = Date.now();
        this.phaseTimings = {};   // { idPhaseMs, userWaitMs, otpPhaseMs }
    }

    /** Mark the beginning of a named step. */
    startStep(name) {
        this.steps[name] = { start: Date.now() };
    }

    /** Mark the end of a named step and warn if it exceeds the threshold. */
    endStep(name) {
        const step = this.steps[name];
        if (!step) return;
        step.end = Date.now();
        step.durationMs = step.end - step.start;
        if (step.durationMs > SLOW_THRESHOLD_MS) {
            logger.warn('Slow download step detected', {
                requestId: this.requestId,
                userId: this.userId,
                step: name,
                durationMs: step.durationMs
            });
        }
    }

    /** Record a phase duration (idPhaseMs, userWaitMs, otpPhaseMs). */
    setPhase(name, durationMs) {
        this.phaseTimings[name] = durationMs;
    }

    /**
     * Emit the structured Download Timing Report.
     * @param {'success'|'failed'|'queued'|string} outcome
     */
    report(outcome = 'success') {
        const totalFlowMs = Date.now() - this.flowStart;
        const timings = {};
        for (const [name, s] of Object.entries(this.steps)) {
            timings[name] = s.durationMs ?? null;
        }
        logger.info('Download Timing Report', {
            requestId: this.requestId,
            userId: this.userId,
            outcome,
            totalFlowMs,
            phases: this.phaseTimings,
            steps: timings
        });
        return { requestId: this.requestId, totalFlowMs, timings };
    }

    /**
     * Serialize to a plain object safe for Redis session storage.
     * Called at end of ID phase so OTP phase can restore it.
     */
    toSession() {
        return {
            requestId: this.requestId,
            flowStart: this.flowStart,
            phaseTimings: this.phaseTimings,
            // steps contain only completed step durations (no Date objects)
            completedSteps: Object.fromEntries(
                Object.entries(this.steps)
                    .filter(([, s]) => s.durationMs != null)
                    .map(([name, s]) => [name, s.durationMs])
            )
        };
    }

    /**
     * Restore from serialized session data.
     * @param {object} data - From toSession()
     * @param {string} userId
     */
    static fromSession(data, userId) {
        if (!data || !data.requestId) return new DownloadTimer(userId);
        const timer = new DownloadTimer(userId, data.requestId);
        timer.flowStart = data.flowStart || Date.now();
        timer.phaseTimings = data.phaseTimings || {};
        // Restore completed steps for the final report
        if (data.completedSteps) {
            for (const [name, ms] of Object.entries(data.completedSteps)) {
                timer.steps[name] = { durationMs: ms };
            }
        }
        return timer;
    }
}

module.exports = { DownloadTimer };
