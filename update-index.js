const fs = require('fs');
const file = 'index.js';
let content = fs.readFileSync(file, 'utf8').replace(/\r\n/g, '\n');

const startMarker = "      // Await background verification (captcha + verify running since ID step)";
const endMarker = "      return;\n    }\n  } catch (error) {";

const startIndex = content.indexOf(startMarker);
const endIndex = content.indexOf(endMarker);

if (startIndex === -1 || endIndex === -1) {
    console.error("Markers not found! Start:", startIndex, "End:", endIndex);
    process.exit(1);
}

const before = content.slice(0, startIndex);
const after = content.slice(endIndex);

const newBlock = `      let timer;
      let otpPhaseStart = Date.now();

      try {
        // Await background verification (captcha + verify running since ID step)
        let verifyResult;
        if (pendingVerifications.has(userId)) {
          verifyResult = await pendingVerifications.get(userId);
          pendingVerifications.delete(userId);
        } else {
          // Safety fallback — should not happen in normal flow
          logger.error('No pending verification found for user', { userId });
          ctx.session = ctx.session || {}; ctx.session.step = null;
          activeDownloads.delete(userId);
          return ctx.reply('❌ Session expired. Please try /start again.');
        }

        if (!verifyResult.success) {
          ctx.session = ctx.session || {}; ctx.session.step = null;
          activeDownloads.delete(userId);
          const rawMsg = verifyResult.error || '';
          const userMsg = /too many|limit|wait/i.test(rawMsg)
            ? '⏳ Too many attempts. Please wait a few minutes before trying again.'
            : /invalid/i.test(rawMsg) ? '❌ Invalid ID. Please check and try again.'
              : '❌ Verification failed. Please try /start again.';
          return ctx.reply(userMsg);
        }

        // Verification succeeded — restore timer and continue with OTP validation
        timer = verifyResult.timer;
        state.tempJwt = verifyResult.token;
        state._timer = timer.toSession();

        otpPhaseStart = Date.now();
        if (state._timer?.flowStart) {
          const idPhaseEnd = (state._timer.flowStart || 0) + (state._timer.phaseTimings?.idPhaseMs || 0);
          timer.setPhase('userWaitMs', otpPhaseStart - idPhaseEnd);
        }

        await ctx.telegram.editMessageText(ctx.chat.id, status.message_id, null, "⏳ Verifying OTP...");
        const authHeader = { ...HEADERS, 'Authorization': \`Bearer \${state.tempJwt}\` };

        let otpResponse;
        let otpAttempts = 2;
        timer.startStep('otpValidation');
        for (let attempt = 1; attempt <= otpAttempts; attempt++) {
          try {
            otpResponse = await fayda.api.post('/validateOtp', {
              otp: validation.value,
              uniqueId: state.id,
              verificationMethod: state.verificationMethod || 'FCN'
            }, {
              headers: authHeader,
              timeout: 35000
            });
            break;
          } catch (e) {
            const isRetryable = !e.response || (e.response.status >= 500 && e.response.status < 600) || ['ECONNABORTED', 'ETIMEDOUT', 'ECONNRESET'].includes(e.code);
            if (attempt === otpAttempts || !isRetryable) throw e;
            logger.warn(\`validateOtp attempt \${attempt} failed, retrying\`, { error: e.message });
            await new Promise(r => setTimeout(r, 2000));
          }
        }
        timer.endStep('otpValidation');

        const { signature, uin, fullName } = otpResponse.data;
        if (!signature || !uin) {
          throw new Error('Missing signature or uin in OTP response');
        }

        // Non-blocking status update — PDF fetch starts immediately in parallel
        ctx.telegram.editMessageText(ctx.chat.id, status.message_id, null, "⏳ OTP verified! Fetching your ID...").catch(() => { });

        // Under heavy load (PREFER_QUEUE_PDF=true) skip sync and always queue for controlled concurrency
        let pdfSent = false;
        let lastSyncError;
        if (!PREFER_QUEUE_PDF) {
          for (let attempt = 1; attempt <= PDF_SYNC_ATTEMPTS && !pdfSent; attempt++) {
            // Cancel-aware: if session was cleared (e.g. /cancel), abort
            if (!ctx.session || ctx.session.step !== 'OTP') {
              logger.info('Download cancelled by user during PDF fetch');
              activeDownloads.delete(userId);
              return;
            }
            try {
              timer.startStep('pdfFetch');
              const pdfResponse = await fayda.api.post('/printableCredentialRoute', { uin, signature }, {
                headers: authHeader,
                responseType: 'text',
                timeout: 25000
              });
              timer.endStep('pdfFetch');

              timer.startStep('pdfConversion');
              const { buffer: pdfBuffer } = parsePdfResponse(pdfResponse.data);
              timer.endStep('pdfConversion');

              const safeName = (fullName?.eng || 'Fayda_Card').replace(/[^a-zA-Z0-9]/g, '_');
              const filename = \`\${safeName}.pdf\`;

              timer.startStep('telegramUpload');
              await ctx.replyWithDocument({
                source: pdfBuffer,
                filename: filename
              }, { caption: "✨ Your Digital ID is ready!" });
              timer.endStep('telegramUpload');

              await User.updateOne(
                { telegramId: userId },
                { $inc: { downloadCount: 1 }, $set: { lastDownload: new Date() } }
              );
              ctx.session = ctx.session || {}; ctx.session.step = null;
              activeDownloads.delete(userId);
              pdfSent = true;
            } catch (syncErr) {
              if (timer && typeof timer.endStep === 'function') {
                timer.endStep('pdfFetch');      // no-op if already ended
                timer.endStep('pdfConversion'); // no-op if not started
                timer.endStep('telegramUpload');
              }
              lastSyncError = syncErr;

              // 400 = session/token invalid — abort immediately, no point retrying
              const status4xx = syncErr.response?.status >= 400 && syncErr.response?.status < 500;
              if (status4xx) {
                logger.warn('PDF fetch returned 4xx, aborting', { status: syncErr.response?.status, error: syncErr.message });
                break; // skip to queue/failure path
              }

              if (attempt < PDF_SYNC_ATTEMPTS) {
                logger.warn(\`Sync PDF attempt \${attempt} failed, retrying\`, { error: syncErr.message });
                // Show user one clean message — no attempt counts
                await ctx.telegram.editMessageText(ctx.chat.id, status.message_id, null, "⏳ Please wait… processing your document.").catch(() => { });
                await new Promise(r => setTimeout(r, PDF_SYNC_RETRY_DELAY_MS));
              }
            }
          }
        }

        if (pdfSent) {
          timer.setPhase('otpPhaseMs', Date.now() - otpPhaseStart);
          timer.report('success');
        } else {
          // Sync failed (or PREFER_QUEUE_PDF) — enqueue for background retries
          try {
            const job = await pdfQueue.add({
              chatId: ctx.chat.id,
              userId: ctx.from.id.toString(),
              userRole: ctx.state.user?.role || 'user',
              authHeader,
              pdfPayload: { uin, signature },
              fullName,
              _timer: timer.toSession()
            }, {
              priority: 1,
              timeout: 60000
            });
            logger.info(\`PDF job \${job.id} queued (sync failed) for user \${ctx.from.id.toString()}\`);
          } catch (queueError) {
            logger.error('Queue add failed, trying sync once more:', queueError);
            await ctx.telegram.editMessageText(ctx.chat.id, status.message_id, null, "⏳ Processing PDF directly...");
            try {
              timer.startStep('pdfFetch');
              const pdfResponse = await fayda.api.post('/printableCredentialRoute', { uin, signature }, {
                headers: authHeader,
                responseType: 'text',
                timeout: 25000
              });
              timer.endStep('pdfFetch');

              timer.startStep('pdfConversion');
              const { buffer: pdfBuffer } = parsePdfResponse(pdfResponse.data);
              timer.endStep('pdfConversion');

              const safeName = (fullName?.eng || 'Fayda_Card').replace(/[^a-zA-Z0-9]/g, '_');

              timer.startStep('telegramUpload');
              await ctx.replyWithDocument({
                source: pdfBuffer,
                filename: \`\${safeName}.pdf\`
              }, { caption: "✨ Your Digital ID is ready!" });
              timer.endStep('telegramUpload');

              await User.updateOne(
                { telegramId: ctx.from.id.toString() },
                { $inc: { downloadCount: 1 }, $set: { lastDownload: new Date() } }
              );
              ctx.session = ctx.session || {}; ctx.session.step = null;
              activeDownloads.delete(userId);
              pdfSent = true;
              timer.setPhase('otpPhaseMs', Date.now() - otpPhaseStart);
              timer.report('success_after_queue_fallback');
            } catch (syncError2) {
              if (timer && typeof timer.endStep === 'function') {
                timer.endStep('pdfFetch');
                timer.endStep('pdfConversion');
                timer.endStep('telegramUpload');
              }
              logger.error('Synchronous PDF processing failed:', {
                error: syncError2.message,
                response: safeResponseForLog(syncError2.response?.data)
              });
              timer.setPhase('otpPhaseMs', Date.now() - otpPhaseStart);
              timer.report('failed');
              await ctx.reply('❌ Download failed. Please try /start again.');
              ctx.session = ctx.session || {}; ctx.session.step = null;
              activeDownloads.delete(userId);
            }
          }

          // Only show "queued" message if we didn't send PDF (queue was used)
          if (!pdfSent) {
            timer.setPhase('otpPhaseMs', Date.now() - otpPhaseStart);
            timer.report('queued');
            ctx.session = ctx.session || {}; ctx.session.step = null;
            activeDownloads.delete(userId);
            await ctx.reply('✅ Your request has been queued. You will receive your PDF shortly.');
          }
        }
      } catch (e) {
        if (timer && typeof timer.endStep === 'function') timer.endStep('otpValidation'); // end if still open
        logger.error("OTP/PDF Error:", {
          error: e.message,
          stack: e.stack,
          response: safeResponseForLog(e.response?.data)
        });
        if (timer && typeof timer.setPhase === 'function') timer.setPhase('otpPhaseMs', Date.now() - otpPhaseStart);
        if (timer && typeof timer.report === 'function') timer.report('failed');

        // Clean session on any error
        ctx.session = ctx.session || {}; ctx.session.step = null;
        activeDownloads.delete(userId);

        if (e.config?.url?.includes('/validateOtp')) {
          try {
            await ctx.telegram.editMessageText(ctx.chat.id, status.message_id, null, "❌ Wrong OTP.");
          } catch (_) {
            try { await ctx.reply("❌ Wrong OTP."); } catch (__) {}
          }
          // Restart the download flow to ask for ID again
          return handleDownload(ctx, false);
        } else {
          try {
            await ctx.reply(\`❌ Failed: \${e.response?.data?.message || e.message || 'Unknown error. Please try again.'}\`);
          } catch (replyError) {
            logger.error('Failed to send error message:', replyError);
          }
        }
      } finally {
        if (state) state.processingOTP = false;
      }
`;

fs.writeFileSync(file, before + newBlock + after);
console.log("Replacement successful.");
