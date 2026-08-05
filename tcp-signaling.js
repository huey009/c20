const net = require('net');

// Map sessionId -> TCP socket (host)
const hostSockets = new Map();

function startTcpSignaling(wss, rooms, pendingOffers, port = 9001) {
    const server = net.createServer((socket) => {
        let sessionId = null;
        let buffer = '';
        let socketClosed = false;

        console.log(`[TCP] New client connection from ${socket.remoteAddress}:${socket.remotePort}`);

        socket.on('error', (err) => {
            if (!socketClosed) {
                console.error(`[TCP] Socket error for ${sessionId || 'unknown'}:`, err.code, err.message);
                socketClosed = true;
            }
        });

        socket.on('data', (data) => {
            if (socketClosed) return;

            try {
                buffer += data.toString();
                let lines = buffer.split('\n');
                buffer = lines.pop();

                for (const line of lines) {
                    if (!line.trim()) continue;
                    try {
                        const msg = JSON.parse(line);
                        handleMessage(socket, msg);
                    } catch (err) {
                        console.error('[TCP] Parse error:', err.message);
                    }
                }
            } catch (err) {
                console.error('[TCP] Data handling error:', err.message);
            }
        });

        function handleMessage(socket, msg) {
            try {
                const type = msg.type;

                if (type === 'host') {
                    sessionId = msg.session_id;
                    socket.sessionId = sessionId;
                    hostSockets.set(sessionId, socket);
                    console.log(`[TCP] ✅ Host registered: ${sessionId}`);

                    // Check if viewer already waiting
                    if (rooms && rooms[sessionId] && rooms[sessionId].viewer) {
                        try {
                            socket.write(JSON.stringify({ type: 'viewer_ready' }) + '\n');
                            console.log(`[TCP] ✅ Viewer already connected for ${sessionId}`);
                        } catch (writeErr) {
                            console.error(`[TCP] Failed to send viewer_ready:`, writeErr.message);
                        }
                    } else {
                        console.log(`[TCP] ⏳ Waiting for viewer to connect for ${sessionId}`);
                    }
                } else if (type === 'offer' || type === 'ice_candidate') {
                    // ✅ If viewer is connected, forward immediately
                    if (rooms && rooms[sessionId] && rooms[sessionId].viewer) {
                        const viewer = rooms[sessionId].viewer;
                        if (viewer.readyState === 1) { // WebSocket.OPEN
                            try {
                                viewer.send(JSON.stringify(msg));
                                console.log(`[TCP] ✅ Forwarded ${type} to viewer ${sessionId}`);
                            } catch (sendErr) {
                                console.error(`[TCP] Failed to forward ${type}:`, sendErr.message);
                            }
                        } else {
                            console.log(`[TCP] ⚠️  Viewer WebSocket not ready (state: ${viewer.readyState})`);
                            // Store it anyway if not ready
                            if (pendingOffers) {
                                pendingOffers[sessionId] = msg;
                                console.log(`[TCP] 📦 Queued ${type} for ${sessionId} (viewer not ready)`);
                            }
                        }
                    } else {
                        // ✅ Viewer not connected — store the offer in pendingOffers
                        if (pendingOffers) {
                            // Store only the latest offer per session
                            pendingOffers[sessionId] = msg;
                            console.log(`[TCP] 📦 Queued ${type} for ${sessionId} (no viewer)`);
                        } else {
                            console.log(`[TCP] ⚠️  No pendingOffers map, dropping ${type} for ${sessionId}`);
                        }
                    }
                }
            } catch (err) {
                console.error('[TCP] Message handling error:', err.message);
            }
        }

        socket.on('close', () => {
            socketClosed = true;
            if (sessionId) {
                hostSockets.delete(sessionId);
                // Clean up pending offers for this session
                if (pendingOffers && pendingOffers[sessionId]) {
                    delete pendingOffers[sessionId];
                    console.log(`[TCP] 🧹 Cleared pending offer for ${sessionId}`);
                }
                console.log(`[TCP] ✅ Host ${sessionId} disconnected`);
            } else {
                console.log(`[TCP] Client disconnected (no session)`);
            }
        });

        socket.on('end', () => {
            socketClosed = true;
            console.log(`[TCP] Client ended connection`);
        });
    });

    server.on('error', (err) => {
        if (err.code === 'EADDRINUSE') {
            console.error(`[TCP] ❌ Port ${port} is already in use`);
        } else {
            console.error(`[TCP] ❌ Server error:`, err.message);
        }
    });

    server.listen(port, '0.0.0.0', () => {
        console.log(`[TCP] ✅ Signaling server listening on port ${port}`);
    });

    // Function to trigger viewer_ready from WebSocket side
    const triggerViewerReady = (sessionId) => {
        const hostSocket = hostSockets.get(sessionId);
        if (hostSocket && hostSocket.writable) {
            try {
                hostSocket.write(JSON.stringify({ type: 'viewer_ready' }) + '\n');
                console.log(`[TCP] ✅ Triggered viewer_ready for ${sessionId} from WebSocket`);
            } catch (err) {
                console.error(`[TCP] Failed to trigger viewer_ready:`, err.message);
                hostSockets.delete(sessionId);
            }
        } else {
            console.log(`[TCP] ⚠️  No writable host socket for ${sessionId}`);
        }
    };

    // Function to forward messages from WebSocket to TCP host
    const forwardToHost = (sessionId, msg) => {
        const hostSocket = hostSockets.get(sessionId);
        if (hostSocket && hostSocket.writable) {
            try {
                hostSocket.write(JSON.stringify(msg) + '\n');
                console.log(`[TCP] ✅ Forwarded to host ${sessionId}: ${msg.type}`);
            } catch (err) {
                console.error(`[TCP] Failed to forward to host:`, err.message);
                hostSockets.delete(sessionId);
            }
        } else {
            console.log(`[TCP] ⚠️  No writable host socket for ${sessionId}`);
        }
    };

    return { triggerViewerReady, forwardToHost };
}

module.exports = { startTcpSignaling, hostSockets };