const express = require('express');
const fs = require('fs');
const path = require('path');
const Agent = require('../models/Agent');
const Task = require('../models/Task');
const { verifyToken } = require('./auth');
const router = express.Router();

// Get all agents with online/offline status
router.get('/', verifyToken, async (req, res) => {
    try {
        const agents = await Agent.findAll();
        
        const now = new Date();
        const updatedAgents = agents.map(agent => {
            const lastSeen = new Date(agent.lastSeen);
            const secondsSinceLastSeen = (now - lastSeen) / 1000;
            
            if (agent.status === 'active' && secondsSinceLastSeen > 60) {
                Agent.updateStatus(agent.agentId, 'offline');
                return { ...agent, status: 'offline' };
            }
            return agent;
        });
        
        res.json(updatedAgents);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Agent heartbeat - keep agent alive
router.post('/heartbeat', async (req, res) => {
    try {
        const { agentId, metrics } = req.body;
        
        console.log(`[Heartbeat] Received from agent: ${agentId}`);
        
        const db = require('../database');
        
        // Update the agent's lastSeen timestamp
        db.run(
            'UPDATE agents SET lastSeen = datetime("now"), status = "active" WHERE agentId = ?',
            [agentId],
            function(err) {
                if (err) {
                    console.error('Heartbeat update error:', err);
                    return res.status(500).json({ error: err.message });
                }
                
                if (this.changes === 0) {
                    console.log(`[Heartbeat] Agent not found: ${agentId}`);
                    return res.status(404).json({ error: 'Agent not found' });
                }
                
                console.log(`[Heartbeat] Updated agent: ${agentId}`);
                res.json({ status: 'ok', lastSeen: new Date().toISOString() });
            }
        );
    } catch (error) {
        console.error('Heartbeat error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Agent registration
router.post('/register', async (req, res) => {
    try {
        const { 
            hostname, username, os, architecture, agentId,
            ipAddress, country, city, isp, latitude, longitude
        } = req.body;
        
        console.log('[Registration] Received:', { hostname, username, ipAddress, country, city });
        
        const newAgentId = agentId || require('crypto').randomBytes(16).toString('hex');
        
        const agent = await Agent.upsert({
            agentId: newAgentId,
            hostname,
            username,
            os,
            architecture,
            ipAddress: ipAddress || req.ip,
            country: country || 'Unknown',
            city: city || 'Unknown',
            isp: isp || 'Unknown',
            latitude: latitude || 0,
            longitude: longitude || 0,
            status: 'active'
        });
        
        console.log(`[Agent] Registered: ${hostname} - IP: ${ipAddress} - Country: ${country}`);
        res.json({ agentId: newAgentId, message: 'Agent registered successfully' });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Test endpoint
router.get('/test', (req, res) => {
    res.json({ message: 'Agent routes are working!' });
});


// Serve PowerShell agent
router.get('/download-ps1', async (req, res) => {
    try {
        const fs = require('fs');
        const path = require('path');
        
        const possiblePaths = [
            path.join(__dirname, '../../agent/powershell_agent.ps1'),
            path.join(__dirname, '../agent/powershell_agent.ps1'),
            path.join(__dirname, '../../../agent/powershell_agent.ps1'),
            path.join(process.cwd(), 'agent/powershell_agent.ps1'),
        ];
        
        let agentPath = null;
        for (const p of possiblePaths) {
            if (fs.existsSync(p)) {
                agentPath = p;
                break;
            }
        }
        
        if (!agentPath) {
            return res.status(404).json({ error: 'PowerShell agent not found' });
        }
        
        const agentCode = fs.readFileSync(agentPath, 'utf8');
        
        res.setHeader('Content-Type', 'text/plain');
        res.setHeader('Content-Disposition', 'attachment; filename="agent.ps1"');
        res.send(agentCode);
        
    } catch (error) {
        console.error('PowerShell agent download error:', error);
        res.status(500).json({ error: error.message });
    }
});

// DOWNLOAD AGENT - Fixed endpoint
router.get('/download', async (req, res) => {
    try {
        const fs = require('fs');
        const path = require('path');
        
        // Try multiple possible paths
        const possiblePaths = [
            path.join(__dirname, '../../agent/agent.py'),
            path.join(__dirname, '../agent/agent.py'),
            path.join(__dirname, '../../../agent/agent.py'),
            path.join(process.cwd(), 'agent/agent.py'),
            path.join(process.cwd(), '../agent/agent.py'),
        ];
        
        let agentPath = null;
        for (const p of possiblePaths) {
            if (fs.existsSync(p)) {
                agentPath = p;
                break;
            }
        }
        
        if (!agentPath) {
            console.error('Agent file not found');
            return res.status(404).json({ error: 'Agent file not found' });
        }
        
        console.log(`Serving agent from: ${agentPath}`);
        const agentCode = fs.readFileSync(agentPath, 'utf8');
        
        res.setHeader('Content-Type', 'text/plain');
        res.setHeader('Content-Disposition', 'attachment; filename="agent.py"');
        res.send(agentCode);
        
    } catch (error) {
        console.error('Agent download error:', error);
        res.status(500).json({ error: error.message });
    }
});

// DELETE agent
router.delete('/:agentId', verifyToken, async (req, res) => {
    try {
        const { agentId } = req.params;
        await Task.deleteByAgent(agentId);
        const deleted = await Agent.delete(agentId);
        
        if (!deleted) {
            return res.status(404).json({ error: 'Agent not found' });
        }
        
        const io = req.app.get('io');
        if (io) {
            io.emit('agent_deleted', { agentId });
        }
        
        res.json({ message: 'Agent deleted successfully', agentId });
    } catch (error) {
        console.error('Delete agent error:', error);
        res.status(500).json({ error: error.message });
    }
});

// PUT agent - Rename/update agent
router.put('/:agentId', verifyToken, async (req, res) => {
    try {
        const { agentId } = req.params;
        const { hostname, note, tags } = req.body;
        
        const updated = await Agent.update(agentId, { hostname, note, tags });
        
        if (!updated) {
            return res.status(404).json({ error: 'Agent not found' });
        }
        
        const io = req.app.get('io');
        if (io) {
            io.emit('agent_updated', { agentId, hostname });
        }
        
        res.json({ message: 'Agent updated successfully', agentId, hostname });
    } catch (error) {
        console.error('Update agent error:', error);
        res.status(500).json({ error: error.message });
    }
});

module.exports = router;