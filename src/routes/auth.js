const express = require('express');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const router = express.Router();

// Login - ONLY ADMIN ROLE CAN LOGIN
router.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        // Find user
        const user = await User.findOne({ username });
        
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // ─── RESTRICT TO ADMIN ONLY ──────────────────────────────────
        if (user.role !== 'admin') {
            return res.status(403).json({ 
                error: 'Access denied. Admin privileges required.' 
            });
        }
        // ──────────────────────────────────────────────────────────────
        
        // Compare password using bcrypt directly
        const bcrypt = require('bcrypt');
        const isValid = await bcrypt.compare(password, user.password);
        
        if (!isValid) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // Generate JWT token
        const token = jwt.sign(
            { userId: user.id, username: user.username, role: user.role },
            process.env.JWT_SECRET || 'default_secret_change_this',
            { expiresIn: '24h' }
        );
        
        // Update last login
        await User.updateLastLogin(username);
        
        res.json({ 
            token, 
            user: { 
                username: user.username, 
                role: user.role,
                apiKey: user.apiKey 
            } 
        });
        
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ─── AGENT LOGIN (FOR AGENT REGISTRATION ONLY) ──────────────────
router.post('/agent/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        // Find user
        const user = await User.findOne({ username });
        
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // ─── ALLOW AGENT ROLE ──────────────────────────────────────
        if (user.role !== 'agent') {
            return res.status(403).json({ 
                error: 'Access denied. Agent role required.' 
            });
        }
        // ──────────────────────────────────────────────────────────────
        
        // Compare password
        const bcrypt = require('bcrypt');
        const isValid = await bcrypt.compare(password, user.password);
        
        if (!isValid) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // Generate short-lived token for agent
        const token = jwt.sign(
            { userId: user.id, username: user.username, role: user.role },
            process.env.JWT_SECRET || 'default_secret_change_this',
            { expiresIn: '24h' }
        );
        
        res.json({ 
            token, 
            user: { 
                username: user.username, 
                role: user.role 
            } 
        });
        
    } catch (error) {
        console.error('Agent login error:', error);
        res.status(500).json({ error: error.message });
    }
});




// Verify token middleware
const verifyToken = (req, res, next) => {
    // in routes/auth.js, inside verifyToken:
    const authHeader = req.headers.authorization || '';
    const bearer = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
    const token = bearer || req.token || req.query.token;   // ← add req.token fallback
    if (!token) return res.status(401).json({ error: 'Unauthorized' });
    
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'default_secret_change_this');
        req.user = decoded;
        next();
    } catch (error) {
        res.status(401).json({ error: 'Invalid token' });
    }
};

// ─── ADMIN ONLY MIDDLEWARE ──────────────────────────────────────
const requireAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin privileges required' });
    }
    next();
};

// Verify endpoint
router.get('/verify', verifyToken, (req, res) => {
    res.json({ valid: true, user: req.user });
});

// Create test users (for development)
router.get('/create-test-users', async (req, res) => {
    try {
        const crypto = require('crypto');
        const bcrypt = require('bcrypt');
        
        // Create admin user if not exists
        const existingAdmin = await User.findOne({ username: 'admin' });
        if (!existingAdmin) {
            const hashedPassword = await bcrypt.hash('Damiboy1234', 10);
            await User.create({
                username: 'admin',
                password: hashedPassword,
                role: 'admin',
                apiKey: crypto.randomBytes(32).toString('hex')
            });
            console.log('✅ Admin user created');
        }
        
        // Create agent user if not exists
        const existingAgent = await User.findOne({ username: 'agent' });
        if (!existingAgent) {
            const hashedPassword = await bcrypt.hash('agent007', 10);
            await User.create({
                username: 'agent',
                password: hashedPassword,
                role: 'agent',
                apiKey: crypto.randomBytes(32).toString('hex')
            });
            console.log('✅ Agent user created');
        }
        
        res.json({ message: 'Test users created' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

module.exports = router;
module.exports.verifyToken = verifyToken;
module.exports.requireAdmin = requireAdmin;