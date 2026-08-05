const express = require('express');
const db = require('../database');
const { verifyToken } = require('./auth');
const router = express.Router();

// ─── Helper: parse params from JSON string or return empty object ──
function parseParams(paramsStr) {
    if (!paramsStr) return {};
    try {
        const parsed = JSON.parse(paramsStr);
        return typeof parsed === 'object' && parsed !== null ? parsed : {};
    } catch (e) {
        return {};
    }
}

// ─── Get all tasks ──────────────────────────────────────────────
router.get('/', verifyToken, async (req, res) => {
    try {
        const tasks = await new Promise((resolve, reject) => {
            db.all('SELECT * FROM tasks ORDER BY createdAt DESC', (err, rows) => {
                if (err) reject(err);
                else resolve(rows || []);
            });
        });
        const parsedTasks = tasks.map(task => ({
            ...task,
            params: parseParams(task.params)
        }));
        res.json(parsedTasks);
    } catch (error) {
        console.error('Get tasks error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ─── Get tasks for a specific agent ─────────────────────────────
router.get('/agent/:agentId', verifyToken, async (req, res) => {
    try {
        const { agentId } = req.params;
        const tasks = await new Promise((resolve, reject) => {
            db.all('SELECT * FROM tasks WHERE agentId = ? ORDER BY createdAt DESC', [agentId], (err, rows) => {
                if (err) reject(err);
                else resolve(rows || []);
            });
        });
        const parsedTasks = tasks.map(task => ({
            ...task,
            params: parseParams(task.params)
        }));
        res.json(parsedTasks);
    } catch (error) {
        console.error('Get agent tasks error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ─── Get pending tasks for an agent (used by agent) ────────────
router.get('/pending/:agentId', verifyToken, async (req, res) => {
    try {
        const { agentId } = req.params;
        const tasks = await new Promise((resolve, reject) => {
            db.all('SELECT * FROM tasks WHERE agentId = ? AND status = "pending" ORDER BY createdAt ASC', [agentId], (err, rows) => {
                if (err) reject(err);
                else resolve(rows || []);
            });
        });
        // ─── CRITICAL: Parse params for each task ──────────────────────
        const parsedTasks = tasks.map(task => ({
            ...task,
            params: parseParams(task.params)
        }));
        res.json(parsedTasks);
    } catch (error) {
        console.error('Get pending tasks error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ─── Delete all pending tasks (optionally by agentId) ──────────
router.delete('/pending', verifyToken, async (req, res) => {
    try {
        const { agentId } = req.query;
        let sql = 'DELETE FROM tasks WHERE status = "pending"';
        const params = [];
        if (agentId) {
            sql += ' AND agentId = ?';
            params.push(agentId);
        }
        db.run(sql, params, function(err) {
            if (err) {
                console.error('Delete pending tasks error:', err);
                return res.status(500).json({ error: err.message });
            }
            res.json({ 
                success: true, 
                deletedCount: this.changes,
                message: `Deleted ${this.changes} pending task(s)${agentId ? ` for agent ${agentId}` : ''}`
            });
        });
    } catch (error) {
        console.error('Delete pending tasks error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ─── Create a new task ──────────────────────────────────────────
router.post('/', verifyToken, async (req, res) => {
    try {
        // Accept both 'params' and 'moduleParams' for flexibility
        const { agentId, type, command, moduleName, moduleAction, params, moduleParams } = req.body;
        
        if (!agentId) {
            return res.status(400).json({ error: 'agentId required' });
        }
        
        const taskId = `${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        
        // Determine the params to store (prefer 'params' if provided, else fallback to 'moduleParams')
        let taskParams = null;
        if (params && typeof params === 'object' && Object.keys(params).length > 0) {
            taskParams = params;
        } else if (moduleParams && typeof moduleParams === 'object' && Object.keys(moduleParams).length > 0) {
            taskParams = moduleParams;
        }
        
        const sql = `
            INSERT INTO tasks (taskId, agentId, type, command, moduleName, moduleAction, params, status, createdAt)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', datetime('now'))
        `;
        
        db.run(sql, [
            taskId,
            agentId,
            type || 'module',
            command || null,
            moduleName || null,
            moduleAction || null,
            taskParams ? JSON.stringify(taskParams) : null   // store as JSON string
        ], function(err) {
            if (err) {
                console.error('Create task error:', err);
                return res.status(500).json({ error: err.message });
            }
            res.json({ success: true, taskId: taskId, message: 'Task created successfully' });
        });
        
    } catch (error) {
        console.error('Create task error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ─── Update task status ─────────────────────────────────────────
router.put('/:taskId', verifyToken, async (req, res) => {
    try {
        const { taskId } = req.params;
        const { status, result, error } = req.body;
        
        let sql = 'UPDATE tasks SET status = ?, updatedAt = datetime("now")';
        const params = [status];
        
        if (result !== undefined) {
            sql += ', result = ?';
            params.push(typeof result === 'string' ? result : JSON.stringify(result));
        }
        
        if (error !== undefined) {
            sql += ', error = ?';
            params.push(error);
        }
        
        sql += ' WHERE taskId = ?';
        params.push(taskId);
        
        db.run(sql, params, function(err) {
            if (err) {
                console.error('Update task error:', err);
                return res.status(500).json({ error: err.message });
            }
            res.json({ success: true });
        });
        
    } catch (error) {
        console.error('Update task error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ─── Delete task ─────────────────────────────────────────────────
router.delete('/:taskId', verifyToken, async (req, res) => {
    try {
        const { taskId } = req.params;
        db.run('DELETE FROM tasks WHERE taskId = ?', [taskId], function(err) {
            if (err) {
                console.error('Delete task error:', err);
                return res.status(500).json({ error: err.message });
            }
            res.json({ success: true });
        });
    } catch (error) {
        console.error('Delete task error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ─── Get a single task by ID ────────────────────────────────────
router.get('/:taskId', verifyToken, async (req, res) => {
    try {
        const { taskId } = req.params;
        const task = await new Promise((resolve, reject) => {
            db.get('SELECT * FROM tasks WHERE taskId = ?', [taskId], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });
        if (!task) {
            return res.status(404).json({ error: 'Task not found' });
        }
        const parsedTask = {
            ...task,
            params: parseParams(task.params)
        };
        res.json(parsedTask);
    } catch (error) {
        console.error('Get task error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ─── Update task result endpoint ─────────────────────────────────
router.post('/result', verifyToken, async (req, res) => {
    const { taskId, result, error } = req.body;
    const status = error ? 'failed' : 'completed';
    let resultStr = result;
    if (typeof result === 'object') {
        resultStr = JSON.stringify(result);
    }
    db.run(
        `UPDATE tasks SET status = ?, result = ?, error = ?, completedAt = datetime('now') WHERE taskId = ?`,
        [status, resultStr, error, taskId],
        function(err) {
            if (err) {
                console.error('Update task error:', err);
                return res.status(500).json({ error: err.message });
            }
            res.json({ success: true });
        }
    );
});

// ─── Test endpoint ──────────────────────────────────────────────
router.get('/test', verifyToken, (req, res) => {
    res.json({ message: 'Tasks route is working!' });
});

module.exports = router;