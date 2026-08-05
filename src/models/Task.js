const db = require('../database');
const crypto = require('crypto');

const Task = {
    // Create new task
    create: (taskData) => {
        return new Promise((resolve, reject) => {
            const taskId = crypto.randomBytes(16).toString('hex');
            const { agentId, type, command, moduleName, moduleAction, moduleParams } = taskData;
            
            const sql = `
                INSERT INTO tasks (taskId, agentId, type, command, moduleName, moduleAction, moduleParams)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            `;
            
            const params = JSON.stringify(moduleParams || {});
            
            db.run(sql, [taskId, agentId, type, command, moduleName, moduleAction, params], 
                function(err) {
                    if (err) reject(err);
                    else resolve({ taskId, agentId, type, command, moduleName, moduleAction });
                });
        });
    },
    
    // Get pending tasks for agent
    findPendingByAgent: (agentId) => {
        return new Promise((resolve, reject) => {
            const sql = 'SELECT * FROM tasks WHERE agentId = ? AND status = "pending" ORDER BY createdAt ASC';
            db.all(sql, [agentId], (err, rows) => {
                if (err) reject(err);
                else {
                    const tasks = rows.map(task => ({
                        ...task,
                        moduleParams: task.moduleParams ? JSON.parse(task.moduleParams) : {}
                    }));
                    resolve(tasks);
                }
            });
        });
    },
    
    // Update task result
    updateResult: (taskId, result, error) => {
        return new Promise((resolve, reject) => {
            const sql = `
                UPDATE tasks 
                SET status = ?, result = ?, error = ?, completedAt = CURRENT_TIMESTAMP
                WHERE taskId = ?
            `;
            const status = error ? 'failed' : 'completed';
            const resultStr = JSON.stringify(result);
            
            db.run(sql, [status, resultStr, error, taskId], (err) => {
                if (err) reject(err);
                else resolve({ success: true });
            });
        });
    },
    
    // Get all tasks
    findAll: () => {
        return new Promise((resolve, reject) => {
            const sql = 'SELECT * FROM tasks ORDER BY createdAt DESC';
            db.all(sql, [], (err, rows) => {
                if (err) reject(err);
                else resolve(rows);
            });
        });
    },
    
    // Get tasks by agent
    findByAgent: (agentId) => {
        return new Promise((resolve, reject) => {
            const sql = 'SELECT * FROM tasks WHERE agentId = ? ORDER BY createdAt DESC';
            db.all(sql, [agentId], (err, rows) => {
                if (err) reject(err);
                else resolve(rows);
            });
        });
    },
    
    // Delete tasks by agent
    deleteByAgent: (agentId) => {
        return new Promise((resolve, reject) => {
            db.run('DELETE FROM tasks WHERE agentId = ?', [agentId], function(err) {
                if (err) reject(err);
                else resolve(this.changes);
            });
        });
    },
    
    // Cancel all pending tasks (optionally for specific agent)
    cancelPending: (agentId) => {
        return new Promise((resolve, reject) => {
            let sql = 'UPDATE tasks SET status = "cancelled", error = "Cancelled by operator" WHERE status = "pending"';
            const params = [];
            
            if (agentId) {
                sql += ' AND agentId = ?';
                params.push(agentId);
            }
            
            db.run(sql, params, function(err) {
                if (err) reject(err);
                else resolve(this.changes);
            });
        });
    },
    
    // Cancel specific task
    cancel: (taskId) => {
        return new Promise((resolve, reject) => {
            const sql = 'UPDATE tasks SET status = "cancelled", error = "Cancelled by operator" WHERE taskId = ? AND status = "pending"';
            db.run(sql, [taskId], function(err) {
                if (err) reject(err);
                else resolve(this.changes > 0);
            });
        });
    }
};

module.exports = Task;