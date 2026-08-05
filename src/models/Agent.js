const db = require('../database');

const Agent = {
    // Get all agents
  findAll: () => {
    return new Promise((resolve, reject) => {
        db.all('SELECT agentId, hostname, username, os, ipAddress, country, city, status, lastSeen, firstSeen FROM agents ORDER BY lastSeen DESC', (err, rows) => {
            if (err) reject(err);
            else resolve(rows);
        });
    });
},
    
    // Find agent by ID
    findOne: (agentId) => {
        return new Promise((resolve, reject) => {
            db.get('SELECT * FROM agents WHERE agentId = ?', [agentId], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });
    },


updateStatus: (agentId, status) => {
    return new Promise((resolve, reject) => {
        const sql = 'UPDATE agents SET status = ? WHERE agentId = ?';
        db.run(sql, [status, agentId], function(err) {
            if (err) reject(err);
            else resolve(this.changes > 0);
        });
    });
},    

    
    // Create or update agent
// In the upsert method, add the new fields:
upsert: (agentData) => {
    return new Promise((resolve, reject) => {
        const { 
            agentId, hostname, username, os, architecture, ipAddress, 
            country, city, isp, latitude, longitude, status
        } = agentData;
        
        const sql = `
            INSERT INTO agents (agentId, hostname, username, os, architecture, ipAddress, 
                                country, city, isp, latitude, longitude, status, lastSeen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(agentId) DO UPDATE SET
                lastSeen = CURRENT_TIMESTAMP,
                hostname = COALESCE(?, hostname),
                username = COALESCE(?, username),
                os = COALESCE(?, os),
                ipAddress = COALESCE(?, ipAddress),
                country = COALESCE(?, country),
                city = COALESCE(?, city),
                isp = COALESCE(?, isp),
                latitude = COALESCE(?, latitude),
                longitude = COALESCE(?, longitude),
                status = COALESCE(?, status)
        `;
        
        db.run(sql, [
            agentId, hostname, username, os, architecture, ipAddress,
            country, city, isp, latitude, longitude, status || 'active',
            hostname, username, os, ipAddress, country, city, isp, latitude, longitude, status || 'active'
        ], function(err) {
            if (err) {
                console.error('Upsert error:', err);
                reject(err);
            } else {
                resolve({ agentId, ...agentData });
            }
        });
    });
},
    
    // Update heartbeat
    updateHeartbeat: (agentId, metrics) => {
        return new Promise((resolve, reject) => {
            const sql = 'UPDATE agents SET lastSeen = CURRENT_TIMESTAMP, systemMetrics = ? WHERE agentId = ?';
            db.run(sql, [JSON.stringify(metrics || {}), agentId], (err) => {
                if (err) reject(err);
                else resolve();
            });
        });
    },
    
    // Update agent status
    updateStatus: (agentId, status) => {
        return new Promise((resolve, reject) => {
            const sql = 'UPDATE agents SET status = ? WHERE agentId = ?';
            db.run(sql, [status, agentId], (err) => {
                if (err) reject(err);
                else resolve();
            });
        });
    },
    
    // DELETE agent
    delete: (agentId) => {
        return new Promise((resolve, reject) => {
            db.run('DELETE FROM agents WHERE agentId = ?', [agentId], function(err) {
                if (err) reject(err);
                else resolve(this.changes > 0);
            });
        });
    },
    
    // UPDATE agent (rename, note, tags)
    update: (agentId, updates) => {
        return new Promise((resolve, reject) => {
            const fields = [];
            const values = [];
            
            if (updates.hostname !== undefined) {
                fields.push('hostname = ?');
                values.push(updates.hostname);
            }
            if (updates.note !== undefined) {
                fields.push('note = ?');
                values.push(updates.note);
            }
            if (updates.tags !== undefined) {
                fields.push('tags = ?');
                values.push(JSON.stringify(updates.tags));
            }
            
            if (fields.length === 0) {
                return resolve(false);
            }
            
            values.push(agentId);
            const sql = `UPDATE agents SET ${fields.join(', ')} WHERE agentId = ?`;
            
            db.run(sql, values, function(err) {
                if (err) reject(err);
                else resolve(this.changes > 0);
            });
        });
    }
};

module.exports = Agent;