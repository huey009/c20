const db = require('../database');

function startCleanupJob() {
    console.log('[Cleanup] Starting agent status monitoring...');
    
    setInterval(() => {
        const now = new Date();
        
        // Mark agents as offline if no heartbeat for 60 seconds
        db.run(
            `UPDATE agents SET status = 'offline' 
             WHERE lastSeen < datetime('now', '-60 seconds') 
             AND status = 'active'`,
            function(err) {
                if (err) {
                    console.error('[Cleanup] Error:', err.message);
                } else if (this.changes > 0) {
                    console.log(`[Cleanup] Marked ${this.changes} agent(s) as offline`);
                    
                    // Cancel pending tasks for agents that just went offline
                    db.run(
                        `UPDATE tasks SET status = 'cancelled', error = 'Agent offline' 
                         WHERE status = 'pending' 
                         AND agentId IN (SELECT agentId FROM agents WHERE status = 'offline')`,
                        function(err2) {
                            if (err2) {
                                console.error('[Cleanup] Task error:', err2.message);
                            } else if (this.changes > 0) {
                                console.log(`[Cleanup] Cancelled ${this.changes} pending task(s)`);
                            }
                        }
                    );
                }
            }
        );
    }, 30000); // Check every 30 seconds
}

module.exports = { startCleanupJob };