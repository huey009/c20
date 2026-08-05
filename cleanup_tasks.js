#!/usr/bin/env node
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const DB_PATH = path.join(__dirname, 'c2_framework.db');
const db = new sqlite3.Database(DB_PATH);

console.log('[TASK CLEANUP] Starting...');

db.serialize(() => {
    // Delete old completed/failed tasks (keep last 1 hour)
    db.run(
        "DELETE FROM tasks WHERE status IN ('completed', 'failed', 'error') AND createdAt < datetime('now', '-1 hour')",
        function(err) {
            if (err) {
                console.error(`Error: ${err.message}`);
            } else {
                console.log(`✅ Deleted ${this.changes} old completed/failed tasks`);
            }
        }
    );
    
    // Delete stuck pending tasks (older than 24 hours)
    db.run(
        "DELETE FROM tasks WHERE status = 'pending' AND createdAt < datetime('now', '-24 hours')",
        function(err) {
            if (err) {
                console.error(`Error: ${err.message}`);
            } else {
                console.log(`✅ Deleted ${this.changes} stuck pending tasks`);
            }
        }
    );
    
    // Vacuum to reclaim space
    db.run("VACUUM", function(err) {
        if (err) {
            console.error(`Vacuum error: ${err.message}`);
        } else {
            console.log('✅ Database vacuumed');
        }
    });
});

db.close(() => {
    console.log('[TASK CLEANUP] Complete!');
});
