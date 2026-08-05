const db = require('./src/database');

// Add new columns to agents table
db.serialize(() => {
    // Add country column
    db.run(`ALTER TABLE agents ADD COLUMN country TEXT DEFAULT 'Unknown'`, (err) => {
        if (err && !err.message.includes('duplicate column name')) {
            console.log('Added country column');
        }
    });
    
    // Add city column
    db.run(`ALTER TABLE agents ADD COLUMN city TEXT DEFAULT 'Unknown'`, (err) => {
        if (err && !err.message.includes('duplicate column name')) {
            console.log('Added city column');
        }
    });
    
    // Add isp column
    db.run(`ALTER TABLE agents ADD COLUMN isp TEXT DEFAULT 'Unknown'`, (err) => {
        if (err && !err.message.includes('duplicate column name')) {
            console.log('Added isp column');
        }
    });
    
    // Add latitude column
    db.run(`ALTER TABLE agents ADD COLUMN latitude REAL DEFAULT 0`, (err) => {
        if (err && !err.message.includes('duplicate column name')) {
            console.log('Added latitude column');
        }
    });
    
    // Add longitude column
    db.run(`ALTER TABLE agents ADD COLUMN longitude REAL DEFAULT 0`, (err) => {
        if (err && !err.message.includes('duplicate column name')) {
            console.log('Added longitude column');
        }
    });
    
    console.log('Database migration complete');
});