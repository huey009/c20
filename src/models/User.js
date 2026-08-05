const db = require('../database');
const bcrypt = require('bcrypt');

const User = {
    // Find user by username
    findOne: (query) => {
        return new Promise((resolve, reject) => {
            const sql = 'SELECT * FROM users WHERE username = ?';
            db.get(sql, [query.username], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });
    },
    
    // Find user by API key
    findByApiKey: (apiKey) => {
        return new Promise((resolve, reject) => {
            const sql = 'SELECT * FROM users WHERE apiKey = ?';
            db.get(sql, [apiKey], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });
    },
    
    // Create new user
    create: async (userData) => {
        const { username, password, role, apiKey } = userData;
        const hashedPassword = await bcrypt.hash(password, 10);
        
        return new Promise((resolve, reject) => {
            const sql = 'INSERT INTO users (username, password, role, apiKey) VALUES (?, ?, ?, ?)';
            db.run(sql, [username, hashedPassword, role, apiKey], function(err) {
                if (err) reject(err);
                else resolve({ id: this.lastID, username, role, apiKey });
            });
        });
    },
    
    // Update last login
    updateLastLogin: (username) => {
        return new Promise((resolve, reject) => {
            const sql = 'UPDATE users SET lastLogin = CURRENT_TIMESTAMP WHERE username = ?';
            db.run(sql, [username], (err) => {
                if (err) reject(err);
                else resolve();
            });
        });
    },
    
    // Validate password (instance method equivalent)
    validatePassword: async (user, plainPassword) => {
        if (!user || !user.password) return false;
        return bcrypt.compare(plainPassword, user.password);
    }
};

// Also add a method to the user object when retrieved
// This wraps the user object with a comparePassword method
const wrapUserWithMethods = (user) => {
    if (!user) return null;
    return {
        ...user,
        comparePassword: async (plainPassword) => {
            return bcrypt.compare(plainPassword, user.password);
        }
    };
};

module.exports = User;
module.exports.wrapUserWithMethods = wrapUserWithMethods;