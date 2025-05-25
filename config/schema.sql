-- config/schema.sql
-- SQL schema for the users table

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    reset_token TEXT,
    reset_token_expiry DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_verified INTEGER DEFAULT 0 NOT NULL, -- For email verification
    verification_token TEXT,                -- For email verification
    verification_token_expiry DATETIME,     -- For email verification
    last_password_change_at DATETIME      -- For password policy (e.g., preventing reuse)
);

-- Optional: Trigger to update 'updated_at' timestamp on row update
-- This syntax is for SQLite. Other databases might have different syntax.
/*
CREATE TRIGGER IF NOT EXISTS update_users_updated_at
AFTER UPDATE ON users
FOR EACH ROW
BEGIN
    UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE id = OLD.id;
END;
*/

-- Rate Limiting & Brute Force Protection
CREATE TABLE IF NOT EXISTS login_attempts (
    ip_address TEXT NOT NULL,
    last_attempt_at INTEGER NOT NULL, -- Unix timestamp
    attempts_count INTEGER NOT NULL,
    PRIMARY KEY (ip_address)
);

CREATE TABLE IF NOT EXISTS user_specific_attempts (
    user_id INTEGER NOT NULL,
    attempt_type TEXT NOT NULL, -- e.g., 'login', 'reset_password_request'
    last_attempt_at INTEGER NOT NULL, -- Unix timestamp
    attempts_count INTEGER NOT NULL,
    PRIMARY KEY (user_id, attempt_type),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Audit Trails
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER, -- Nullable for system events or unauthenticated user actions
    ip_address TEXT,
    event_type TEXT NOT NULL, -- e.g., USER_LOGIN_SUCCESS, PASSWORD_RESET_REQUEST
    details TEXT, -- Could be JSON or simple text
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_event_type ON audit_log(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);


-- Persistent Sessions for "Remember Me"
CREATE TABLE IF NOT EXISTS persistent_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    series_hash TEXT NOT NULL UNIQUE, -- To identify a series of tokens for a single device/browser
    token_hash TEXT NOT NULL,        -- The hashed current token for this series
    expires_at DATETIME NOT NULL,
    last_used_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    user_agent TEXT,                 -- Store user agent for potential security review
    ip_address TEXT,                 -- Store IP for potential security review
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_persistent_sessions_user_id ON persistent_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_persistent_sessions_series_hash ON persistent_sessions(series_hash);
