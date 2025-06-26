-- BCash Security Upgrade Migration - D1/SQLite Compatible
-- Version 4.0 - Säkerhetsförbättringar

-- Add security-related columns (safe for SQLite)
ALTER TABLE auth_logs ADD COLUMN severity TEXT DEFAULT 'info';
ALTER TABLE auth_logs ADD COLUMN details TEXT;

-- Add session tracking table
CREATE TABLE IF NOT EXISTS user_sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  user_type TEXT NOT NULL,
  session_token TEXT UNIQUE NOT NULL,
  ip_address TEXT,
  user_agent TEXT,
  created_at TEXT NOT NULL,
  last_active TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  is_active BOOLEAN DEFAULT 1,
  FOREIGN KEY (user_id) REFERENCES children (id) ON DELETE CASCADE
);

-- Add audit log table for all important actions
CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  user_type TEXT,
  action TEXT NOT NULL,
  resource_type TEXT,
  resource_id INTEGER,
  old_values TEXT, -- JSON
  new_values TEXT, -- JSON
  ip_address TEXT,
  user_agent TEXT,
  created_at TEXT NOT NULL
);

-- Add security configuration table
CREATE TABLE IF NOT EXISTS security_config (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  config_key TEXT UNIQUE NOT NULL,
  config_value TEXT NOT NULL,
  description TEXT,
  updated_at TEXT NOT NULL
);

-- Insert default security settings with current timestamp
INSERT OR REPLACE INTO security_config (config_key, config_value, description, updated_at) VALUES
('max_login_attempts', '5', 'Maximalt antal inloggningsförsök', datetime('now')),
('lockout_duration_minutes', '15', 'Antal minuter kontot låses efter misslyckade försök', datetime('now')),
('session_timeout_hours', '24', 'Antal timmar innan session löper ut', datetime('now')),
('require_password_change_days', '90', 'Antal dagar innan lösenordsbyte krävs', datetime('now')),
('min_password_length', '8', 'Minsta lösenordslängd', datetime('now')),
('password_history_count', '5', 'Antal gamla lösenord att komma ihåg', datetime('now'));

-- Add password history table
CREATE TABLE IF NOT EXISTS password_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  user_type TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES parents (id) ON DELETE CASCADE
);

-- Add additional security columns to users (use NULL default for datetime)
ALTER TABLE children ADD COLUMN password_changed_at TEXT;
ALTER TABLE children ADD COLUMN require_password_change BOOLEAN DEFAULT 0;
ALTER TABLE children ADD COLUMN two_factor_enabled BOOLEAN DEFAULT 0;

ALTER TABLE parents ADD COLUMN password_changed_at TEXT;
ALTER TABLE parents ADD COLUMN require_password_change BOOLEAN DEFAULT 0;
ALTER TABLE parents ADD COLUMN two_factor_enabled BOOLEAN DEFAULT 0;
ALTER TABLE parents ADD COLUMN two_factor_secret TEXT;

-- Set current timestamp for existing users
UPDATE children SET password_changed_at = datetime('now') WHERE password_changed_at IS NULL;
UPDATE parents SET password_changed_at = datetime('now') WHERE password_changed_at IS NULL;

-- Add financial limits and controls
CREATE TABLE IF NOT EXISTS transaction_limits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  child_id INTEGER NOT NULL,
  daily_spending_limit INTEGER DEFAULT 0,    -- in öre
  weekly_spending_limit INTEGER DEFAULT 0,   -- in öre
  monthly_spending_limit INTEGER DEFAULT 0,  -- in öre
  requires_parent_approval_above INTEGER DEFAULT 5000, -- in öre (50kr)
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (child_id) REFERENCES children (id) ON DELETE CASCADE
);

-- Add pending transactions table for approval workflow
CREATE TABLE IF NOT EXISTS pending_transactions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  child_id INTEGER NOT NULL,
  amount INTEGER NOT NULL,
  description TEXT NOT NULL,
  type TEXT NOT NULL,
  requested_by INTEGER NOT NULL,
  requires_approval_from INTEGER,
  status TEXT DEFAULT 'pending', -- pending, approved, rejected
  created_at TEXT NOT NULL,
  processed_at TEXT,
  FOREIGN KEY (child_id) REFERENCES children (id) ON DELETE CASCADE,
  FOREIGN KEY (requested_by) REFERENCES children (id),
  FOREIGN KEY (requires_approval_from) REFERENCES parents (id)
);

-- Add indexes for performance
CREATE INDEX IF NOT EXISTS idx_user_sessions_token ON user_sessions(session_token);
CREATE INDEX IF NOT EXISTS idx_user_sessions_user ON user_sessions(user_id, user_type);
CREATE INDEX IF NOT EXISTS idx_user_sessions_active ON user_sessions(is_active, expires_at);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user_id, user_type);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_password_history_user ON password_history(user_id, user_type);
CREATE INDEX IF NOT EXISTS idx_transaction_limits_child ON transaction_limits(child_id);
CREATE INDEX IF NOT EXISTS idx_pending_transactions_child ON pending_transactions(child_id);
CREATE INDEX IF NOT EXISTS idx_pending_transactions_status ON pending_transactions(status);

-- Log this upgrade
INSERT INTO health_checks (check_type, status, details) VALUES
('security_upgrade', 'completed', 'BCash v4.0 security features installed successfully'); 