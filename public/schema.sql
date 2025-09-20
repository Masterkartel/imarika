-- ========= USERS =========
CREATE TABLE IF NOT EXISTS users (
  phone       TEXT PRIMARY KEY,
  account     TEXT UNIQUE NOT NULL,
  full_name   TEXT,
  id_number   TEXT,
  pass_hash   TEXT,
  wallet      INTEGER DEFAULT 0,
  invested    INTEGER DEFAULT 0,
  created_at  INTEGER DEFAULT (strftime('%s','now'))
);

CREATE INDEX IF NOT EXISTS idx_users_account ON users(account);


-- ========= ADMINS =========
CREATE TABLE IF NOT EXISTS admins (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  phone       TEXT UNIQUE NOT NULL,
  pass_hash   TEXT NOT NULL,
  created_at  INTEGER DEFAULT (strftime('%s','now'))
);


-- ========= TRANSACTIONS =========
CREATE TABLE IF NOT EXISTS tx (
  id          TEXT PRIMARY KEY,
  phone       TEXT NOT NULL,
  type        TEXT NOT NULL,
  detail      TEXT,
  amount      INTEGER NOT NULL,
  status      TEXT NOT NULL,
  ts          INTEGER
);

CREATE INDEX IF NOT EXISTS idx_tx_phone  ON tx(phone);
CREATE INDEX IF NOT EXISTS idx_tx_status ON tx(status);
