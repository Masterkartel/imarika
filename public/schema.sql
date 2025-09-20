-- ========= USERS =========
-- Columns expected by the worker: phone, full_name, id_number, account, wallet, invested, created_at
-- We also keep legacy aliases: full, idn (nullable)

CREATE TABLE IF NOT EXISTS users (
  phone       TEXT PRIMARY KEY,
  account     TEXT UNIQUE,                 -- issued automatically (e.g. IMK-XXXX-1234)
  full_name   TEXT,
  id_number   TEXT,
  -- legacy columns (kept for compatibility with any old UI code)
  full        TEXT,
  idn         TEXT,

  pass_hash   TEXT,                        -- optional (for future server-side auth)
  wallet      INTEGER DEFAULT 0,           -- store KES as integer shillings
  invested    INTEGER DEFAULT 0,
  created_at  INTEGER DEFAULT (strftime('%s','now'))  -- epoch seconds
);

CREATE INDEX IF NOT EXISTS idx_users_account ON users(account);


-- ========= ADMINS =========
-- Used by /api/admin/login and seeded by /api/admin/init

CREATE TABLE IF NOT EXISTS admins (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  phone       TEXT UNIQUE NOT NULL,
  pass_hash   TEXT NOT NULL,
  created_at  INTEGER DEFAULT (strftime('%s','now'))
);


-- ========= TRANSACTIONS =========
-- Matches the admin pending/approve/reject flows

CREATE TABLE IF NOT EXISTS tx (
  id          TEXT PRIMARY KEY,            -- ULID/uuid
  phone       TEXT NOT NULL,               -- references users.phone (not enforced)
  type        TEXT NOT NULL,               -- 'Deposit' | 'Withdrawal' | 'Investment'
  detail      TEXT,
  amount      INTEGER NOT NULL,            -- positive integer
  status      TEXT NOT NULL,               -- 'Pending' | 'Approved' | 'Rejected' | 'Requested'
  ts          INTEGER                      -- epoch ms
);

CREATE INDEX IF NOT EXISTS idx_tx_phone  ON tx(phone);
CREATE INDEX IF NOT EXISTS idx_tx_status ON tx(status);
