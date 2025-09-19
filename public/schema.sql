-- Users
CREATE TABLE IF NOT EXISTS users (
  phone TEXT PRIMARY KEY,
  account TEXT UNIQUE NOT NULL,
  full TEXT,
  idn TEXT,
  pass_hash TEXT,
  wallet INTEGER DEFAULT 0,
  invested INTEGER DEFAULT 0,
  created_at INTEGER
);

-- Transactions
CREATE TABLE IF NOT EXISTS tx (
  id TEXT PRIMARY KEY,
  phone TEXT NOT NULL,
  type TEXT NOT NULL,      -- 'Deposit' | 'Withdrawal' | 'Investment'
  amount INTEGER NOT NULL, -- positive numbers (store as cents if needed)
  detail TEXT,
  status TEXT NOT NULL,    -- 'Pending' | 'Approved' | 'Rejected' | 'Requested'
  ts INTEGER               -- epoch ms
);
CREATE INDEX IF NOT EXISTS tx_phone_idx ON tx(phone);
CREATE INDEX IF NOT EXISTS tx_status_idx ON tx(status);
