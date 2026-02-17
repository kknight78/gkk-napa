-- G&KK NAPA SMS Marketing - D1 Schema
-- Database: gkk-napa-sms

-- ─── Customers ───────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS customers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  phone TEXT UNIQUE,                     -- E.164 format (+12175551234), NULL for email-only
  name TEXT,
  email TEXT,
  store TEXT,                            -- danville / cayuga / rockville / covington
  sms_status TEXT NOT NULL DEFAULT 'none', -- none → invited → subscribed → stopped
  sms_consent_at TEXT,                   -- ISO 8601 timestamp
  sms_stop_at TEXT,                      -- ISO 8601 timestamp
  invite_sent_at TEXT,                   -- ISO 8601 timestamp
  source TEXT NOT NULL DEFAULT 'import', -- import / web / admin
  notes TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_customers_store ON customers(store);
CREATE INDEX IF NOT EXISTS idx_customers_sms_status ON customers(sms_status);
CREATE INDEX IF NOT EXISTS idx_customers_phone ON customers(phone);
CREATE INDEX IF NOT EXISTS idx_customers_email ON customers(email);

-- ─── Campaigns ───────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS campaigns (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  body TEXT NOT NULL,
  store_filter TEXT,                     -- NULL = all stores
  recipient_count INTEGER NOT NULL DEFAULT 0,
  sent_count INTEGER NOT NULL DEFAULT 0,
  delivered_count INTEGER NOT NULL DEFAULT 0,
  failed_count INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ─── Messages ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  twilio_sid TEXT UNIQUE,
  customer_id INTEGER NOT NULL REFERENCES customers(id),
  campaign_id INTEGER REFERENCES campaigns(id),
  direction TEXT NOT NULL DEFAULT 'outbound', -- outbound / inbound
  body TEXT,
  status TEXT NOT NULL DEFAULT 'queued',      -- queued / sent / delivered / failed / undelivered
  error_code TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_messages_twilio_sid ON messages(twilio_sid);
CREATE INDEX IF NOT EXISTS idx_messages_campaign_id ON messages(campaign_id);
CREATE INDEX IF NOT EXISTS idx_messages_customer_id ON messages(customer_id);
