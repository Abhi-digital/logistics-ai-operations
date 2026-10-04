const { Pool } = require('pg');

const connectionString = process.env.DATABASE_URL || 'postgresql://postgres:postgres@localhost:5432/routeiq';
const pool = new Pool({
  connectionString,
  max: Number(process.env.PG_POOL_MAX || 10),
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000
});

async function query(text, params = []) {
  return pool.query(text, params);
}

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('admin','operator','viewer')),
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS shipments (
      id TEXT PRIMARY KEY,
      tracking_id TEXT UNIQUE NOT NULL,
      origin TEXT NOT NULL,
      destination TEXT NOT NULL,
      current_location TEXT NOT NULL,
      carrier TEXT NOT NULL,
      status TEXT NOT NULL,
      eta TIMESTAMPTZ NOT NULL,
      sla TEXT NOT NULL,
      reason TEXT NOT NULL,
      priority TEXT NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL,
      timeline JSONB NOT NULL DEFAULT '[]'::jsonb
    );
    CREATE INDEX IF NOT EXISTS idx_shipments_status ON shipments(status);
    CREATE TABLE IF NOT EXISTS notifications (
      id TEXT PRIMARY KEY,
      shipment_id TEXT NOT NULL,
      channel TEXT NOT NULL,
      customer_name TEXT NOT NULL,
      customer_contact TEXT NOT NULL,
      subject TEXT NOT NULL,
      message TEXT NOT NULL,
      status TEXT NOT NULL,
      created_by TEXT NOT NULL,
      approved_by TEXT,
      sent_by TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      sent_at TIMESTAMPTZ
    );
    CREATE TABLE IF NOT EXISTS audit_events (
      id TEXT PRIMARY KEY,
      action TEXT NOT NULL,
      actor TEXT NOT NULL,
      target TEXT,
      details JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_notifications_created_at ON notifications(created_at DESC);
    CREATE TABLE IF NOT EXISTS automation_events (
      id TEXT PRIMARY KEY,
      shipment_id TEXT NOT NULL,
      event_type TEXT NOT NULL,
      event_key TEXT NOT NULL,
      status TEXT NOT NULL,
      reason TEXT,
      notification_id TEXT,
      details JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(shipment_id,event_type,event_key)
    );
    CREATE INDEX IF NOT EXISTS idx_automation_events_created_at ON automation_events(created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_automation_events_shipment ON automation_events(shipment_id);
    CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_events(created_at DESC);
    CREATE TABLE IF NOT EXISTS operations_team (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      shift TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
}

async function closeDb() {
  await pool.end();
}

module.exports = { pool, query, initDb, closeDb };
