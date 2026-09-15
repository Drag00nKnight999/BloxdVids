import pg from 'pg';
import bcrypt from 'bcryptjs';

const { Pool } = pg;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes('localhost') ? false : { rejectUnauthorized: false },
});

export default pool;

export async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(50) UNIQUE NOT NULL,
      email VARCHAR(320),
      password_hash VARCHAR(255) NOT NULL,
      role VARCHAR(30) NOT NULL DEFAULT 'user',
      preview_mode BOOLEAN NOT NULL DEFAULT TRUE,
      banned BOOLEAN NOT NULL DEFAULT FALSE,
      ban_until TIMESTAMPTZ,
      ban_reason TEXT,
      restricted BOOLEAN NOT NULL DEFAULT FALSE,
      restriction_until TIMESTAMPTZ,
      restriction_type VARCHAR(30),
      restriction_reason TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS videos (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title VARCHAR(255) NOT NULL,
      description TEXT DEFAULT '',
      storage_key VARCHAR(500) NOT NULL,
      thumbnail_key VARCHAR(500),
      thumbnail_mime_type VARCHAR(100),
      mime_type VARCHAR(100) NOT NULL,
      file_size BIGINT NOT NULL,
      duration_seconds INTEGER,
      view_count INTEGER DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_videos_user_id ON videos(user_id);
    CREATE INDEX IF NOT EXISTS idx_videos_created_at ON videos(created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_videos_title ON videos USING gin(to_tsvector('english', title || ' ' || COALESCE(description, '')));
    CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_lower ON users (LOWER(username));
    ALTER TABLE users ADD COLUMN IF NOT EXISTS email VARCHAR(320);
    CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_lower ON users (LOWER(email)) WHERE email IS NOT NULL;
    ALTER TABLE users ALTER COLUMN role TYPE VARCHAR(30);
    ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(30) NOT NULL DEFAULT 'user';
    ALTER TABLE users ADD COLUMN IF NOT EXISTS preview_mode BOOLEAN NOT NULL DEFAULT TRUE;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS banned BOOLEAN NOT NULL DEFAULT FALSE;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS ban_until TIMESTAMPTZ;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS ban_reason TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS restricted BOOLEAN NOT NULL DEFAULT FALSE;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS restriction_until TIMESTAMPTZ;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS restriction_type VARCHAR(30);
    ALTER TABLE users ADD COLUMN IF NOT EXISTS restriction_reason TEXT;
    ALTER TABLE videos ADD COLUMN IF NOT EXISTS thumbnail_mime_type VARCHAR(100);

    CREATE TABLE IF NOT EXISTS channels (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
      handle VARCHAR(30) NOT NULL UNIQUE,
      name VARCHAR(100) NOT NULL,
      description VARCHAR(1000) NOT NULL DEFAULT '',
      subscriber_count INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_channels_handle_lower ON channels (LOWER(handle));

    CREATE TABLE IF NOT EXISTS subscriptions (
      subscriber_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      channel_id INTEGER NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      PRIMARY KEY (subscriber_id, channel_id)
    );
    CREATE INDEX IF NOT EXISTS idx_subscriptions_channel ON subscriptions(channel_id);

    CREATE TABLE IF NOT EXISTS reports (
      id SERIAL PRIMARY KEY,
      reporter_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      reported_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      video_id INTEGER REFERENCES videos(id) ON DELETE SET NULL,
      category VARCHAR(40) NOT NULL,
      details TEXT NOT NULL,
      status VARCHAR(20) NOT NULL DEFAULT 'open',
      resolution_note TEXT,
      reviewed_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW(),
      CHECK (reported_user_id IS NOT NULL OR video_id IS NOT NULL)
    );
    CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status, created_at DESC);

    CREATE TABLE IF NOT EXISTS appeals (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      reason TEXT NOT NULL,
      status VARCHAR(20) NOT NULL DEFAULT 'open',
      reviewer_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      decision_note TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_appeals_status ON appeals(status, created_at DESC);

    CREATE TABLE IF NOT EXISTS bug_reports (
      id SERIAL PRIMARY KEY,
      reporter_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      title VARCHAR(200) NOT NULL,
      description TEXT NOT NULL,
      steps_to_reproduce TEXT DEFAULT '',
      severity VARCHAR(20) NOT NULL DEFAULT 'normal',
      status VARCHAR(20) NOT NULL DEFAULT 'open',
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_bug_reports_status ON bug_reports(status, created_at DESC);

    CREATE TABLE IF NOT EXISTS crash_logs (
      id SERIAL PRIMARY KEY,
      reporter_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      message VARCHAR(500) NOT NULL,
      stack TEXT DEFAULT '',
      page_url VARCHAR(1000) DEFAULT '',
      user_agent VARCHAR(500) DEFAULT '',
      metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_crash_logs_created_at ON crash_logs(created_at DESC);
  `);

  await seedOwnerAccount();
}

async function seedOwnerAccount() {
  const ownerUsername = 'Drag00nKnight';
  const ownerPassword = process.env.OWNER_PASSWORD;
  if (!ownerPassword) {
    throw new Error('OWNER_PASSWORD must be configured before starting BloxdVids');
  }

  const existing = await pool.query(
    'SELECT id FROM users WHERE LOWER(username) = LOWER($1) LIMIT 1',
    [ownerUsername]
  );

  if (existing.rows[0]) {
    await pool.query(
      'UPDATE users SET username = $1, role = $2 WHERE id = $3',
      [ownerUsername, 'owner', existing.rows[0].id]
    );
    await ensureChannel(existing.rows[0].id, ownerUsername);
    return;
  }

  const passwordHash = await bcrypt.hash(ownerPassword, 12);
  const inserted = await pool.query(
    'INSERT INTO users (username, password_hash, role, preview_mode) VALUES ($1, $2, $3, $4) RETURNING id',
    [ownerUsername, passwordHash, 'owner', true]
  );
  await ensureChannel(inserted.rows[0].id, ownerUsername);
}

async function ensureChannel(userId, username) {
  await pool.query(
    `INSERT INTO channels (user_id, handle, name)
     VALUES ($1, $2, $3)
     ON CONFLICT (user_id) DO NOTHING`,
    [userId, username.toLowerCase(), username]
  );
}
