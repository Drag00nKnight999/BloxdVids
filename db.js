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
      password_hash VARCHAR(255) NOT NULL,
      role VARCHAR(20) NOT NULL DEFAULT 'user',
      preview_mode BOOLEAN NOT NULL DEFAULT TRUE,
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
    ALTER TABLE users DROP COLUMN IF EXISTS email;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(20) NOT NULL DEFAULT 'user';
    ALTER TABLE users ADD COLUMN IF NOT EXISTS preview_mode BOOLEAN NOT NULL DEFAULT TRUE;
    ALTER TABLE videos ADD COLUMN IF NOT EXISTS thumbnail_mime_type VARCHAR(100);
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
    return;
  }

  const passwordHash = await bcrypt.hash(ownerPassword, 12);
  await pool.query(
    'INSERT INTO users (username, password_hash, role, preview_mode) VALUES ($1, $2, $3, $4)',
    [ownerUsername, passwordHash, 'owner', true]
  );
}
