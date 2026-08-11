import pg from 'pg';

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
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
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
    ALTER TABLE videos ADD COLUMN IF NOT EXISTS thumbnail_mime_type VARCHAR(100);
  `);
}
