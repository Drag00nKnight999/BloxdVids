import { Router } from 'express';
import pool from '../db.js';
import { requireAuth } from '../middleware/auth.js';

const router = Router();

function clean(value, max) {
  return typeof value === 'string' ? value.trim().slice(0, max) : '';
}

async function ensureChannel(user) {
  const existing = await pool.query(
    `SELECT c.*, u.username
     FROM channels c JOIN users u ON u.id = c.user_id
     WHERE c.user_id = $1`,
    [user.id]
  );
  if (existing.rows[0]) return existing.rows[0];

  const inserted = await pool.query(
    `INSERT INTO channels (user_id, handle, name)
     VALUES ($1, $2, $3)
     ON CONFLICT (user_id) DO UPDATE SET user_id = EXCLUDED.user_id
     RETURNING *`,
    [user.id, user.username.toLowerCase(), user.username]
  );
  return { ...inserted.rows[0], username: user.username };
}

async function findChannel(handle) {
  const result = await pool.query(
    `SELECT c.id, c.user_id, c.handle, c.name, c.description, c.created_at,
            (SELECT COUNT(*) FROM subscriptions s WHERE s.channel_id = c.id)::integer AS subscriber_count,
            u.username
     FROM channels c JOIN users u ON u.id = c.user_id
     WHERE LOWER(c.handle) = LOWER($1)`,
    [handle]
  );
  return result.rows[0];
}

router.get('/me', requireAuth, async (req, res, next) => {
  try {
    const channel = await ensureChannel(req.currentUser);
    res.json({ channel });
  } catch (err) {
    next(err);
  }
});

router.patch('/me', requireAuth, async (req, res, next) => {
  try {
    const name = clean(req.body?.name, 100);
    const description = clean(req.body?.description, 1000);
    if (!name) return res.status(400).json({ error: 'Channel name is required' });
    await ensureChannel(req.currentUser);
    const result = await pool.query(
      `UPDATE channels SET name = $1, description = $2, updated_at = NOW()
       WHERE user_id = $3 RETURNING *`,
      [name, description, req.currentUser.id]
    );
    res.json({ channel: result.rows[0] });
  } catch (err) {
    next(err);
  }
});

router.post('/:handle/subscribe', requireAuth, async (req, res, next) => {
  try {
    const channel = await findChannel(req.params.handle);
    if (!channel) return res.status(404).json({ error: 'Channel not found' });
    if (channel.user_id === req.currentUser.id) return res.status(400).json({ error: 'You cannot subscribe to your own channel' });
    await pool.query(
      `INSERT INTO subscriptions (subscriber_id, channel_id)
       VALUES ($1, $2) ON CONFLICT DO NOTHING`,
      [req.currentUser.id, channel.id]
    );
    res.json({ subscribed: true });
  } catch (err) {
    next(err);
  }
});

router.delete('/:handle/subscribe', requireAuth, async (req, res, next) => {
  try {
    const channel = await findChannel(req.params.handle);
    if (!channel) return res.status(404).json({ error: 'Channel not found' });
    await pool.query(
      'DELETE FROM subscriptions WHERE subscriber_id = $1 AND channel_id = $2',
      [req.currentUser.id, channel.id]
    );
    res.json({ subscribed: false });
  } catch (err) {
    next(err);
  }
});

router.get('/:handle/videos', async (req, res, next) => {
  try {
    const channel = await findChannel(req.params.handle);
    if (!channel) return res.status(404).json({ error: 'Channel not found' });
    const result = await pool.query(
      `SELECT v.id, v.title, v.description, v.thumbnail_key, v.view_count,
              v.created_at, v.file_size, v.mime_type, u.username AS uploader
       FROM videos v JOIN users u ON u.id = v.user_id
       WHERE v.user_id = $1 AND v.storage_key <> 'pending'
       ORDER BY v.created_at DESC LIMIT 100`,
      [channel.user_id]
    );
    res.json({ channel, videos: result.rows });
  } catch (err) {
    next(err);
  }
});

router.get('/:handle', async (req, res, next) => {
  try {
    const channel = await findChannel(req.params.handle);
    if (!channel) return res.status(404).json({ error: 'Channel not found' });
    let subscribed = false;
    if (req.session?.userId) {
      const result = await pool.query(
        'SELECT 1 FROM subscriptions WHERE subscriber_id = $1 AND channel_id = $2',
        [req.session.userId, channel.id]
      );
      subscribed = Boolean(result.rows[0]);
    }
    res.json({ channel: { ...channel, subscribed } });
  } catch (err) {
    next(err);
  }
});

export default router;