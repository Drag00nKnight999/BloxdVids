import { Router } from 'express';
import bcrypt from 'bcryptjs';
import pool from '../db.js';
import { requireAuth } from '../middleware/auth.js';

const router = Router();
const SALT_ROUNDS = 12;

// Simple username validation
function isValidUsername(u) {
  return /^[a-zA-Z0-9_]{3,30}$/.test(u);
}
function isValidPassword(p) {
  return typeof p === 'string' && p.length >= 8 && p.length <= 128;
}
function isValidEmail(value) {
  return typeof value === 'string'
    && value.length <= 320
    && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function sessionUser(user, req) {
  req.session.userId = user.id;
  req.session.username = user.username;
  req.session.role = user.role;
  req.session.previewMode = user.preview_mode;
}

function publicUser(user) {
  const banned = user.banned === true
    && (!user.ban_until || new Date(user.ban_until) > new Date());
  const restricted = user.restricted === true
    && (!user.restriction_until || new Date(user.restriction_until) > new Date());
  return {
    id: user.id,
    username: user.username,
    role: user.role || 'user',
    hasEmail: Boolean(user.email),
    previewMode: user.preview_mode !== false,
    adminMode: user.role === 'owner' && user.preview_mode === false,
    banned,
    restricted,
    banReason: banned ? user.ban_reason : null,
    restrictionType: restricted ? user.restriction_type : null,
    restrictionReason: restricted ? user.restriction_reason : null,
    betaAccess: user.role === 'beta_tester',
    canModerate: user.role === 'moderator'
      || user.role === 'admin'
      || (user.role === 'owner' && user.preview_mode === false),
    canManagePlatform: user.role === 'admin'
      || (user.role === 'owner' && user.preview_mode === false),
    canViewDeveloperTools: user.role === 'developer'
      || user.role === 'admin'
      || (user.role === 'owner' && user.preview_mode === false),
  };
}

// POST /api/auth/register
router.post('/register', async (req, res) => {
  try {
    const { username, email, password } = req.body || {};

    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Username, email, and password are required' });
    }
    if (!isValidUsername(username)) {
      return res.status(400).json({ error: 'Username must be 3–30 characters and contain only letters, numbers, or underscores' });
    }
    if (!isValidPassword(password)) {
      return res.status(400).json({ error: 'Password must be 8–128 characters' });
    }
    if (!isValidEmail(email)) {
      return res.status(400).json({ error: 'Enter a valid email address' });
    }

    const existing = await pool.query(
      'SELECT 1 FROM users WHERE LOWER(username) = LOWER($1) OR LOWER(email) = LOWER($2) LIMIT 1',
      [username, email]
    );
    if (existing.rows[0]) {
      return res.status(409).json({ error: 'Username is already taken' });
    }

    const hash = await bcrypt.hash(password, SALT_ROUNDS);
    const result = await pool.query(
      `INSERT INTO users (username, email, password_hash)
       VALUES ($1, $2, $3)
       RETURNING id, username, email, role, preview_mode, banned, ban_until, ban_reason,
       restricted, restriction_until, restriction_type, restriction_reason`,
      [username.toLowerCase(), email.toLowerCase(), hash]
    );

    const user = result.rows[0];
    req.session.regenerate((err) => {
      if (err) {
        console.error('Registration session error:', err);
        return res.status(500).json({ error: 'Registration failed' });
      }
      sessionUser(user, req);
      res.json({ user: publicUser(user) });
    });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: 'Username is already taken' });
    }
    console.error('Register error:', err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// POST /api/auth/login
router.post('/login', async (req, res) => {
  try {
    const { identifier, username, email, password } = req.body || {};
    const loginIdentifier = identifier || username || email;

    if (!loginIdentifier || !password) {
      return res.status(400).json({ error: 'Email or username and password are required' });
    }

    const result = await pool.query(
      `SELECT id, username, email, password_hash, role, preview_mode, banned, ban_until, ban_reason,
              restricted, restriction_until, restriction_type, restriction_reason
       FROM users WHERE LOWER(username) = LOWER($1) OR LOWER(email) = LOWER($1)
       ORDER BY id ASC LIMIT 1`,
      [loginIdentifier]
    );
    const user = result.rows[0];

    if (!user) {
      // Constant-time response to prevent username enumeration
      await bcrypt.compare(password, '$2b$12$invalidhashfortimingnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn');
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    req.session.regenerate((err) => {
      if (err) return res.status(500).json({ error: 'Login failed' });
      sessionUser(user, req);
      res.json({ user: publicUser(user) });
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// POST /api/auth/logout
router.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) return res.status(500).json({ error: 'Logout failed' });
    res.clearCookie('connect.sid');
    res.json({ success: true });
  });
});

// GET /api/auth/me
router.get('/me', (req, res) => {
  if (!req.session?.userId) {
    return res.json({ user: null });
  }
  pool.query(
    `SELECT id, username, email, role, preview_mode, banned, ban_until, ban_reason,
            restricted, restriction_until, restriction_type, restriction_reason
     FROM users WHERE id = $1`,
    [req.session.userId]
  ).then((result) => {
    const user = result.rows[0];
    if (!user) return res.json({ user: null });
    sessionUser(user, req);
    res.json({ user: publicUser(user) });
  }).catch((err) => {
    console.error('Session user error:', err);
    res.status(500).json({ error: 'Failed to load account' });
  });
});

// GET /api/auth/settings
router.get('/settings', requireAuth, async (req, res) => {
  const result = await pool.query(
    `SELECT id, username, email, role, preview_mode, banned, ban_until, ban_reason,
            restricted, restriction_until, restriction_type, restriction_reason
     FROM users WHERE id = $1`,
    [req.session.userId]
  );
  const user = result.rows[0];
  if (!user) return res.status(404).json({ error: 'User not found' });
  req.session.role = user.role;
  req.session.previewMode = user.preview_mode;
  res.json({ user: publicUser(user), email: user.email || '' });
});

// PATCH /api/auth/settings/email — add or update an account email
router.patch('/settings/email', requireAuth, async (req, res) => {
  const email = typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase() : '';
  if (!isValidEmail(email)) {
    return res.status(400).json({ error: 'Enter a valid email address' });
  }

  try {
    const existing = await pool.query(
      'SELECT 1 FROM users WHERE LOWER(email) = LOWER($1) AND id <> $2 LIMIT 1',
      [email, req.session.userId]
    );
    if (existing.rows[0]) {
      return res.status(409).json({ error: 'That email address is already in use' });
    }

    const result = await pool.query(
      `UPDATE users SET email = $1
       WHERE id = $2
       RETURNING id, username, email, role, preview_mode, banned, ban_until, ban_reason,
       restricted, restriction_until, restriction_type, restriction_reason`,
      [email, req.session.userId]
    );
    const user = result.rows[0];
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ user: publicUser(user), email: user.email });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: 'That email address is already in use' });
    }
    console.error('Email settings error:', err);
    res.status(500).json({ error: 'Could not update email address' });
  }
});

// PATCH /api/auth/settings/preview-mode
router.patch('/settings/preview-mode', requireAuth, async (req, res) => {
  if (req.session.role !== 'owner') {
    return res.status(403).json({ error: 'Only the owner can change preview mode' });
  }
  const previewMode = req.body?.previewMode;
  if (typeof previewMode !== 'boolean') {
    return res.status(400).json({ error: 'previewMode must be a boolean' });
  }

  const result = await pool.query(
    `UPDATE users SET preview_mode = $1 WHERE id = $2
     RETURNING id, username, email, role, preview_mode, banned, ban_until, ban_reason,
     restricted, restriction_until, restriction_type, restriction_reason`,
    [previewMode, req.session.userId]
  );
  const user = result.rows[0];
  req.session.previewMode = user.preview_mode;
  res.json({ user: publicUser(user) });
});

export default router;
