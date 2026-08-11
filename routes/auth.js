import { Router } from 'express';
import bcrypt from 'bcryptjs';
import pool from '../db.js';

const router = Router();
const SALT_ROUNDS = 12;

// Simple username/email validation
function isValidUsername(u) {
  return /^[a-zA-Z0-9_]{3,30}$/.test(u);
}
function isValidEmail(e) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e) && e.length <= 255;
}
function isValidPassword(p) {
  return typeof p === 'string' && p.length >= 8 && p.length <= 128;
}

// POST /api/auth/register
router.post('/register', async (req, res) => {
  try {
    const { username, email, password } = req.body || {};

    if (!username || !email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    if (!isValidUsername(username)) {
      return res.status(400).json({ error: 'Username must be 3–30 characters and contain only letters, numbers, or underscores' });
    }
    if (!isValidEmail(email)) {
      return res.status(400).json({ error: 'Invalid email address' });
    }
    if (!isValidPassword(password)) {
      return res.status(400).json({ error: 'Password must be 8–128 characters' });
    }

    const hash = await bcrypt.hash(password, SALT_ROUNDS);
    const result = await pool.query(
      'INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id, username, email',
      [username.toLowerCase(), email.toLowerCase(), hash]
    );

    const user = result.rows[0];
    req.session.userId = user.id;
    req.session.username = user.username;

    res.json({ user: { id: user.id, username: user.username, email: user.email } });
  } catch (err) {
    if (err.code === '23505') {
      const field = err.detail?.includes('username') ? 'Username' : 'Email';
      return res.status(409).json({ error: `${field} is already taken` });
    }
    console.error('Register error:', err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// POST /api/auth/login
router.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    const result = await pool.query(
      'SELECT id, username, email, password_hash FROM users WHERE username = $1',
      [username.toLowerCase()]
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
      req.session.userId = user.id;
      req.session.username = user.username;
      res.json({ user: { id: user.id, username: user.username, email: user.email } });
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
  res.json({ user: { id: req.session.userId, username: req.session.username } });
});

export default router;
