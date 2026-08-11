import express from 'express';
import session from 'express-session';
import pgSession from 'connect-pg-simple';
import pool, { initDb } from './db.js';
import authRoutes from './routes/auth.js';
import videoRoutes from './routes/videos.js';

const app = express();
const PORT = process.env.PORT || 5000;

// Trust Replit's proxy
app.set('trust proxy', 1);

// Body parsing
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// Session setup with PostgreSQL store
const PgSession = pgSession(session);
app.use(
  session({
    store: new PgSession({
      pool,
      tableName: 'session',
      createTableIfMissing: true,
    }),
    secret: process.env.SESSION_SECRET || 'fallback-secret-change-in-production',
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === 'production',
      httpOnly: true,
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    },
  })
);

// Security headers
app.use((_req, res, next) => {
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'SAMEORIGIN',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
  });
  next();
});

// Static files
app.use(express.static('public', { maxAge: '1d' }));

// API routes
app.use('/api/auth', authRoutes);
app.use('/api/videos', videoRoutes);

// SPA fallback — serve index.html for any unmatched browser routes.
// Express 5 no longer accepts the legacy "*" path pattern.
app.get(/.*/, (_req, res) => {
  res.sendFile('public/index.html', { root: '.' });
});

// Global error handler
app.use((err, _req, res, _next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// Start
initDb()
  .then(() => {
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`Video platform running on port ${PORT}`);
    });
  })
  .catch((err) => {
    console.error('Failed to initialize database:', err);
    process.exit(1);
  });
