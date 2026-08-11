import express from 'express';
import session from 'express-session';
import pgSession from 'connect-pg-simple';
import pool, { initDb } from './db.js';
import authRoutes from './routes/auth.js';
import videoRoutes from './routes/videos.js';

const app = express();
const PORT = process.env.PORT || 5000;
const sessionSecret = process.env.SESSION_SECRET;

if (!sessionSecret) {
  throw new Error('SESSION_SECRET must be configured before starting BloxdVids');
}

// Trust Replit's proxy
app.set('trust proxy', 1);
app.disable('x-powered-by');

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
    secret: sessionSecret,
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
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    'Content-Security-Policy': [
      "default-src 'self'",
      "base-uri 'self'",
      "form-action 'self'",
      "frame-ancestors 'self'",
      "img-src 'self' blob: data:",
      "media-src 'self' blob:",
      "style-src 'self' 'unsafe-inline'",
      "script-src 'self' 'unsafe-inline'",
      "connect-src 'self'",
    ].join('; '),
  });
  next();
});

// Static files — keep the preview shell fresh after edits.
app.use(express.static('public', {
  maxAge: 0,
  etag: false,
  setHeaders(res) {
    res.setHeader('Cache-Control', 'no-store');
  },
}));

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
      console.log(`BloxdVids running on port ${PORT}`);
    });
  })
  .catch((err) => {
    console.error('Failed to initialize database:', err);
    process.exit(1);
  });
