export function requireAuth(req, res, next) {
  if (!req.session?.userId) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  next();
}

export function optionalAuth(req, res, next) {
  // Attach user info if logged in, but don't block the request
  next();
}
