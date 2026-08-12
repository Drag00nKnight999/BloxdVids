export function requireAuth(req, res, next) {
  if (!req.session?.userId) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  next();
}

export function requireOwnerAdmin(req, res, next) {
  if (!req.session?.userId) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  if (req.session.role !== 'owner' || req.session.previewMode !== false) {
    return res.status(403).json({ error: 'Owner admin mode is required' });
  }
  next();
}

export function optionalAuth(req, res, next) {
  // Attach user info if logged in, but don't block the request
  next();
}
