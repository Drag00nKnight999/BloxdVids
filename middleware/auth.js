import pool from '../db.js';

export const ROLE_LABELS = {
  owner: 'Owner',
  admin: 'Admin',
  moderator: 'Moderator',
  developer: 'Developer',
  beta_tester: 'Beta Tester',
  bug_hunter: 'Bug Hunter',
  contributor: 'Contributor',
  booster: 'Booster',
  og_user: 'OG User',
  user: 'User',
};

export const ASSIGNABLE_ROLES = [
  'admin', 'moderator', 'developer', 'beta_tester', 'bug_hunter',
  'contributor', 'booster', 'og_user', 'user',
];

export function isOwnerAdmin(user) {
  return user?.role === 'owner' && user.preview_mode === false;
}

export function isPlatformAdmin(user) {
  return user?.role === 'admin' || isOwnerAdmin(user);
}

export function isModerator(user) {
  return user?.role === 'moderator' || isPlatformAdmin(user);
}

export function canManageTarget(actor, target) {
  if (!actor || !target || actor.id === target.id) return false;
  if (target.role === 'owner') return isOwnerAdmin(actor);
  if (actor.role === 'moderator' && target.role === 'admin') return false;
  return isModerator(actor);
}

export function isCurrentlyBanned(user) {
  return user?.banned === true && (!user.ban_until || new Date(user.ban_until) > new Date());
}

export function isCurrentlyRestricted(user) {
  return user?.restricted === true
    && (!user.restriction_until || new Date(user.restriction_until) > new Date());
}

async function loadUser(req) {
  if (!req.session?.userId) return null;
  const result = await pool.query(
    `SELECT u.id, u.username, u.role, u.preview_mode, u.banned, u.ban_until, u.ban_reason,
            u.restricted, u.restriction_until, u.restriction_type, u.restriction_reason,
            COALESCE((SELECT c.copyright_suspended_at IS NOT NULL
                      FROM channels c WHERE c.user_id = u.id), FALSE) AS copyright_suspended
     FROM users u WHERE u.id = $1`,
    [req.session.userId]
  );
  const user = result.rows[0];
  if (!user) return null;
  req.currentUser = user;
  req.session.username = user.username;
  req.session.role = user.role;
  req.session.previewMode = user.preview_mode;
  return user;
}

export function requireAuth(req, res, next) {
  loadUser(req).then((user) => {
    if (!user) return res.status(401).json({ error: 'Authentication required' });
    next();
  }).catch(next);
}

function requirePermission(check, message) {
  return (req, res, next) => {
    loadUser(req).then((user) => {
      if (!user) return res.status(401).json({ error: 'Authentication required' });
      if (!check(user)) return res.status(403).json({ error: message });
      next();
    }).catch(next);
  };
}

export const requireModeration = requirePermission(
  isModerator,
  'Moderator or admin permissions are required'
);

export const requirePlatformAdmin = requirePermission(
  isPlatformAdmin,
  'Admin permissions are required'
);

export const requireDeveloperAccess = requirePermission(
  (user) => user.role === 'developer' || isPlatformAdmin(user),
  'Developer access is required'
);

export const requireUploadAccess = requirePermission(
  (user) => !user.copyright_suspended
    && !isCurrentlyBanned(user)
    && !(isCurrentlyRestricted(user) && user.restriction_type !== 'reporting'),
  'Your channel cannot upload while it is suspended or your account is restricted'
);

export function requireOwnerAdmin(req, res, next) {
  return requirePermission(isOwnerAdmin, 'Owner admin mode is required')(req, res, next);
}

export function optionalAuth(req, res, next) {
  // Attach user info if logged in, but don't block the request
  next();
}
