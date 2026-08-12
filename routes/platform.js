import { Router } from 'express';
import pool from '../db.js';
import { deleteFile } from '../storage.js';
import {
  ASSIGNABLE_ROLES,
  canManageTarget,
  isCurrentlyBanned,
  isCurrentlyRestricted,
  isModerator,
  isOwnerAdmin,
  isPlatformAdmin,
  requireAuth,
  requireDeveloperAccess,
  requireModeration,
  requirePlatformAdmin,
} from '../middleware/auth.js';

const router = Router();
const REPORT_CATEGORIES = new Set(['community_guidelines', 'tos', 'privacy', 'spam', 'copyright', 'other']);
const CASE_STATUSES = new Set(['open', 'investigating', 'resolved', 'dismissed']);
const BUG_STATUSES = new Set(['open', 'triaged', 'in_progress', 'fixed', 'wont_fix']);
const SEVERITIES = new Set(['low', 'normal', 'high', 'critical']);

function text(value, max) {
  return typeof value === 'string' ? value.trim().slice(0, max) : '';
}

function parseDuration(value) {
  if (value === 'permanent' || value === null || value === undefined || value === '') return null;
  const days = Number(value);
  if (!Number.isInteger(days) || days < 1 || days > 3650) return undefined;
  return new Date(Date.now() + days * 24 * 60 * 60 * 1000);
}

async function findUser(id) {
  const result = await pool.query(
    `SELECT id, username, role, preview_mode, banned, ban_until, ban_reason,
            restricted, restriction_until, restriction_type, restriction_reason
     FROM users WHERE id = $1`,
    [id]
  );
  return result.rows[0];
}

function targetError(actor, target) {
  if (!target) return 'User not found';
  if (!canManageTarget(actor, target)) {
    return target.role === 'owner'
      ? 'The owner account is protected'
      : 'You cannot manage this account';
  }
  return null;
}

// Platform administration: user directory, role assignment, and account deletion.
router.get('/users', requirePlatformAdmin, async (_req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT id, username, role, preview_mode, banned, ban_until, ban_reason,
              restricted, restriction_until, restriction_type, restriction_reason, created_at
       FROM users ORDER BY created_at ASC`
    );
    res.json({ users: result.rows });
  } catch (err) {
    next(err);
  }
});

router.patch('/users/:id/role', requirePlatformAdmin, async (req, res, next) => {
  try {
    const id = Number.parseInt(req.params.id, 10);
    const role = text(req.body?.role, 30);
    if (!Number.isInteger(id) || !ASSIGNABLE_ROLES.includes(role)) {
      return res.status(400).json({ error: 'Invalid user or assignable role' });
    }
    const target = await findUser(id);
    const error = targetError(req.currentUser, target);
    if (error) return res.status(target ? 403 : 404).json({ error });

    const result = await pool.query(
      `UPDATE users SET role = $1
       WHERE id = $2 RETURNING id, username, role, preview_mode`,
      [role, id]
    );
    res.json({ user: result.rows[0] });
  } catch (err) {
    next(err);
  }
});

router.patch('/users/:id/status', requireModeration, async (req, res, next) => {
  try {
    const id = Number.parseInt(req.params.id, 10);
    const action = text(req.body?.action, 20);
    const reason = text(req.body?.reason, 1000);
    const restrictionType = text(req.body?.restrictionType || 'upload', 30);
    const duration = parseDuration(req.body?.duration);
    if (!Number.isInteger(id) || !['ban', 'unban', 'restrict', 'unrestrict'].includes(action)) {
      return res.status(400).json({ error: 'Invalid user status action' });
    }
    if (duration === undefined) return res.status(400).json({ error: 'Duration must be permanent or between 1 and 3650 days' });
    if (['ban', 'restrict'].includes(action) && !reason) {
      return res.status(400).json({ error: 'A reason is required for this action' });
    }
    if (action === 'restrict' && !['upload', 'reporting', 'full'].includes(restrictionType)) {
      return res.status(400).json({ error: 'Invalid restriction type' });
    }

    const target = await findUser(id);
    const error = targetError(req.currentUser, target);
    if (error) return res.status(target ? 403 : 404).json({ error });

    let query;
    let params;
    if (action === 'ban') {
      query = `UPDATE users SET banned = TRUE, ban_until = $1, ban_reason = $2
               WHERE id = $3 RETURNING id, username, role, banned, ban_until, ban_reason,
               restricted, restriction_until, restriction_type, restriction_reason`;
      params = [duration, reason, id];
    } else if (action === 'unban') {
      query = `UPDATE users SET banned = FALSE, ban_until = NULL, ban_reason = NULL
               WHERE id = $1 RETURNING id, username, role, banned, ban_until, ban_reason,
               restricted, restriction_until, restriction_type, restriction_reason`;
      params = [id];
    } else if (action === 'restrict') {
      query = `UPDATE users SET restricted = TRUE, restriction_until = $1,
               restriction_type = $2, restriction_reason = $3
               WHERE id = $4 RETURNING id, username, role, banned, ban_until, ban_reason,
               restricted, restriction_until, restriction_type, restriction_reason`;
      params = [duration, restrictionType, reason, id];
    } else {
      query = `UPDATE users SET restricted = FALSE, restriction_until = NULL,
               restriction_type = NULL, restriction_reason = NULL
               WHERE id = $1 RETURNING id, username, role, banned, ban_until, ban_reason,
               restricted, restriction_until, restriction_type, restriction_reason`;
      params = [id];
    }
    const result = await pool.query(query, params);
    res.json({ user: result.rows[0] });
  } catch (err) {
    next(err);
  }
});

router.delete('/users/:id', requirePlatformAdmin, async (req, res, next) => {
  try {
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) return res.status(400).json({ error: 'Invalid user ID' });
    const target = await findUser(id);
    const error = targetError(req.currentUser, target);
    if (error) return res.status(target ? 403 : 404).json({ error });
    if (id === req.currentUser.id) return res.status(400).json({ error: 'You cannot delete your own account here' });

    const videos = await pool.query('SELECT storage_key, thumbnail_key FROM videos WHERE user_id = $1', [id]);
    await Promise.allSettled(videos.rows.flatMap((video) => [
      video.storage_key && video.storage_key !== 'pending' ? deleteFile(video.storage_key) : Promise.resolve(),
      video.thumbnail_key ? deleteFile(video.thumbnail_key) : Promise.resolve(),
    ]));
    await pool.query('DELETE FROM users WHERE id = $1', [id]);
    res.json({ success: true });
  } catch (err) {
    next(err);
  }
});

// Reports are submitted by users and resolved by moderators/admins.
router.post('/reports', requireAuth, async (req, res, next) => {
  try {
    const reportedUserId = req.body?.reportedUserId ? Number.parseInt(req.body.reportedUserId, 10) : null;
    const videoId = req.body?.videoId ? Number.parseInt(req.body.videoId, 10) : null;
    const category = text(req.body?.category, 40);
    const details = text(req.body?.details, 3000);
    if (!REPORT_CATEGORIES.has(category) || !details || (!reportedUserId && !videoId)) {
      return res.status(400).json({ error: 'A valid category, details, and reported user or video are required' });
    }
    if (reportedUserId === req.currentUser.id) return res.status(400).json({ error: 'You cannot report yourself' });
    const result = await pool.query(
      `INSERT INTO reports (reporter_id, reported_user_id, video_id, category, details)
       VALUES ($1, $2, $3, $4, $5) RETURNING id, status, created_at`,
      [req.currentUser.id, reportedUserId, videoId, category, details]
    );
    res.status(201).json({ report: result.rows[0] });
  } catch (err) {
    next(err);
  }
});

router.get('/reports', requireModeration, async (_req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT r.*, reporter.username AS reporter, reported.username AS reported_user,
              v.title AS video_title
       FROM reports r
       JOIN users reporter ON reporter.id = r.reporter_id
       LEFT JOIN users reported ON reported.id = r.reported_user_id
       LEFT JOIN videos v ON v.id = r.video_id
       ORDER BY CASE WHEN r.status = 'open' THEN 0 ELSE 1 END, r.created_at DESC`
    );
    res.json({ reports: result.rows });
  } catch (err) {
    next(err);
  }
});

router.patch('/reports/:id', requireModeration, async (req, res, next) => {
  try {
    const status = text(req.body?.status, 20);
    const note = text(req.body?.resolutionNote, 2000);
    if (!CASE_STATUSES.has(status)) return res.status(400).json({ error: 'Invalid report status' });
    const result = await pool.query(
      `UPDATE reports SET status = $1, resolution_note = $2, reviewed_by = $3, updated_at = NOW()
       WHERE id = $4 RETURNING *`,
      [status, note, req.currentUser.id, Number.parseInt(req.params.id, 10)]
    );
    if (!result.rows[0]) return res.status(404).json({ error: 'Report not found' });
    res.json({ report: result.rows[0] });
  } catch (err) {
    next(err);
  }
});

// Appeals may be filed by a restricted account; only the affected user can file one.
router.post('/appeals', requireAuth, async (req, res, next) => {
  try {
    const reason = text(req.body?.reason, 3000);
    if (!reason) return res.status(400).json({ error: 'An appeal reason is required' });
    if (!isCurrentlyBanned(req.currentUser) && !isCurrentlyRestricted(req.currentUser)) {
      return res.status(400).json({ error: 'Your account has no active restriction to appeal' });
    }
    const result = await pool.query(
      'INSERT INTO appeals (user_id, reason) VALUES ($1, $2) RETURNING id, status, created_at',
      [req.currentUser.id, reason]
    );
    res.status(201).json({ appeal: result.rows[0] });
  } catch (err) {
    next(err);
  }
});

router.get('/appeals', requireModeration, async (_req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT a.*, u.username, u.role, u.banned, u.ban_reason, u.restricted,
              u.restriction_type, u.restriction_reason
       FROM appeals a JOIN users u ON u.id = a.user_id
       ORDER BY CASE WHEN a.status = 'open' THEN 0 ELSE 1 END, a.created_at DESC`
    );
    res.json({ appeals: result.rows });
  } catch (err) {
    next(err);
  }
});

router.patch('/appeals/:id', requireModeration, async (req, res, next) => {
  try {
    const status = text(req.body?.status, 20);
    const decisionNote = text(req.body?.decisionNote, 2000);
    if (!['resolved', 'dismissed'].includes(status)) return res.status(400).json({ error: 'Appeals can only be resolved or dismissed' });
    const appeal = await pool.query('SELECT * FROM appeals WHERE id = $1', [Number.parseInt(req.params.id, 10)]);
    if (!appeal.rows[0]) return res.status(404).json({ error: 'Appeal not found' });
    if (status === 'resolved') {
      await pool.query(
        `UPDATE users SET banned = FALSE, ban_until = NULL, ban_reason = NULL,
         restricted = FALSE, restriction_until = NULL, restriction_type = NULL, restriction_reason = NULL
         WHERE id = $1`,
        [appeal.rows[0].user_id]
      );
    }
    const result = await pool.query(
      `UPDATE appeals SET status = $1, reviewer_id = $2, decision_note = $3, updated_at = NOW()
       WHERE id = $4 RETURNING *`,
      [status, req.currentUser.id, decisionNote, appeal.rows[0].id]
    );
    res.json({ appeal: result.rows[0] });
  } catch (err) {
    next(err);
  }
});

// Bug reports are open to authenticated users; developers can view the queue.
router.post('/bugs', requireAuth, async (req, res, next) => {
  try {
    const title = text(req.body?.title, 200);
    const description = text(req.body?.description, 5000);
    const steps = text(req.body?.stepsToReproduce, 5000);
    const severity = text(req.body?.severity || 'normal', 20);
    if (!title || !description || !SEVERITIES.has(severity)) {
      return res.status(400).json({ error: 'Title, description, and a valid severity are required' });
    }
    const result = await pool.query(
      `INSERT INTO bug_reports (reporter_id, title, description, steps_to_reproduce, severity)
       VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [req.currentUser.id, title, description, steps, severity]
    );
    res.status(201).json({ bug: result.rows[0] });
  } catch (err) {
    next(err);
  }
});

router.get('/bugs', requireDeveloperAccess, async (_req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT b.*, u.username AS reporter FROM bug_reports b
       LEFT JOIN users u ON u.id = b.reporter_id ORDER BY b.created_at DESC`
    );
    res.json({ bugs: result.rows });
  } catch (err) {
    next(err);
  }
});

router.patch('/bugs/:id', requireDeveloperAccess, async (req, res, next) => {
  try {
    const status = text(req.body?.status, 20);
    if (!BUG_STATUSES.has(status)) return res.status(400).json({ error: 'Invalid bug status' });
    const result = await pool.query(
      'UPDATE bug_reports SET status = $1, updated_at = NOW() WHERE id = $2 RETURNING *',
      [status, Number.parseInt(req.params.id, 10)]
    );
    if (!result.rows[0]) return res.status(404).json({ error: 'Bug report not found' });
    res.json({ bug: result.rows[0] });
  } catch (err) {
    next(err);
  }
});

router.post('/crashes', async (req, res, next) => {
  try {
    const message = text(req.body?.message, 500);
    if (!message) return res.status(400).json({ error: 'Crash message is required' });
    const metadata = req.body?.metadata && typeof req.body.metadata === 'object' ? req.body.metadata : {};
    const result = await pool.query(
      `INSERT INTO crash_logs (reporter_id, message, stack, page_url, user_agent, metadata)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, created_at`,
      [req.session?.userId || null, message, text(req.body?.stack, 10000),
       text(req.body?.pageUrl, 1000), text(req.body?.userAgent, 500), JSON.stringify(metadata)]
    );
    res.status(201).json({ crash: result.rows[0] });
  } catch (err) {
    next(err);
  }
});

router.get('/crashes', requireDeveloperAccess, async (_req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT c.*, u.username AS reporter FROM crash_logs c
       LEFT JOIN users u ON u.id = c.reporter_id ORDER BY c.created_at DESC LIMIT 500`
    );
    res.json({ crashes: result.rows });
  } catch (err) {
    next(err);
  }
});

export default router;