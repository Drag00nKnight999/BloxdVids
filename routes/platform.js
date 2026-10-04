import { Router } from 'express';
import { randomUUID } from 'node:crypto';
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

function legalText(value, max) {
  if (typeof value !== 'string') return '';
  const trimmed = value.trim();
  return trimmed.length <= max ? trimmed : null;
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

async function inTransaction(work) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await work(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

async function addCopyrightStrike(client, { sourceType, sourceId, videoId, reviewerId, reason }) {
  const target = await client.query(
    `SELECT c.id AS channel_id
     FROM videos v JOIN channels c ON c.user_id = v.user_id
     WHERE v.id = $1
     FOR UPDATE OF c`,
    [videoId]
  );
  if (!target.rows[0]) return { error: 'The selected video or its channel no longer exists' };

  const channelId = target.rows[0].channel_id;
  const inserted = await client.query(
    `INSERT INTO copyright_strikes
       (channel_id, target_video_id, source_type, source_id, reason, issued_by)
     VALUES ($1, $2, $3, $4, $5, $6)
     ON CONFLICT (source_type, source_id) DO NOTHING
     RETURNING id`,
    [channelId, videoId, sourceType, sourceId, reason, reviewerId]
  );
  if (!inserted.rows[0]) return { duplicate: true };

  const count = await client.query(
    `SELECT COUNT(*)::integer AS active_strikes
     FROM copyright_strikes
     WHERE channel_id = $1 AND status = 'active'`,
    [channelId]
  );
  const activeStrikes = count.rows[0].active_strikes;
  await client.query(
    `UPDATE channels
     SET copyright_suspended_at = CASE
       WHEN $2 >= 3 THEN COALESCE(copyright_suspended_at, NOW())
       ELSE NULL
     END
     WHERE id = $1`,
    [channelId, activeStrikes]
  );
  return { strikeId: inserted.rows[0].id, channelId, activeStrikes, suspended: activeStrikes >= 3 };
}

async function refreshCopyrightSuspension(client, channelId) {
  const count = await client.query(
    `SELECT COUNT(*)::integer AS active_strikes
     FROM copyright_strikes
     WHERE channel_id = $1 AND status = 'active'`,
    [channelId]
  );
  const activeStrikes = count.rows[0].active_strikes;
  await client.query(
    `UPDATE channels
     SET copyright_suspended_at = CASE
       WHEN $2 >= 3 THEN COALESCE(copyright_suspended_at, NOW())
       ELSE NULL
     END
     WHERE id = $1`,
    [channelId, activeStrikes]
  );
  return { activeStrikes, suspended: activeStrikes >= 3 };
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
    const [reportedUser, reportedVideo] = await Promise.all([
      reportedUserId ? pool.query('SELECT 1 FROM users WHERE id = $1', [reportedUserId]) : Promise.resolve({ rows: [] }),
      videoId ? pool.query('SELECT 1 FROM videos WHERE id = $1', [videoId]) : Promise.resolve({ rows: [] }),
    ]);
    if (reportedUserId && !reportedUser.rows[0]) return res.status(404).json({ error: 'Reported user not found' });
    if (videoId && !reportedVideo.rows[0]) return res.status(404).json({ error: 'Reported video not found' });
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

// Copyright notices and counter-notices are private intake records. Only moderators
// and admins can retrieve or update them; public submitters receive only a reference.
router.post('/copyright-cases', async (req, res, next) => {
  try {
    const type = legalText(req.body?.type, 20);
    const name = legalText(req.body?.name, 200);
    const rawEmail = legalText(req.body?.email, 320);
    const email = rawEmail?.toLowerCase() || rawEmail;
    const address = legalText(req.body?.address, 2000);
    const phone = legalText(req.body?.phone, 60);
    const signature = legalText(req.body?.signature, 200);
    const copyrightedWork = legalText(req.body?.copyrightedWork, 5000);
    const contentLocation = legalText(req.body?.contentLocation, 5000);
    const priorNoticeDetails = legalText(req.body?.reference, 2000);
    const trap = legalText(req.body?.website, 300);

    if ([type, name, rawEmail, address, phone, signature, copyrightedWork, contentLocation, priorNoticeDetails, trap].includes(null)) {
      return res.status(400).json({ error: 'One or more fields exceed the allowed length' });
    }
    if (trap) return res.status(400).json({ error: 'Unable to accept this submission' });
    if (!['notice', 'counter_notice'].includes(type)) {
      return res.status(400).json({ error: 'Choose a notice or counter-notice' });
    }
    if (!name || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !address || !phone || !signature || !contentLocation) {
      return res.status(400).json({ error: 'Name, valid email, mailing address, phone, signature, and content location are required' });
    }

    let relatedNoticeId = null;
    if (type === 'notice') {
      const goodFaith = req.body?.goodFaith === true;
      const accuracyAndAuthority = req.body?.accuracyAndAuthority === true;
      if (!copyrightedWork || !goodFaith || !accuracyAndAuthority) {
        return res.status(400).json({ error: 'Identify the copyrighted work and confirm both required notice statements' });
      }
    } else {
      if (priorNoticeDetails) {
        const original = await pool.query(
          `SELECT id FROM copyright_cases
           WHERE LOWER(public_ref) = LOWER($1) AND submission_type = 'notice'`,
          [priorNoticeDetails]
        );
        relatedNoticeId = original.rows[0]?.id ?? null;
      }
      if (
        req.body?.counterGoodFaith !== true
        || req.body?.jurisdictionConsent !== true
        || req.body?.serviceOfProcessConsent !== true
      ) {
        return res.status(400).json({ error: 'Confirm the required counter-notice statements and consents' });
      }
    }

    const publicRef = `DMCA-${randomUUID().toUpperCase()}`;
    const result = await pool.query(
      `INSERT INTO copyright_cases
        (public_ref, submission_type, claimant_name, email, mailing_address, phone, signature,
         copyrighted_work, content_location, prior_notice_details, related_notice_id, good_faith, accuracy_and_authority,
         counter_good_faith, jurisdiction_consent, service_of_process_consent)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
       RETURNING public_ref, submission_type, status, created_at`,
      [
        publicRef, type, name, email, address, phone, signature, copyrightedWork,
        contentLocation, priorNoticeDetails || '', relatedNoticeId, req.body?.goodFaith === true,
        req.body?.accuracyAndAuthority === true, req.body?.counterGoodFaith === true,
        req.body?.jurisdictionConsent === true, req.body?.serviceOfProcessConsent === true,
      ]
    );
    res.status(201).json({ submission: result.rows[0] });
  } catch (err) {
    next(err);
  }
});

router.get('/copyright-cases', requireModeration, async (_req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT c.*, original.public_ref AS original_notice_ref
       FROM copyright_cases c
       LEFT JOIN copyright_cases original ON original.id = c.related_notice_id
       ORDER BY CASE WHEN c.status = 'open' THEN 0 WHEN c.status = 'investigating' THEN 1 ELSE 2 END,
                c.created_at DESC
       LIMIT 200`
    );
    res.json({ cases: result.rows });
  } catch (err) {
    next(err);
  }
});

router.patch('/copyright-cases/:id', requireModeration, async (req, res, next) => {
  try {
    const id = Number.parseInt(req.params.id, 10);
    const status = text(req.body?.status, 20);
    const note = text(req.body?.resolutionNote, 3000);
    if (!Number.isInteger(id) || !['open', 'investigating', 'resolved', 'dismissed'].includes(status)) {
      return res.status(400).json({ error: 'Invalid copyright case or status' });
    }
    const result = await pool.query(
      `UPDATE copyright_cases
       SET status = $1, resolution_note = $2, reviewed_by = $3, updated_at = NOW()
       WHERE id = $4
       RETURNING id, public_ref, status, resolution_note, reviewed_by, updated_at`,
      [status, note, req.currentUser.id, id]
    );
    if (!result.rows[0]) return res.status(404).json({ error: 'Copyright case not found' });
    res.json({ case: result.rows[0] });
  } catch (err) {
    next(err);
  }
});

// A strike is created only when a moderator explicitly confirms infringement.
router.post('/copyright-cases/:id/strike', requireModeration, async (req, res, next) => {
  try {
    const caseId = Number.parseInt(req.params.id, 10);
    const videoId = Number.parseInt(req.body?.videoId, 10);
    const reason = text(req.body?.reason, 3000);
    if (!Number.isInteger(caseId) || !Number.isInteger(videoId) || !reason) {
      return res.status(400).json({ error: 'A notice, affected video, and confirmation reason are required' });
    }
    const outcome = await inTransaction(async (client) => {
      const copyrightCase = await client.query(
        'SELECT id, submission_type, status FROM copyright_cases WHERE id = $1 FOR UPDATE',
        [caseId]
      );
      if (!copyrightCase.rows[0]) return { error: 'Copyright notice not found', status: 404 };
      if (copyrightCase.rows[0].submission_type !== 'notice' || copyrightCase.rows[0].status === 'dismissed') {
        return { error: 'Only an active copyright notice can result in a strike', status: 400 };
      }
      const strike = await addCopyrightStrike(client, {
        sourceType: 'dmca_notice',
        sourceId: caseId,
        videoId,
        reviewerId: req.currentUser.id,
        reason,
      });
      if (strike.error) return { error: strike.error, status: 404 };
      if (strike.duplicate) return { error: 'A strike has already been issued for this notice', status: 409 };
      await client.query(
        `UPDATE copyright_cases
         SET status = 'resolved', resolution_note = $1, reviewed_by = $2, updated_at = NOW()
         WHERE id = $3`,
        [reason, req.currentUser.id, caseId]
      );
      return strike;
    });
    if (outcome.error) return res.status(outcome.status).json({ error: outcome.error });
    res.status(201).json({ strike: outcome });
  } catch (err) {
    next(err);
  }
});

router.get('/copyright-strikes/mine', requireAuth, async (req, res, next) => {
  try {
    const channel = await pool.query(
      `SELECT id, handle, copyright_suspended_at
       FROM channels WHERE user_id = $1`,
      [req.currentUser.id]
    );
    if (!channel.rows[0]) {
      return res.json({ channel: null, activeStrikes: 0, suspended: false, strikes: [] });
    }
    const strikes = await pool.query(
      `SELECT s.id, s.source_type, s.reason, s.status, s.created_at,
              s.target_video_id, v.title AS video_title, latest_appeal.status AS appeal_status
       FROM copyright_strikes s
       LEFT JOIN videos v ON v.id = s.target_video_id
       LEFT JOIN LATERAL (
         SELECT ca.status FROM copyright_appeals ca
         WHERE ca.strike_id = s.id AND ca.appellant_id = $2
         ORDER BY ca.created_at DESC LIMIT 1
       ) latest_appeal ON TRUE
       WHERE s.channel_id = $1
       ORDER BY s.created_at DESC LIMIT 100`,
      [channel.rows[0].id, req.currentUser.id]
    );
    const active = strikes.rows.filter((strike) => strike.status === 'active').length;
    res.json({
      channel: { handle: channel.rows[0].handle },
      activeStrikes: active,
      suspended: Boolean(channel.rows[0].copyright_suspended_at),
      strikes: strikes.rows,
    });
  } catch (err) {
    next(err);
  }
});

router.post('/copyright-reports/:id/strike', requireModeration, async (req, res, next) => {
  try {
    const reportId = Number.parseInt(req.params.id, 10);
    const reason = text(req.body?.reason, 3000);
    if (!Number.isInteger(reportId) || !reason) {
      return res.status(400).json({ error: 'A copyright report and confirmation reason are required' });
    }
    const outcome = await inTransaction(async (client) => {
      const report = await client.query(
        `SELECT id, category, status, video_id
         FROM reports WHERE id = $1 FOR UPDATE`,
        [reportId]
      );
      if (!report.rows[0]) return { error: 'Report not found', status: 404 };
      if (report.rows[0].category !== 'copyright' || report.rows[0].status === 'dismissed') {
        return { error: 'Only an active copyright report can result in a strike', status: 400 };
      }
      if (!report.rows[0].video_id) return { error: 'This copyright report is not linked to a video', status: 400 };
      const strike = await addCopyrightStrike(client, {
        sourceType: 'copyright_report',
        sourceId: reportId,
        videoId: report.rows[0].video_id,
        reviewerId: req.currentUser.id,
        reason,
      });
      if (strike.error) return { error: strike.error, status: 404 };
      if (strike.duplicate) return { error: 'A strike has already been issued for this report', status: 409 };
      await client.query(
        `UPDATE reports
         SET status = 'resolved', resolution_note = $1, reviewed_by = $2, updated_at = NOW()
         WHERE id = $3`,
        [reason, req.currentUser.id, reportId]
      );
      return strike;
    });
    if (outcome.error) return res.status(outcome.status).json({ error: outcome.error });
    res.status(201).json({ strike: outcome });
  } catch (err) {
    next(err);
  }
});

router.get('/copyright-strikes', requireModeration, async (_req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT s.*, c.handle AS channel_handle, u.username AS channel_owner,
              v.title AS video_title,
              CASE WHEN s.source_type = 'dmca_notice' THEN cc.public_ref
                   ELSE 'Copyright report #' || s.source_id::text END AS source_reference,
              (SELECT COUNT(*)::integer FROM copyright_strikes active
               WHERE active.channel_id = s.channel_id AND active.status = 'active') AS active_channel_strikes
       FROM copyright_strikes s
       JOIN channels c ON c.id = s.channel_id
       JOIN users u ON u.id = c.user_id
       LEFT JOIN videos v ON v.id = s.target_video_id
       LEFT JOIN copyright_cases cc ON s.source_type = 'dmca_notice' AND cc.id = s.source_id
       ORDER BY s.created_at DESC LIMIT 500`
    );
    res.json({ strikes: result.rows });
  } catch (err) {
    next(err);
  }
});

router.post('/copyright-appeals', requireAuth, async (req, res, next) => {
  try {
    const strikeId = Number.parseInt(req.body?.strikeId, 10);
    const reason = text(req.body?.reason, 3000);
    if (!Number.isInteger(strikeId) || !reason) {
      return res.status(400).json({ error: 'Select an active copyright strike and provide an appeal reason' });
    }
    const ownership = await pool.query(
      `SELECT s.id, s.status
       FROM copyright_strikes s JOIN channels c ON c.id = s.channel_id
       WHERE s.id = $1 AND c.user_id = $2`,
      [strikeId, req.currentUser.id]
    );
    if (!ownership.rows[0]) return res.status(404).json({ error: 'Copyright strike not found for your channel' });
    if (ownership.rows[0].status !== 'active') return res.status(400).json({ error: 'Only active copyright strikes can be appealed' });
    const result = await pool.query(
      `INSERT INTO copyright_appeals (strike_id, appellant_id, reason)
       VALUES ($1, $2, $3)
       ON CONFLICT (strike_id) WHERE status IN ('open', 'investigating') DO NOTHING
       RETURNING id, strike_id, status, created_at`,
      [strikeId, req.currentUser.id, reason]
    );
    if (!result.rows[0]) return res.status(409).json({ error: 'An appeal for this strike is already under review' });
    res.status(201).json({ appeal: result.rows[0] });
  } catch (err) {
    next(err);
  }
});

router.get('/copyright-appeals', requireModeration, async (_req, res, next) => {
  try {
    const result = await pool.query(
      `SELECT ca.*, appellant.username AS appellant, c.handle AS channel_handle,
              s.reason AS strike_reason, s.status AS strike_status,
              v.title AS video_title
       FROM copyright_appeals ca
       JOIN users appellant ON appellant.id = ca.appellant_id
       JOIN copyright_strikes s ON s.id = ca.strike_id
       JOIN channels c ON c.id = s.channel_id
       LEFT JOIN videos v ON v.id = s.target_video_id
       ORDER BY CASE WHEN ca.status = 'open' THEN 0 WHEN ca.status = 'investigating' THEN 1 ELSE 2 END,
                ca.created_at DESC
       LIMIT 500`
    );
    res.json({ appeals: result.rows });
  } catch (err) {
    next(err);
  }
});

router.patch('/copyright-appeals/:id', requireModeration, async (req, res, next) => {
  try {
    const appealId = Number.parseInt(req.params.id, 10);
    const status = text(req.body?.status, 20);
    const note = text(req.body?.decisionNote, 3000);
    if (!Number.isInteger(appealId) || !['investigating', 'granted', 'denied'].includes(status)) {
      return res.status(400).json({ error: 'Choose investigating, granted, or denied for this appeal' });
    }
    const outcome = await inTransaction(async (client) => {
      const appeal = await client.query(
        `SELECT ca.id, ca.status, s.id AS strike_id, s.channel_id, s.status AS strike_status
         FROM copyright_appeals ca
         JOIN copyright_strikes s ON s.id = ca.strike_id
         WHERE ca.id = $1
         FOR UPDATE OF ca, s`,
        [appealId]
      );
      if (!appeal.rows[0]) return { error: 'Copyright appeal not found', status: 404 };
      if (['granted', 'denied'].includes(appeal.rows[0].status)) {
        return { error: 'This copyright appeal already has a final decision', status: 409 };
      }
      if (status === 'granted') {
        await client.query(
          `UPDATE copyright_strikes
           SET status = 'rescinded', rescinded_by = $1, rescinded_at = NOW()
           WHERE id = $2 AND status = 'active'`,
          [req.currentUser.id, appeal.rows[0].strike_id]
        );
      }
      const updated = await client.query(
        `UPDATE copyright_appeals
         SET status = $1, decision_note = $2, reviewer_id = $3, updated_at = NOW()
         WHERE id = $4
         RETURNING id, strike_id, status, decision_note, updated_at`,
        [status, note, req.currentUser.id, appealId]
      );
      const channel = await refreshCopyrightSuspension(client, appeal.rows[0].channel_id);
      return { appeal: updated.rows[0], ...channel };
    });
    if (outcome.error) return res.status(outcome.status).json({ error: outcome.error });
    res.json(outcome);
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