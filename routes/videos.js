import { Router } from 'express';
import multer from 'multer';
import crypto from 'node:crypto';
import fs from 'node:fs';
import fsPromises from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import pool from '../db.js';
import { uploadFileFromFilename, downloadStream, deleteFile } from '../storage.js';
import {
  requireAuth, requireModeration, requireUploadAccess,
  isOwnerAdmin, isModerator, isCurrentlyBanned, isCurrentlyRestricted,
} from '../middleware/auth.js';

const router = Router();

// Allowed MIME types for videos
const ALLOWED_VIDEO_TYPES = new Set([
  'video/mp4', 'video/webm', 'video/ogg', 'video/quicktime',
  'video/x-msvideo', 'video/x-matroska', 'video/mpeg',
]);
const ALLOWED_IMAGE_TYPES = new Set([
  'image/jpeg', 'image/png', 'image/webp', 'image/gif',
]);

const MAX_VIDEO_SIZE = 10 * 1024 * 1024 * 1024; // 10 GB
const MAX_THUMB_SIZE = 10 * 1024 * 1024;        // 10 MB
const VIDEO_CATEGORIES = new Set([
  'Gaming', 'Entertainment', 'Education', 'Music', 'News', 'Sports', 'Technology', 'Other',
]);
const TEMP_UPLOAD_DIR = path.join(os.tmpdir(), 'bloxdvids-uploads');
fs.mkdirSync(TEMP_UPLOAD_DIR, { recursive: true });

const storage = multer.diskStorage({
  destination: TEMP_UPLOAD_DIR,
  filename: (_req, file, cb) => {
    cb(null, `${crypto.randomUUID()}-${file.fieldname}`);
  },
});

const upload = multer({
  storage,
  limits: {
    fileSize: MAX_VIDEO_SIZE,
    files: 2,
    fields: 5,
    parts: 8,
    fieldNameSize: 100,
    fieldSize: 100 * 1024,
    headerPairs: 200,
  },
  fileFilter(_req, file, cb) {
    if (file.fieldname === 'video' && ALLOWED_VIDEO_TYPES.has(file.mimetype)) {
      cb(null, true);
    } else if (file.fieldname === 'thumbnail' && ALLOWED_IMAGE_TYPES.has(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error(`Invalid file type: ${file.mimetype}`));
    }
  },
});

const thumbnailUpload = multer({
  storage,
  limits: {
    fileSize: MAX_THUMB_SIZE,
    files: 1,
    fields: 0,
    parts: 1,
    fieldNameSize: 100,
    headerPairs: 200,
  },
  fileFilter(_req, file, cb) {
    cb(ALLOWED_IMAGE_TYPES.has(file.mimetype) ? null : new Error(`Invalid file type: ${file.mimetype}`),
      ALLOWED_IMAGE_TYPES.has(file.mimetype));
  },
});

// GET /api/videos  — list / search
router.get('/', async (req, res) => {
  try {
    const { q, category, sort = 'recent', page = 1, limit = 20 } = req.query;
    const pageNum = Math.max(1, parseInt(page, 10) || 1);
    const limitNum = Math.min(100, Math.max(1, parseInt(limit, 10) || 20));
    const offset = (pageNum - 1) * limitNum;

    const params = [];
    const conditions = [];
    let query;
    if (q && q.trim()) {
      params.push(q.trim(), `%${q.trim()}%`);
      conditions.push(`(
        to_tsvector('english', v.title || ' ' || COALESCE(v.description, '') || ' ' || COALESCE(c.name, ''))
          @@ plainto_tsquery('english', $${params.length - 1})
        OR v.title ILIKE $${params.length}
        OR c.name ILIKE $${params.length}
      )`);
    }
    if (category && VIDEO_CATEGORIES.has(category)) {
      params.push(category);
      conditions.push(`v.category = $${params.length}`);
    }
    const orderBy = sort === 'trending'
      ? '(v.view_count * 1.0 + (SELECT COUNT(*) FROM video_likes vl WHERE vl.video_id = v.id) * 8) / GREATEST(EXTRACT(EPOCH FROM (NOW() - v.created_at)) / 86400 + 2, 2) DESC, v.created_at DESC'
      : 'v.created_at DESC';
    params.push(limitNum, offset);
    query = `
       SELECT v.id, v.title, v.description, v.thumbnail_key, v.view_count, v.category,
              v.created_at, v.file_size, v.mime_type,
              (SELECT COUNT(*) FROM video_likes vl WHERE vl.video_id = v.id)::int AS like_count,
              u.username AS uploader, c.handle AS channel_handle, c.name AS channel_name,
              COUNT(*) OVER() AS total_count
      FROM videos v
      JOIN users u ON u.id = v.user_id
       LEFT JOIN channels c ON c.user_id = u.id
      ${conditions.length ? `WHERE ${conditions.join(' AND ')}` : ''}
      ORDER BY ${orderBy}
      LIMIT $${params.length - 1} OFFSET $${params.length}
    `;

    const result = await pool.query(query, params);
    const total = result.rows[0]?.total_count ?? 0;

    res.json({
      videos: result.rows.map(stripStorageKey),
      pagination: {
        total: parseInt(total, 10),
        page: pageNum,
        limit: limitNum,
        pages: Math.ceil(total / limitNum),
      },
    });
  } catch (err) {
    console.error('List videos error:', err);
    res.status(500).json({ error: 'Failed to load videos' });
  }
});

// GET /api/videos/manage — moderator/admin moderation list
router.get('/manage', requireModeration, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT v.id, v.title, v.description, v.thumbnail_key, v.view_count,
              v.created_at, v.file_size, v.mime_type, u.username AS uploader
       FROM videos v JOIN users u ON u.id = v.user_id
       ORDER BY v.created_at DESC`
    );
    res.json({ videos: result.rows.map(stripStorageKey) });
  } catch (err) {
    console.error('Manage videos error:', err);
    res.status(500).json({ error: 'Failed to load moderation queue' });
  }
});

// GET /api/videos/my/uploads — list the authenticated user's videos
// This must be declared before /:id so "my" is not parsed as a video ID.
router.get('/my/uploads', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT v.id, v.title, v.description, v.thumbnail_key, v.view_count,
              v.created_at, v.file_size, v.mime_type, v.category,
              (SELECT COUNT(*) FROM video_likes vl WHERE vl.video_id = v.id)::int AS like_count
       FROM videos v
       WHERE v.user_id = $1
       ORDER BY v.created_at DESC`,
      [req.session.userId]
    );
    res.json({ videos: result.rows.map(stripStorageKey) });
  } catch (err) {
    console.error('My uploads error:', err);
    res.status(500).json({ error: 'Failed to load uploads' });
  }
});

// GET /api/videos/:id — single video metadata
router.get('/:id', async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) return res.status(400).json({ error: 'Invalid video ID' });

    const result = await pool.query(
       `SELECT v.*, u.username AS uploader, c.handle AS channel_handle, c.name AS channel_name
        FROM videos v JOIN users u ON u.id = v.user_id
        LEFT JOIN channels c ON c.user_id = u.id
       WHERE v.id = $1`,
      [id]
    );
    if (!result.rows[0]) return res.status(404).json({ error: 'Video not found' });

    const viewUpdate = await pool.query(
      'UPDATE videos SET view_count = view_count + 1 WHERE id = $1 RETURNING view_count',
      [id]
    );
    result.rows[0].view_count = viewUpdate.rows[0]?.view_count ?? result.rows[0].view_count;
    const likeCount = await pool.query(
      'SELECT COUNT(*)::int AS count FROM video_likes WHERE video_id = $1',
      [id]
    );
    result.rows[0].like_count = likeCount.rows[0].count;
    if (req.session?.userId) {
      const liked = await pool.query(
        'SELECT 1 FROM video_likes WHERE video_id = $1 AND user_id = $2',
        [id, req.session.userId]
      );
      result.rows[0].liked = Boolean(liked.rows[0]);
    } else {
      result.rows[0].liked = false;
    }

    res.json(stripStorageKey(result.rows[0]));
  } catch (err) {
    console.error('Get video error:', err);
    res.status(500).json({ error: 'Failed to load video' });
  }
});

// POST /api/videos — upload a new video (auth required)
router.post(
  '/',
  requireUploadAccess,
  (req, res, next) => {
    upload.fields([
      { name: 'video', maxCount: 1 },
      { name: 'thumbnail', maxCount: 1 },
    ])(req, res, (err) => {
      if (err) {
        const partialFiles = Object.values(req.files || {}).flat();
        Promise.allSettled(partialFiles.map((file) => fsPromises.rm(file.path, { force: true }))).finally(() => {
          if (err.code === 'LIMIT_FILE_SIZE') {
            return res.status(413).json({ error: 'Video file too large (max 10 GB)' });
          }
          return res.status(400).json({ error: err.message });
        });
        return;
      }
      next();
    });
  },
  async (req, res) => {
    let videoId = null;
    let uploadedVideoKey = null;
    let uploadedThumbnailKey = null;
    const tempFiles = Object.values(req.files || {}).flat().map((file) => file.path);
    try {
      const videoFile = req.files?.video?.[0];
      if (!videoFile) return res.status(400).json({ error: 'Video file is required' });

       const { title, description } = req.body || {};
       const category = typeof req.body?.category === 'string' && VIDEO_CATEGORIES.has(req.body.category)
         ? req.body.category
         : 'Other';
      if (!title || !title.trim()) return res.status(400).json({ error: 'Title is required' });
      if (title.trim().length > 255) return res.status(400).json({ error: 'Title too long (max 255 characters)' });
      if (req.body?.content_policy_ack !== 'on') {
        return res.status(400).json({ error: 'Please confirm that you have the rights to upload this content and that it follows our content rules' });
      }

      const thumbFile = req.files?.thumbnail?.[0];
      if (thumbFile) {
        if (thumbFile.size > MAX_THUMB_SIZE) {
          return res.status(413).json({ error: 'Thumbnail too large (max 10 MB)' });
        }
      }

      if (!await hasValidFileSignature(videoFile.path, videoFile.mimetype, false)) {
        return res.status(400).json({ error: 'The video file contents do not match its declared type' });
      }
      if (thumbFile && !await hasValidFileSignature(thumbFile.path, thumbFile.mimetype, true)) {
        return res.status(400).json({ error: 'The thumbnail file contents do not match its declared type' });
      }

      // Reserve a DB row first to get an ID for the storage key
      const { rows } = await pool.query(
         `INSERT INTO videos (user_id, title, description, category, storage_key, mime_type, file_size)
          VALUES ($1, $2, $3, $4, $5, $6, $7)
         RETURNING id`,
        [
          req.session.userId,
          title.trim(),
          (description || '').trim().slice(0, 5000),
           category,
          'pending',
          videoFile.mimetype,
          videoFile.size,
        ]
      );
      videoId = rows[0].id;

      // Build storage keys
      const ext = videoFile.originalname.split('.').pop()?.toLowerCase() || 'mp4';
      const safeExt = /^[a-zA-Z0-9]+$/.test(ext) ? ext : 'mp4';
      const vKey = `videos/${videoId}.${safeExt}`;

      // Upload video
      await uploadFileFromFilename(vKey, videoFile.path, videoFile.mimetype);
      uploadedVideoKey = vKey;

      // Upload thumbnail if provided
      let tKey = null;
      if (thumbFile) {
        tKey = `thumbnails/${videoId}.jpg`;
        await uploadFileFromFilename(tKey, thumbFile.path, thumbFile.mimetype);
        uploadedThumbnailKey = tKey;
      }

      // Update row with real keys
      await pool.query(
        'UPDATE videos SET storage_key = $1, thumbnail_key = $2, thumbnail_mime_type = $3 WHERE id = $4',
        [vKey, tKey, thumbFile?.mimetype || null, videoId]
      );

      res.status(201).json({
        video: { id: videoId, title: title.trim(), description: (description || '').trim(), category },
      });
    } catch (err) {
      console.error('Upload error:', err);
      await Promise.allSettled([
        uploadedVideoKey ? deleteFile(uploadedVideoKey) : Promise.resolve(),
        uploadedThumbnailKey ? deleteFile(uploadedThumbnailKey) : Promise.resolve(),
        videoId ? pool.query('DELETE FROM videos WHERE id = $1', [videoId]) : Promise.resolve(),
      ]);
      const storageMessage = String(err?.message || '');
      if (/bucket name|storage|cloud storage/i.test(storageMessage)) {
        return res.status(503).json({
          error: 'Video storage is unavailable right now. Please try again later.',
        });
      }
      res.status(500).json({ error: 'Upload failed while processing the video' });
    } finally {
      await Promise.allSettled(tempFiles.map((file) => fsPromises.rm(file, { force: true })));
    }
  }
);

// PATCH /api/videos/:id — owners can edit public metadata
router.patch('/:id', requireAuth, async (req, res) => {
  try {
    const id = Number.parseInt(req.params.id, 10);
    const title = typeof req.body?.title === 'string' ? req.body.title.trim() : '';
    const description = typeof req.body?.description === 'string' ? req.body.description.trim() : '';
    const category = typeof req.body?.category === 'string' ? req.body.category.trim() : '';
    if (!Number.isInteger(id) || !title || title.length > 255 || description.length > 5000) {
      return res.status(400).json({ error: 'Title is required and fields are too long' });
    }
    if (!VIDEO_CATEGORIES.has(category)) return res.status(400).json({ error: 'Choose a valid category' });
    const result = await pool.query(
      `UPDATE videos SET title = $1, description = $2, category = $3, updated_at = NOW()
       WHERE id = $4 AND user_id = $5
       RETURNING id, title, description, category, updated_at`,
      [title, description, category, id, req.session.userId]
    );
    if (!result.rows[0]) return res.status(404).json({ error: 'Video not found or you do not own it' });
    res.json({ video: result.rows[0] });
  } catch (err) {
    console.error('Edit video error:', err);
    res.status(500).json({ error: 'Could not update video' });
  }
});

// PATCH /api/videos/:id/thumbnail — owners can replace a thumbnail
router.patch('/:id/thumbnail', requireAuth, (req, res, next) => {
  thumbnailUpload.single('thumbnail')(req, res, (err) => {
    if (err) return res.status(err.code === 'LIMIT_FILE_SIZE' ? 413 : 400).json({
      error: err.code === 'LIMIT_FILE_SIZE' ? 'Thumbnail too large (max 10 MB)' : err.message,
    });
    next();
  });
}, async (req, res) => {
  const file = req.file;
  let newKey = null;
  try {
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(id) || !file) return res.status(400).json({ error: 'A thumbnail image is required' });
    if (file.size > MAX_THUMB_SIZE) return res.status(413).json({ error: 'Thumbnail too large (max 10 MB)' });
    if (!await hasValidFileSignature(file.path, file.mimetype, true)) {
      return res.status(400).json({ error: 'The thumbnail contents do not match its declared type' });
    }
    const current = await pool.query(
      'SELECT thumbnail_key FROM videos WHERE id = $1 AND user_id = $2',
      [id, req.session.userId]
    );
    if (!current.rows[0]) return res.status(404).json({ error: 'Video not found or you do not own it' });
    newKey = `thumbnails/${id}-${crypto.randomUUID()}`;
    await uploadFileFromFilename(newKey, file.path, file.mimetype);
    await pool.query(
      'UPDATE videos SET thumbnail_key = $1, thumbnail_mime_type = $2, updated_at = NOW() WHERE id = $3',
      [newKey, file.mimetype, id]
    );
    if (current.rows[0].thumbnail_key) await deleteFile(current.rows[0].thumbnail_key).catch(() => {});
    res.json({ success: true });
  } catch (err) {
    if (newKey) await deleteFile(newKey).catch(() => {});
    console.error('Edit thumbnail error:', err);
    res.status(500).json({ error: 'Could not update thumbnail' });
  } finally {
    if (file?.path) await fsPromises.rm(file.path, { force: true });
  }
});

// GET /api/videos/:id/comments
router.get('/:id/comments', async (req, res) => {
  try {
    const id = Number.parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) return res.status(400).json({ error: 'Invalid video ID' });
    const result = await pool.query(
      `SELECT c.id, c.content, c.created_at, c.updated_at, u.id AS user_id, u.username
       FROM video_comments c JOIN users u ON u.id = c.user_id
       WHERE c.video_id = $1 ORDER BY c.created_at DESC LIMIT 200`,
      [id]
    );
    res.json({ comments: result.rows });
  } catch (err) {
    console.error('List comments error:', err);
    res.status(500).json({ error: 'Failed to load comments' });
  }
});

router.post('/:id/comments', requireAuth, async (req, res) => {
  try {
    const id = Number.parseInt(req.params.id, 10);
    const content = typeof req.body?.content === 'string' ? req.body.content.trim().slice(0, 2000) : '';
    if (!Number.isInteger(id) || !content) return res.status(400).json({ error: 'Comment text is required' });
    const video = await pool.query('SELECT 1 FROM videos WHERE id = $1', [id]);
    if (!video.rows[0]) return res.status(404).json({ error: 'Video not found' });
    const result = await pool.query(
      `INSERT INTO video_comments (video_id, user_id, content)
       VALUES ($1, $2, $3)
       RETURNING id, content, created_at, updated_at`,
      [id, req.session.userId, content]
    );
    res.status(201).json({ comment: { ...result.rows[0], user_id: req.currentUser.id, username: req.currentUser.username } });
  } catch (err) {
    console.error('Create comment error:', err);
    res.status(500).json({ error: 'Could not post comment' });
  }
});

router.delete('/:id/comments/:commentId', requireAuth, async (req, res) => {
  try {
    const commentId = Number.parseInt(req.params.commentId, 10);
    const result = await pool.query(
      `DELETE FROM video_comments c
       USING users u
       WHERE c.id = $1 AND c.user_id = u.id
         AND (c.user_id = $2 OR $3 = TRUE)
       RETURNING c.id`,
      [commentId, req.session.userId, isOwnerAdmin(req.currentUser) || isModerator(req.currentUser)]
    );
    if (!result.rows[0]) return res.status(404).json({ error: 'Comment not found or not removable' });
    res.json({ success: true });
  } catch (err) {
    console.error('Delete comment error:', err);
    res.status(500).json({ error: 'Could not delete comment' });
  }
});

router.post('/:id/like', requireAuth, async (req, res) => {
  try {
    const id = Number.parseInt(req.params.id, 10);
    const result = await pool.query(
      `INSERT INTO video_likes (video_id, user_id) VALUES ($1, $2)
       ON CONFLICT DO NOTHING RETURNING video_id`,
      [id, req.session.userId]
    );
    if (!result.rows[0]) {
      const exists = await pool.query('SELECT 1 FROM videos WHERE id = $1', [id]);
      if (!exists.rows[0]) return res.status(404).json({ error: 'Video not found' });
    }
    const count = await pool.query('SELECT COUNT(*)::int AS count FROM video_likes WHERE video_id = $1', [id]);
    res.json({ liked: true, likeCount: count.rows[0].count });
  } catch (err) {
    console.error('Like video error:', err);
    res.status(500).json({ error: 'Could not like video' });
  }
});

router.delete('/:id/like', requireAuth, async (req, res) => {
  try {
    const id = Number.parseInt(req.params.id, 10);
    await pool.query('DELETE FROM video_likes WHERE video_id = $1 AND user_id = $2', [id, req.session.userId]);
    const count = await pool.query('SELECT COUNT(*)::int AS count FROM video_likes WHERE video_id = $1', [id]);
    res.json({ liked: false, likeCount: count.rows[0].count });
  } catch (err) {
    console.error('Unlike video error:', err);
    res.status(500).json({ error: 'Could not remove like' });
  }
});

// DELETE /api/videos/:id — owner deletion or moderator/admin content moderation
router.delete('/:id', requireAuth, async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) return res.status(400).json({ error: 'Invalid video ID' });

    if (isCurrentlyBanned(req.currentUser)
      || (isCurrentlyRestricted(req.currentUser) && req.currentUser.restriction_type !== 'reporting')) {
      return res.status(403).json({ error: 'Your account is currently restricted' });
    }
    const elevated = isOwnerAdmin(req.currentUser) || isModerator(req.currentUser);
    const result = await pool.query(
      elevated
        ? 'SELECT * FROM videos WHERE id = $1'
        : 'SELECT * FROM videos WHERE id = $1 AND user_id = $2',
      elevated ? [id] : [id, req.session.userId]
    );
    const video = result.rows[0];
    if (!video) return res.status(404).json({ error: 'Video not found or you do not own it' });

    // Delete from storage (best-effort)
    try {
      await Promise.all([
        video.storage_key && video.storage_key !== 'pending'
          ? deleteFile(video.storage_key)
          : Promise.resolve(),
        video.thumbnail_key ? deleteFile(video.thumbnail_key) : Promise.resolve(),
      ]);
    } catch (storageError) {
      console.error('Delete storage error:', storageError);
      return res.status(502).json({ error: 'Video storage is temporarily unavailable. Please try again.' });
    }

    await pool.query('DELETE FROM videos WHERE id = $1', [id]);
    res.json({ success: true });
  } catch (err) {
    console.error('Delete video error:', err);
    res.status(500).json({ error: 'Delete failed' });
  }
});

// GET /api/videos/:id/stream — stream the video from storage
router.get('/:id/stream', async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) return res.status(400).json({ error: 'Invalid video ID' });

    const result = await pool.query('SELECT storage_key, mime_type, file_size FROM videos WHERE id = $1', [id]);
    const video = result.rows[0];
    if (!video || video.storage_key === 'pending') return res.status(404).json({ error: 'Video not found' });

    // Stream directly from App Storage instead of buffering multi-GB files in RAM.
    // The SDK does not expose byte-range downloads, so seeking is intentionally
    // disabled rather than advertising incorrect range support.
    const stream = downloadStream(video.storage_key);
    res.writeHead(200, {
      'Content-Length': video.file_size,
      'Accept-Ranges': 'none',
      'Content-Type': video.mime_type,
      'Cache-Control': 'public, max-age=3600',
    });
    stream.on('error', (err) => {
      console.error('Storage stream error:', err);
      if (!res.headersSent) res.status(500).json({ error: 'Stream failed' });
      else res.destroy(err);
    });
    stream.pipe(res);
  } catch (err) {
    console.error('Stream error:', err);
    res.status(500).json({ error: 'Stream failed' });
  }
});

// GET /api/videos/:id/thumbnail — serve the thumbnail
router.get('/:id/thumbnail', async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) return res.status(400).end();

    const result = await pool.query('SELECT thumbnail_key, thumbnail_mime_type FROM videos WHERE id = $1', [id]);
    const video = result.rows[0];

    if (!video?.thumbnail_key) {
      // Redirect to a default placeholder
      return res.redirect('/placeholder-thumb.svg');
    }

    const stream = downloadStream(video.thumbnail_key);
    res.set({
      'Content-Type': video.thumbnail_mime_type || 'image/jpeg',
      'Cache-Control': 'public, max-age=86400',
    });
    stream.on('error', () => {
      if (!res.headersSent) res.redirect('/placeholder-thumb.svg');
      else res.destroy();
    });
    stream.pipe(res);
  } catch (err) {
    console.error('Thumbnail error:', err);
    res.redirect('/placeholder-thumb.svg');
  }
});

function stripStorageKey(video) {
  const { storage_key, ...rest } = video;
  return rest;
}

async function hasValidFileSignature(filename, mimeType, isImage) {
  const handle = await fsPromises.open(filename, 'r');
  try {
    const header = Buffer.alloc(32);
    const { bytesRead } = await handle.read(header, 0, header.length, 0);
    const bytes = header.subarray(0, bytesRead);

    if (isImage) {
      return (
        (mimeType === 'image/jpeg' && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) ||
        (mimeType === 'image/png' && bytes.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]))) ||
        (mimeType === 'image/gif' && (bytes.subarray(0, 6).toString() === 'GIF87a' || bytes.subarray(0, 6).toString() === 'GIF89a')) ||
        (mimeType === 'image/webp' && bytes.subarray(0, 4).toString() === 'RIFF' && bytes.subarray(8, 12).toString() === 'WEBP')
      );
    }

    return (
      (mimeType === 'video/mp4' || mimeType === 'video/quicktime') && bytes.subarray(4, 8).toString() === 'ftyp' ||
      (mimeType === 'video/webm' || mimeType === 'video/x-matroska') && bytes.subarray(0, 4).equals(Buffer.from([0x1a, 0x45, 0xdf, 0xa3])) ||
      mimeType === 'video/ogg' && bytes.subarray(0, 4).toString() === 'OggS' ||
      mimeType === 'video/x-msvideo' && bytes.subarray(0, 4).toString() === 'RIFF' && bytes.subarray(8, 12).toString() === 'AVI ' ||
      mimeType === 'video/mpeg' && (bytes.subarray(0, 3).toString() === 'ID3' || bytes[0] === 0x00 && bytes[1] === 0x00 && bytes[2] === 0x01)
    );
  } finally {
    await handle.close();
  }
}

export default router;
