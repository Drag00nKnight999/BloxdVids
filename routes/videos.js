import { Router } from 'express';
import multer from 'multer';
import crypto from 'node:crypto';
import fs from 'node:fs';
import fsPromises from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import pool from '../db.js';
import { uploadFileFromFilename, downloadStream, deleteFile } from '../storage.js';
import { requireAuth, requireOwnerAdmin } from '../middleware/auth.js';

const router = Router();

// Allowed MIME types for videos
const ALLOWED_VIDEO_TYPES = new Set([
  'video/mp4', 'video/webm', 'video/ogg', 'video/quicktime',
  'video/x-msvideo', 'video/x-matroska', 'video/mpeg',
]);
const ALLOWED_IMAGE_TYPES = new Set([
  'image/jpeg', 'image/png', 'image/webp', 'image/gif',
]);

const MAX_VIDEO_SIZE = 5 * 1024 * 1024 * 1024; // 5 GB
const MAX_THUMB_SIZE = 10 * 1024 * 1024;        // 10 MB
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
    fields: 3,
    parts: 5,
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

// GET /api/videos  — list / search
router.get('/', async (req, res) => {
  try {
    const { q, page = 1, limit = 20 } = req.query;
    const pageNum = Math.max(1, parseInt(page, 10) || 1);
    const limitNum = Math.min(100, Math.max(1, parseInt(limit, 10) || 20));
    const offset = (pageNum - 1) * limitNum;

    let query, params;
    if (q && q.trim()) {
      const search = q.trim();
      query = `
        SELECT v.id, v.title, v.description, v.thumbnail_key, v.view_count,
               v.created_at, v.file_size, v.mime_type,
               u.username AS uploader,
               COUNT(*) OVER() AS total_count
        FROM videos v
        JOIN users u ON u.id = v.user_id
        WHERE to_tsvector('english', v.title || ' ' || COALESCE(v.description, ''))
              @@ plainto_tsquery('english', $1)
           OR v.title ILIKE $2
        ORDER BY v.created_at DESC
        LIMIT $3 OFFSET $4
      `;
      params = [search, `%${search}%`, limitNum, offset];
    } else {
      query = `
        SELECT v.id, v.title, v.description, v.thumbnail_key, v.view_count,
               v.created_at, v.file_size, v.mime_type,
               u.username AS uploader,
               COUNT(*) OVER() AS total_count
        FROM videos v
        JOIN users u ON u.id = v.user_id
        ORDER BY v.created_at DESC
        LIMIT $1 OFFSET $2
      `;
      params = [limitNum, offset];
    }

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

// GET /api/videos/manage — owner-only moderation list
router.get('/manage', requireOwnerAdmin, async (req, res) => {
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
              v.created_at, v.file_size, v.mime_type
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
      `SELECT v.*, u.username AS uploader
       FROM videos v JOIN users u ON u.id = v.user_id
       WHERE v.id = $1`,
      [id]
    );
    if (!result.rows[0]) return res.status(404).json({ error: 'Video not found' });

    // Increment view count asynchronously
    pool.query('UPDATE videos SET view_count = view_count + 1 WHERE id = $1', [id]).catch(() => {});

    res.json(stripStorageKey(result.rows[0]));
  } catch (err) {
    console.error('Get video error:', err);
    res.status(500).json({ error: 'Failed to load video' });
  }
});

// POST /api/videos — upload a new video (auth required)
router.post(
  '/',
  requireAuth,
  (req, res, next) => {
    upload.fields([
      { name: 'video', maxCount: 1 },
      { name: 'thumbnail', maxCount: 1 },
    ])(req, res, (err) => {
      if (err) {
        const partialFiles = Object.values(req.files || {}).flat();
        Promise.allSettled(partialFiles.map((file) => fsPromises.rm(file.path, { force: true }))).finally(() => {
          if (err.code === 'LIMIT_FILE_SIZE') {
            return res.status(413).json({ error: 'Video file too large (max 5 GB)' });
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
        `INSERT INTO videos (user_id, title, description, storage_key, mime_type, file_size)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING id`,
        [
          req.session.userId,
          title.trim(),
          (description || '').trim().slice(0, 5000),
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
        video: { id: videoId, title: title.trim(), description: (description || '').trim() },
      });
    } catch (err) {
      console.error('Upload error:', err);
      await Promise.allSettled([
        uploadedVideoKey ? deleteFile(uploadedVideoKey) : Promise.resolve(),
        uploadedThumbnailKey ? deleteFile(uploadedThumbnailKey) : Promise.resolve(),
        videoId ? pool.query('DELETE FROM videos WHERE id = $1', [videoId]) : Promise.resolve(),
      ]);
      res.status(500).json({ error: 'Upload failed' });
    } finally {
      await Promise.allSettled(tempFiles.map((file) => fsPromises.rm(file, { force: true })));
    }
  }
);

// DELETE /api/videos/:id — delete a video (auth required, owner only)
router.delete('/:id', requireAuth, async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) return res.status(400).json({ error: 'Invalid video ID' });

    const isOwnerAdmin = req.session.role === 'owner' && req.session.previewMode === false;
    const result = await pool.query(
      isOwnerAdmin
        ? 'SELECT * FROM videos WHERE id = $1'
        : 'SELECT * FROM videos WHERE id = $1 AND user_id = $2',
      isOwnerAdmin ? [id] : [id, req.session.userId]
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
