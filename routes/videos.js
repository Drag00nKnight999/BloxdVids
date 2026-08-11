import { Router } from 'express';
import multer from 'multer';
import pool from '../db.js';
import { uploadFile, downloadFile, deleteFile, videoKey, thumbnailKey } from '../storage.js';
import { requireAuth } from '../middleware/auth.js';

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

const storage = multer.memoryStorage();

const upload = multer({
  storage,
  limits: { fileSize: MAX_VIDEO_SIZE },
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
        if (err.code === 'LIMIT_FILE_SIZE') {
          return res.status(413).json({ error: 'Video file too large (max 5 GB)' });
        }
        return res.status(400).json({ error: err.message });
      }
      next();
    });
  },
  async (req, res) => {
    try {
      const videoFile = req.files?.video?.[0];
      if (!videoFile) return res.status(400).json({ error: 'Video file is required' });

      const { title, description } = req.body || {};
      if (!title || !title.trim()) return res.status(400).json({ error: 'Title is required' });
      if (title.trim().length > 255) return res.status(400).json({ error: 'Title too long (max 255 characters)' });

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
      const videoId = rows[0].id;

      // Build storage keys
      const ext = videoFile.originalname.split('.').pop()?.toLowerCase() || 'mp4';
      const safeExt = /^[a-zA-Z0-9]+$/.test(ext) ? ext : 'mp4';
      const vKey = `videos/${videoId}.${safeExt}`;

      // Upload video
      await uploadFile(vKey, videoFile.buffer, videoFile.mimetype);

      // Upload thumbnail if provided
      let tKey = null;
      const thumbFile = req.files?.thumbnail?.[0];
      if (thumbFile) {
        if (thumbFile.size > MAX_THUMB_SIZE) {
          await pool.query('DELETE FROM videos WHERE id = $1', [videoId]);
          return res.status(413).json({ error: 'Thumbnail too large (max 10 MB)' });
        }
        tKey = `thumbnails/${videoId}.jpg`;
        await uploadFile(tKey, thumbFile.buffer, thumbFile.mimetype);
      }

      // Update row with real keys
      await pool.query(
        'UPDATE videos SET storage_key = $1, thumbnail_key = $2 WHERE id = $3',
        [vKey, tKey, videoId]
      );

      res.status(201).json({
        video: { id: videoId, title: title.trim(), description: (description || '').trim() },
      });
    } catch (err) {
      console.error('Upload error:', err);
      res.status(500).json({ error: 'Upload failed' });
    }
  }
);

// DELETE /api/videos/:id — delete a video (auth required, owner only)
router.delete('/:id', requireAuth, async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) return res.status(400).json({ error: 'Invalid video ID' });

    const result = await pool.query(
      'SELECT * FROM videos WHERE id = $1 AND user_id = $2',
      [id, req.session.userId]
    );
    const video = result.rows[0];
    if (!video) return res.status(404).json({ error: 'Video not found or you do not own it' });

    // Delete from storage (best-effort)
    await Promise.allSettled([
      video.storage_key && video.storage_key !== 'pending'
        ? deleteFile(video.storage_key)
        : Promise.resolve(),
      video.thumbnail_key ? deleteFile(video.thumbnail_key) : Promise.resolve(),
    ]);

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

    const buffer = await downloadFile(video.storage_key);
    const total = buffer.length;
    const rangeHeader = req.headers.range;

    if (rangeHeader) {
      const [startStr, endStr] = rangeHeader.replace(/bytes=/, '').split('-');
      const start = parseInt(startStr, 10);
      const end = endStr ? parseInt(endStr, 10) : Math.min(start + 1024 * 1024 - 1, total - 1);

      if (start >= total || end >= total || start > end) {
        return res.status(416).set('Content-Range', `bytes */${total}`).end();
      }

      res.writeHead(206, {
        'Content-Range': `bytes ${start}-${end}/${total}`,
        'Accept-Ranges': 'bytes',
        'Content-Length': end - start + 1,
        'Content-Type': video.mime_type,
        'Cache-Control': 'public, max-age=3600',
      });
      res.end(buffer.slice(start, end + 1));
    } else {
      res.writeHead(200, {
        'Content-Length': total,
        'Content-Type': video.mime_type,
        'Accept-Ranges': 'bytes',
        'Cache-Control': 'public, max-age=3600',
      });
      res.end(buffer);
    }
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

    const result = await pool.query('SELECT thumbnail_key FROM videos WHERE id = $1', [id]);
    const video = result.rows[0];

    if (!video?.thumbnail_key) {
      // Redirect to a default placeholder
      return res.redirect('/placeholder-thumb.svg');
    }

    const buffer = await downloadFile(video.thumbnail_key);
    res.set({
      'Content-Type': 'image/jpeg',
      'Cache-Control': 'public, max-age=86400',
    });
    res.send(Buffer.from(buffer));
  } catch (err) {
    console.error('Thumbnail error:', err);
    res.redirect('/placeholder-thumb.svg');
  }
});

// GET /api/videos/my/uploads — list the authenticated user's videos
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

function stripStorageKey(video) {
  const { storage_key, ...rest } = video;
  return rest;
}

export default router;
