'use strict';

/**
 * TDub — Express REST API
 * MongoDB Atlas (Mongoose) + CORS for Cloudflare Pages + password-protected uploads.
 *
 * Env vars:
 *   MONGODB_URI      MongoDB Atlas connection string (required)
 *   ADMIN_PASSWORD   Password for the admin dashboard / POST endpoint (required, 8+ chars)
 *   PORT             Port to listen on (default 5000)
 *   ALLOWED_ORIGINS  Comma-separated list of allowed frontend origins.
 *                    Supports wildcards like https://*.tdub.pages.dev
 */

require('dotenv').config();

const crypto = require('crypto');
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

/* ------------------------------------------------------------------ */
/* Config                                                              */
/* ------------------------------------------------------------------ */

const MONGODB_URI = process.env.MONGODB_URI;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const PORT = Number(process.env.PORT) || 5000;
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map((s) => s.trim().replace(/\/+$/, ''))
  .filter(Boolean);

if (!MONGODB_URI) {
  console.error('[TDub] Missing MONGODB_URI environment variable.');
  process.exit(1);
}
if (!ADMIN_PASSWORD || ADMIN_PASSWORD.length < 8) {
  console.error('[TDub] ADMIN_PASSWORD must be set and at least 8 characters long.');
  process.exit(1);
}

/* ------------------------------------------------------------------ */
/* Mongoose models                                                     */
/* ------------------------------------------------------------------ */

const sourceSchema = new mongoose.Schema(
  {
    serverName: { type: String, trim: true, required: true, maxlength: 80 },
    url: { type: String, trim: true, required: true, maxlength: 2048 },
  },
  { _id: false }
);

const episodeSchema = new mongoose.Schema(
  {
    season: { type: Number, required: true, min: 0, max: 1000 },
    episodeNumber: { type: Number, required: true, min: 0, max: 100000 },
    title: { type: String, trim: true, default: '', maxlength: 200 },
    sources: { type: [sourceSchema], default: [] },
  },
  { _id: false }
);

const videoSchema = new mongoose.Schema(
  {
    title: { type: String, required: true, trim: true, maxlength: 200 },
    description: { type: String, trim: true, default: '', maxlength: 5000 },
    posterUrl: { type: String, trim: true, default: '', maxlength: 2048 },
    type: { type: String, required: true, enum: ['movie', 'series'] },
    genre: { type: [String], default: [] },
    qualityBadge: { type: String, enum: ['HD', '4K'], default: 'HD' },
    sources: { type: [sourceSchema], default: [] }, // movies
    episodes: { type: [episodeSchema], default: [] }, // series
  },
  { timestamps: true }
);

videoSchema.index({ createdAt: -1 });
videoSchema.index({ type: 1, createdAt: -1 });

const Video = mongoose.model('Video', videoSchema);

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function isHttpUrl(value) {
  try {
    const u = new URL(value);
    return u.protocol === 'https:' || u.protocol === 'http:';
  } catch {
    return false;
  }
}

function str(value, max) {
  return String(value ?? '').trim().slice(0, max);
}

function cleanSources(list, label) {
  if (!Array.isArray(list)) return [];
  const out = [];
  list.forEach((s, i) => {
    const url = str(s && s.url, 2048);
    if (!url) return; // skip empty rows
    if (!isHttpUrl(url)) {
      throw new HttpError(400, `${label}: source #${i + 1} is not a valid http(s) URL.`);
    }
    out.push({
      serverName: str(s && s.serverName, 80) || `Server ${out.length + 1}`,
      url,
    });
  });
  return out;
}

/** Validates and normalises a POST body into a Video document payload. */
function buildVideoPayload(body) {
  if (!body || typeof body !== 'object') throw new HttpError(400, 'Request body must be JSON.');

  const title = str(body.title, 200);
  if (!title) throw new HttpError(400, 'Title is required.');

  const type = str(body.type, 10).toLowerCase();
  if (!['movie', 'series'].includes(type)) {
    throw new HttpError(400, 'Type must be "movie" or "series".');
  }

  const posterUrl = str(body.posterUrl, 2048);
  if (posterUrl && !isHttpUrl(posterUrl)) {
    throw new HttpError(400, 'Poster URL must be a valid http(s) URL.');
  }

  const rawGenre = Array.isArray(body.genre) ? body.genre : String(body.genre || '').split(',');
  const genre = [...new Set(rawGenre.map((g) => str(g, 40)).filter(Boolean))].slice(0, 20);

  const qualityBadge = str(body.qualityBadge, 4).toUpperCase() === '4K' ? '4K' : 'HD';

  const payload = {
    title,
    description: str(body.description, 5000),
    posterUrl,
    type,
    genre,
    qualityBadge,
    sources: [],
    episodes: [],
  };

  if (type === 'movie') {
    payload.sources = cleanSources(body.sources, 'Movie');
    if (!payload.sources.length) throw new HttpError(400, 'A movie needs at least one video source.');
  } else {
    const episodes = Array.isArray(body.episodes) ? body.episodes : [];
    const seen = new Set();
    payload.episodes = episodes.map((ep, i) => {
      const season = Number.parseInt(ep && ep.season, 10);
      const episodeNumber = Number.parseInt(ep && ep.episodeNumber, 10);
      if (!Number.isFinite(season) || season < 0) {
        throw new HttpError(400, `Episode #${i + 1}: season must be a number.`);
      }
      if (!Number.isFinite(episodeNumber) || episodeNumber < 0) {
        throw new HttpError(400, `Episode #${i + 1}: episode number must be a number.`);
      }
      const key = `${season}-${episodeNumber}`;
      if (seen.has(key)) throw new HttpError(400, `Duplicate episode S${season}E${episodeNumber}.`);
      seen.add(key);

      const label = `S${season}E${episodeNumber}`;
      const sources = cleanSources(ep.sources, label);
      if (!sources.length) throw new HttpError(400, `${label} needs at least one video source.`);
      return { season, episodeNumber, title: str(ep.title, 200), sources };
    });
    if (!payload.episodes.length) throw new HttpError(400, 'A series needs at least one episode.');
    payload.episodes.sort((a, b) => a.season - b.season || a.episodeNumber - b.episodeNumber);
  }

  return payload;
}

/** Constant-time password comparison (hash first so lengths always match). */
function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

function requireAdmin(req, res, next) {
  const auth = req.get('authorization') || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : req.get('x-admin-password') || '';
  if (!token || !safeEqual(token, ADMIN_PASSWORD)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

function originAllowed(origin) {
  if (!origin) return true; // curl, uptime pingers, server-to-server
  if (!ALLOWED_ORIGINS.length) return true; // not configured yet: allow all (dev)
  const clean = origin.replace(/\/+$/, '');
  return ALLOWED_ORIGINS.some((allowed) => {
    if (allowed === '*') return true;
    if (allowed.includes('*.')) {
      // e.g. https://*.tdub.pages.dev  -> matches https://abc123.tdub.pages.dev
      const [scheme, host] = allowed.split('://');
      const suffix = host.replace('*.', '.');
      return clean.startsWith(`${scheme}://`) && clean.endsWith(suffix);
    }
    return allowed === clean;
  });
}

const asyncRoute = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

/* ------------------------------------------------------------------ */
/* App                                                                 */
/* ------------------------------------------------------------------ */

const app = express();
app.set('trust proxy', 1); // behind Render / Railway / Koyeb proxies
app.disable('x-powered-by');

app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(
  cors({
    origin(origin, cb) {
      if (originAllowed(origin)) return cb(null, true);
      return cb(new HttpError(403, 'Origin not allowed by CORS'));
    },
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Admin-Password'],
    maxAge: 86400,
  })
);
app.use(express.json({ limit: '1mb' }));

const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 60,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Too many requests. Please try again later.' },
});

/* ---------- Routes ---------- */

// Lightweight keep-alive ping (point UptimeRobot / cron-job.org here).
app.get('/api/health', (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.json({
    status: 'ok',
    db: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    uptime: Math.round(process.uptime()),
    time: new Date().toISOString(),
  });
});

// Catalog list. Light by default (no stream links); ?full=1 includes everything.
// Optional filters: ?type=movie|series  ?q=search  ?genre=Anime  ?limit=200
app.get(
  '/api/videos',
  asyncRoute(async (req, res) => {
    const filter = {};
    const type = str(req.query.type, 10).toLowerCase();
    if (type === 'movie' || type === 'series') filter.type = type;

    const genre = str(req.query.genre, 40);
    if (genre) filter.genre = { $regex: `^${escapeRegex(genre)}$`, $options: 'i' };

    const q = str(req.query.q, 100);
    if (q) filter.title = { $regex: escapeRegex(q), $options: 'i' };

    const limit = Math.min(Math.max(Number.parseInt(req.query.limit, 10) || 500, 1), 1000);
    const full = req.query.full === '1' || req.query.full === 'true';

    let query = Video.find(filter).sort({ createdAt: -1 }).limit(limit).lean();
    if (!full) query = query.select('title description posterUrl type genre qualityBadge createdAt updatedAt');

    const videos = await query;
    res.set('Cache-Control', 'public, max-age=60');
    res.json(videos);
  })
);

// Single title with all mirrors / episodes.
app.get(
  '/api/videos/:id',
  asyncRoute(async (req, res) => {
    if (!mongoose.isValidObjectId(req.params.id)) throw new HttpError(404, 'Video not found.');
    const video = await Video.findById(req.params.id).lean();
    if (!video) throw new HttpError(404, 'Video not found.');
    res.set('Cache-Control', 'public, max-age=60');
    res.json(video);
  })
);

// Protected: create a new title.
app.post(
  '/api/videos',
  adminLimiter,
  requireAdmin,
  asyncRoute(async (req, res) => {
    const payload = buildVideoPayload(req.body);
    const video = await Video.create(payload);
    res.status(201).json(video);
  })
);

// Protected: lets the admin page check the password before showing the form.
app.post('/api/admin/verify', adminLimiter, requireAdmin, (req, res) => {
  res.json({ ok: true });
});

// Unknown API routes.
app.use('/api', (req, res) => res.status(404).json({ error: 'Not found' }));
app.get('/', (req, res) => res.json({ name: 'TDub API', health: '/api/health' }));

// Central error handler.
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Invalid JSON body.' });
  if (err.name === 'ValidationError') return res.status(400).json({ error: err.message });
  const status = err.status || 500;
  if (status >= 500) console.error('[TDub] Error:', err);
  res.status(status).json({ error: status >= 500 ? 'Internal server error' : err.message });
});

function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/* ------------------------------------------------------------------ */
/* Start                                                               */
/* ------------------------------------------------------------------ */

let server;

mongoose.set('strictQuery', true);
mongoose
  .connect(MONGODB_URI, { serverSelectionTimeoutMS: 15000 })
  .then(() => {
    console.log('[TDub] Connected to MongoDB');
    server = app.listen(PORT, () => console.log(`[TDub] API listening on port ${PORT}`));
  })
  .catch((err) => {
    console.error('[TDub] MongoDB connection failed:', err.message);
    process.exit(1);
  });

mongoose.connection.on('disconnected', () => console.warn('[TDub] MongoDB disconnected'));

function shutdown(signal) {
  console.log(`[TDub] ${signal} received, shutting down...`);
  const close = () => mongoose.connection.close(false).finally(() => process.exit(0));
  if (server) server.close(close);
  else close();
  setTimeout(() => process.exit(1), 10000).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
