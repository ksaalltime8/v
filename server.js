require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const required = ['MONGODB_URI', 'SESSION_SECRET', 'OWNER_USERNAME', 'OWNER_PASSWORD_HASH'];
for (const key of required) if (!process.env[key]) console.warn(`[config] Missing ${key}`);

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, trim: true, minlength: 3, maxlength: 32 },
  passwordHash: { type: String, required: true },
  role: { type: String, enum: ['owner', 'user'], default: 'user' },
  active: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now },
  lastLoginAt: Date
});
const watchSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, required: true, index: true },
  mediaType: { type: String, enum: ['movie', 'tv'], required: true },
  tmdbId: { type: Number, required: true },
  title: String,
  posterPath: String,
  season: Number,
  episode: Number,
  position: { type: Number, default: 0 },
  duration: { type: Number, default: 0 },
  updatedAt: { type: Date, default: Date.now }
});
watchSchema.index({ userId: 1, mediaType: 1, tmdbId: 1, season: 1, episode: 1 }, { unique: true });
const listSchema = new mongoose.Schema({ userId: { type: mongoose.Schema.Types.ObjectId, required: true, index: true }, mediaType: String, tmdbId: Number, title: String, posterPath: String, addedAt: { type: Date, default: Date.now } });
listSchema.index({ userId: 1, mediaType: 1, tmdbId: 1 }, { unique: true });
const sourceSchema = new mongoose.Schema({
  mediaType: { type: String, enum: ['movie', 'tv'], required: true }, tmdbId: { type: Number, required: true },
  season: { type: Number, default: 0 }, episode: { type: Number, default: 0 }, title: String,
  playbackUrl: { type: String, required: true }, sourceLabel: { type: String, default: 'Authorized source' },
  introStart: { type: Number, default: null }, introEnd: { type: Number, default: null },
  recapStart: { type: Number, default: null }, recapEnd: { type: Number, default: null },
  creditsStart: { type: Number, default: null }, enabled: { type: Boolean, default: true }, updatedAt: { type: Date, default: Date.now }
});
sourceSchema.index({ mediaType: 1, tmdbId: 1, season: 1, episode: 1 }, { unique: true });
const User = mongoose.model('User', userSchema);
const Watch = mongoose.model('Watch', watchSchema);
const Watchlist = mongoose.model('Watchlist', listSchema);
const Source = mongoose.model('Source', sourceSchema);

app.disable('x-powered-by');
// Allow the separately hosted iik27.com frontend to call this API with session cookies.
// Keep the allow-list explicit; never use wildcard origins with credentials.
app.set('trust proxy', 1);
const allowedOrigins = new Set(
  String(process.env.FRONTEND_URL || 'http://localhost:3000')
    .split(',').map(x => x.trim()).filter(Boolean)
);
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && allowedOrigins.has(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PATCH,DELETE,OPTIONS');
  }
  if (req.method === 'OPTIONS') return res.sendStatus(origin && allowedOrigins.has(origin) ? 204 : 403);
  next();
});
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(express.json({ limit: '200kb' }));
app.use(express.urlencoded({ extended: false, limit: '50kb' }));
app.use(session({
  name: 'velora.sid', secret: process.env.SESSION_SECRET || 'development-only-change-me',
  resave: false, saveUninitialized: false,
  store: process.env.MONGODB_URI ? MongoStore.create({ mongoUrl: process.env.MONGODB_URI, collectionName: 'sessions', ttl: 60 * 60 * 24 * 30 }) : undefined,
  cookie: { httpOnly: true, sameSite: String(process.env.COOKIE_SAMESITE || 'lax').toLowerCase(), secure: process.env.COOKIE_SECURE === 'true', maxAge: 1000 * 60 * 60 * 24 * 30 }
}));
app.use('/api/auth/login', rateLimit({ windowMs: 15 * 60 * 1000, limit: 20, standardHeaders: true, legacyHeaders: false }));
app.use(express.static(path.join(__dirname, 'public')));

const safeUser = u => ({ id: String(u._id), username: u.username, role: u.role, createdAt: u.createdAt, active: u.active, lastLoginAt: u.lastLoginAt || null });
function requireAuth(req, res, next) { if (!req.session.user) return res.status(401).json({ error: 'Please sign in.' }); next(); }
function requireOwner(req, res, next) { if (!req.session.user || req.session.user.role !== 'owner') return res.status(403).json({ error: 'Owner access required.' }); next(); }
function validType(type) { return type === 'movie' || type === 'tv'; }
function num(v, fallback = 0) { const n = Number(v); return Number.isFinite(n) && n >= 0 ? n : fallback; }
function cleanText(v, max = 120) { return String(v || '').trim().slice(0, max); }
function allowedPlaybackUrl(raw) {
  try { const u = new URL(raw); return ['https:', 'http:'].includes(u.protocol) && !['localhost', '127.0.0.1', '0.0.0.0'].includes(u.hostname); } catch { return false; }
}

app.get('/api/health', (req, res) => res.json({ ok: true, service: 'VELORA' }));
app.get('/api/auth/me', async (req, res) => {
  if (!req.session.user) return res.json({ authenticated: false });
  const u = await User.findById(req.session.user.id);
  if (!u || !u.active) { req.session.destroy(() => {}); return res.json({ authenticated: false }); }
  res.json({ authenticated: true, user: safeUser(u) });
});
app.post('/api/auth/login', async (req, res) => {
  const username = cleanText(req.body.username, 32);
  const password = String(req.body.password || '');
  if (!username || !password) return res.status(400).json({ error: 'Enter your username and password.' });
  let user = await User.findOne({ username: username.toLowerCase() });
  // Bootstrap owner is defined in environment variables. It is never exposed by a public registration endpoint.
  if (!user && username.toLowerCase() === String(process.env.OWNER_USERNAME || '').toLowerCase() && process.env.OWNER_PASSWORD_HASH) {
    const ok = await bcrypt.compare(password, process.env.OWNER_PASSWORD_HASH).catch(() => false);
    if (ok) {
      user = await User.findOneAndUpdate({ username: username.toLowerCase() }, { $setOnInsert: { username: username.toLowerCase(), passwordHash: process.env.OWNER_PASSWORD_HASH, role: 'owner', active: true } }, { upsert: true, new: true, setDefaultsOnInsert: true });
    }
  }
  if (!user || !user.active || !(await bcrypt.compare(password, user.passwordHash).catch(() => false))) return res.status(401).json({ error: 'Incorrect username or password.' });
  if (user.role === 'owner' && username.toLowerCase() !== String(process.env.OWNER_USERNAME || '').toLowerCase()) return res.status(403).json({ error: 'Owner sign-in is not configured correctly.' });
  await User.updateOne({ _id: user._id }, { $set: { lastLoginAt: new Date() } });
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: 'Could not start your session.' });
    req.session.user = { id: String(user._id), username: user.username, role: user.role };
    req.session.save(e => e ? res.status(500).json({ error: 'Could not save your session.' }) : res.json({ ok: true, user: safeUser(user) }));
  });
});
app.post('/api/auth/logout', (req, res) => req.session.destroy(err => { res.clearCookie('velora.sid'); if (err) return res.status(500).json({ error: 'Logout failed.' }); res.json({ ok: true }); }));

// Catalog metadata is supplied by TMDB. TMDB does not supply commercial movie/TV video streams.
app.get('/api/catalog/:kind', requireAuth, async (req, res) => {
  const kind = req.params.kind;
  if (!['trending', 'movie', 'tv', 'search', 'upcoming'].includes(kind)) return res.status(400).json({ error: 'Unknown catalog request.' });
  if (!process.env.TMDB_API_KEY) return res.status(503).json({ error: 'Add TMDB_API_KEY in the environment to enable the catalog.' });
  const page = Math.min(20, Math.max(1, Number(req.query.page) || 1));
  const q = cleanText(req.query.q, 100);
  let endpoint;
  if (kind === 'search') endpoint = `/search/multi?query=${encodeURIComponent(q)}&include_adult=false&page=${page}`;
  else if (kind === 'movie') endpoint = `/movie/popular?page=${page}`;
  else if (kind === 'tv') endpoint = `/tv/popular?page=${page}`;
  else if (kind === 'upcoming') endpoint = `/tv/on_the_air?page=${page}`;
  else endpoint = `/trending/all/week?page=${page}`;
  try {
    const r = await fetch(`https://api.themoviedb.org/3${endpoint}`, { headers: { Authorization: `Bearer ${process.env.TMDB_API_KEY}`, accept: 'application/json' } });
    const data = await r.json(); if (!r.ok) return res.status(r.status).json({ error: data.status_message || 'Catalog request failed.' });
    const results = (data.results || []).filter(x => x.media_type !== 'person').map(x => ({ id: x.id, mediaType: x.media_type || (kind === 'tv' || kind === 'upcoming' ? 'tv' : 'movie'), title: x.title || x.name || 'Untitled', overview: x.overview || '', posterPath: x.poster_path || null, backdropPath: x.backdrop_path || null, date: x.release_date || x.first_air_date || '', rating: x.vote_average || 0 }));
    res.json({ results, page: data.page, totalPages: data.total_pages });
  } catch { res.status(502).json({ error: 'Could not reach the catalog service.' }); }
});
app.get('/api/title/:kind/:id', requireAuth, async (req, res) => {
  const { kind } = req.params; const id = Number(req.params.id);
  if (!validType(kind) || !Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Invalid title.' });
  if (!process.env.TMDB_API_KEY) return res.status(503).json({ error: 'TMDB API key is not configured.' });
  try {
    const r = await fetch(`https://api.themoviedb.org/3/${kind}/${id}?append_to_response=credits,videos,seasons`, { headers: { Authorization: `Bearer ${process.env.TMDB_API_KEY}`, accept: 'application/json' } });
    const d = await r.json(); if (!r.ok) return res.status(r.status).json({ error: d.status_message || 'Title not found.' });
    const srcs = await Source.find({ mediaType: kind, tmdbId: id, enabled: true }).lean();
    res.json({ id: d.id, mediaType: kind, title: d.title || d.name, overview: d.overview || '', posterPath: d.poster_path, backdropPath: d.backdrop_path, date: d.release_date || d.first_air_date, rating: d.vote_average, runtime: d.runtime || null, seasons: (d.seasons || []).map(s => ({ season: s.season_number, name: s.name, episodes: s.episode_count })), cast: (d.credits?.cast || []).slice(0, 8).map(c => c.name), trailerKey: (d.videos?.results || []).find(v => v.site === 'YouTube' && v.type === 'Trailer')?.key || null, sources: srcs.map(s => ({ season: s.season, episode: s.episode, title: s.title, sourceLabel: s.sourceLabel })) });
  } catch { res.status(502).json({ error: 'Could not load title details.' }); }
});
app.get('/api/title/:kind/:id/episodes/:season', requireAuth, async (req, res) => {
  if (req.params.kind !== 'tv' || !process.env.TMDB_API_KEY) return res.status(400).json({ error: 'Invalid series request.' });
  try {
    const r = await fetch(`https://api.themoviedb.org/3/tv/${Number(req.params.id)}/season/${Number(req.params.season)}`, { headers: { Authorization: `Bearer ${process.env.TMDB_API_KEY}` } });
    const d = await r.json(); if (!r.ok) return res.status(r.status).json({ error: d.status_message || 'Season unavailable.' });
    res.json({ episodes: (d.episodes || []).map(e => ({ id: e.id, episode: e.episode_number, title: e.name, overview: e.overview, stillPath: e.still_path, date: e.air_date, runtime: e.runtime })) });
  } catch { res.status(502).json({ error: 'Could not load episodes.' }); }
});

app.get('/api/source/:kind/:id', requireAuth, async (req, res) => {
  const kind = req.params.kind, id = Number(req.params.id), season = num(req.query.season), episode = num(req.query.episode);
  if (!validType(kind) || !Number.isInteger(id)) return res.status(400).json({ error: 'Invalid title.' });
  const source = await Source.findOne({ mediaType: kind, tmdbId: id, season: kind === 'tv' ? season : 0, episode: kind === 'tv' ? episode : 0, enabled: true }).lean();
  if (!source) return res.status(404).json({ error: 'No authorized playback source has been added for this title yet.' });
  res.json({ playbackUrl: source.playbackUrl, sourceLabel: source.sourceLabel, introStart: source.introStart, introEnd: source.introEnd, recapStart: source.recapStart, recapEnd: source.recapEnd, creditsStart: source.creditsStart });
});
app.get('/api/me/watchlist', requireAuth, async (req, res) => res.json({ items: await Watchlist.find({ userId: req.session.user.id }).sort({ addedAt: -1 }).lean() }));
app.post('/api/me/watchlist', requireAuth, async (req, res) => {
  const { mediaType, tmdbId } = req.body; if (!validType(mediaType) || !Number.isInteger(Number(tmdbId))) return res.status(400).json({ error: 'Invalid title.' });
  const filter = { userId: req.session.user.id, mediaType, tmdbId: Number(tmdbId) };
  if (req.body.remove) { await Watchlist.deleteOne(filter); return res.json({ ok: true, saved: false }); }
  await Watchlist.updateOne(filter, { $set: { title: cleanText(req.body.title), posterPath: cleanText(req.body.posterPath, 200) }, $setOnInsert: { ...filter, addedAt: new Date() } }, { upsert: true });
  res.json({ ok: true, saved: true });
});
app.get('/api/me/history', requireAuth, async (req, res) => res.json({ items: await Watch.find({ userId: req.session.user.id }).sort({ updatedAt: -1 }).limit(100).lean() }));
app.post('/api/me/progress', requireAuth, async (req, res) => {
  const { mediaType, tmdbId } = req.body; if (!validType(mediaType) || !Number.isInteger(Number(tmdbId))) return res.status(400).json({ error: 'Invalid title.' });
  const season = num(req.body.season), episode = num(req.body.episode), position = num(req.body.position), duration = num(req.body.duration);
  const filter = { userId: req.session.user.id, mediaType, tmdbId: Number(tmdbId), season, episode };
  await Watch.updateOne(filter, { $set: { title: cleanText(req.body.title), posterPath: cleanText(req.body.posterPath, 200), position, duration, updatedAt: new Date() }, $setOnInsert: filter }, { upsert: true });
  res.json({ ok: true });
});

app.get('/api/admin/users', requireOwner, async (req, res) => res.json({ users: (await User.find().sort({ createdAt: -1 }).lean()).map(safeUser) }));
app.post('/api/admin/users', requireOwner, async (req, res) => {
  const username = cleanText(req.body.username, 32).toLowerCase(); const password = String(req.body.password || '');
  if (!/^[a-z0-9][a-z0-9._-]{2,31}$/.test(username)) return res.status(400).json({ error: 'Username must be 3–32 characters and use letters, numbers, dots, underscores or hyphens.' });
  if (password.length < 10 || password.length > 200) return res.status(400).json({ error: 'Password must be at least 10 characters.' });
  if (username === String(process.env.OWNER_USERNAME || '').toLowerCase()) return res.status(409).json({ error: 'That username is reserved for the owner.' });
  try { const u = await User.create({ username, passwordHash: await bcrypt.hash(password, 12), role: 'user', active: true }); res.status(201).json({ user: safeUser(u) }); }
  catch (e) { if (e.code === 11000) return res.status(409).json({ error: 'That username already exists.' }); throw e; }
});
app.patch('/api/admin/users/:id', requireOwner, async (req, res) => {
  const u = await User.findById(req.params.id); if (!u) return res.status(404).json({ error: 'User not found.' });
  if (u.role === 'owner') return res.status(400).json({ error: 'The owner account cannot be changed here.' });
  if (typeof req.body.active === 'boolean') u.active = req.body.active;
  if (req.body.password !== undefined) { const p = String(req.body.password); if (p.length < 10) return res.status(400).json({ error: 'New password must be at least 10 characters.' }); u.passwordHash = await bcrypt.hash(p, 12); }
  await u.save(); res.json({ user: safeUser(u) });
});
app.delete('/api/admin/users/:id', requireOwner, async (req, res) => {
  const u = await User.findById(req.params.id); if (!u) return res.status(404).json({ error: 'User not found.' });
  if (u.role === 'owner') return res.status(400).json({ error: 'The owner account cannot be deleted here.' });
  await Promise.all([User.deleteOne({ _id: u._id }), Watch.deleteMany({ userId: u._id }), Watchlist.deleteMany({ userId: u._id })]); res.json({ ok: true });
});
app.get('/api/admin/sources', requireOwner, async (req, res) => res.json({ sources: await Source.find().sort({ updatedAt: -1 }).lean() }));
app.post('/api/admin/sources', requireOwner, async (req, res) => {
  const { mediaType } = req.body, tmdbId = Number(req.body.tmdbId), season = mediaType === 'tv' ? num(req.body.season) : 0, episode = mediaType === 'tv' ? num(req.body.episode) : 0, playbackUrl = String(req.body.playbackUrl || '').trim();
  if (!validType(mediaType) || !Number.isInteger(tmdbId) || tmdbId <= 0 || !allowedPlaybackUrl(playbackUrl)) return res.status(400).json({ error: 'Provide a valid type, TMDB ID and HTTP(S) playback URL.' });
  const vals = {}; for (const key of ['introStart','introEnd','recapStart','recapEnd','creditsStart']) vals[key] = req.body[key] === '' || req.body[key] == null ? null : num(req.body[key], null);
  const filter = { mediaType, tmdbId, season, episode };
  const doc = await Source.findOneAndUpdate(filter, { $set: { ...filter, playbackUrl, sourceLabel: cleanText(req.body.sourceLabel, 80) || 'Authorized source', title: cleanText(req.body.title), enabled: req.body.enabled !== false, ...vals, updatedAt: new Date() } }, { upsert: true, new: true, runValidators: true });
  res.json({ source: doc });
});
app.delete('/api/admin/sources/:id', requireOwner, async (req, res) => { await Source.deleteOne({ _id: req.params.id }); res.json({ ok: true }); });

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
(async () => {
  try {
    if (!process.env.MONGODB_URI) throw new Error('MONGODB_URI is required');
    await mongoose.connect(process.env.MONGODB_URI);
    console.log('VELORA connected to MongoDB');
    app.listen(PORT, () => console.log(`VELORA running on port ${PORT}`));
  } catch (e) { console.error('VELORA startup failed:', e.message); process.exit(1); }
})();
