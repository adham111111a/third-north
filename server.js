// التالتة شمال — Third North check-in server
// Pure Node.js, zero dependencies.
// Storage: JSON file (data/checkins.json) + photo files (data/photos/).
// Works on any host with a persistent filesystem (Replit, Render, VPS).
// Admin PIN is checked server-side only. Geofence is enforced server-side.

'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');

const PORT = parseInt(process.env.PORT || '3000', 10);
const HOST = process.env.HOST || '0.0.0.0';
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const PHOTOS_DIR = path.join(DATA_DIR, 'photos');
const DB_FILE = path.join(DATA_DIR, 'checkins.json');
const SECRET_FILE = path.join(DATA_DIR, '.secret');
const ADMIN_PIN = process.env.ADMIN_PIN || '2468';

// Cairo International Stadium — 30.0722, 31.3035 (approx centre)
const STADIUM = { lat: 30.0722, lng: 31.3035, radiusM: 600 };

fs.mkdirSync(PHOTOS_DIR, { recursive: true });

// ---- session secret (persisted so logins survive restarts on the same FS) ----
let SESSION_SECRET;
try {
  SESSION_SECRET = fs.readFileSync(SECRET_FILE, 'utf8').trim();
  if (SESSION_SECRET.length < 32) throw new Error('short secret');
} catch {
  SESSION_SECRET = crypto.randomBytes(32).toString('hex');
  fs.writeFileSync(SECRET_FILE, SESSION_SECRET, { mode: 0o600 });
}

// ---- tiny JSON store (atomic writes, serialized) ----
let checkins = [];
try {
  checkins = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  if (!Array.isArray(checkins)) checkins = [];
} catch { checkins = []; }

let writeQueue = Promise.resolve();
function saveDb() {
  writeQueue = writeQueue.then(() => {
    const tmp = DB_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(checkins, null, 2));
    fs.renameSync(tmp, DB_FILE);
  }).catch((e) => console.error('DB save failed:', e.message));
  return writeQueue;
}

// ---- helpers ----
function haversineM(lat1, lng1, lat2, lng2) {
  const R = 6371000;
  const toRad = (d) => (d * Math.PI) / 180;
  const dLat = toRad(lat2 - lat1);
  const dLng = toRad(lng2 - lng1);
  const a = Math.sin(dLat / 2) ** 2 +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLng / 2) ** 2;
  return 2 * R * Math.asin(Math.sqrt(a));
}

function cairoTime(iso) {
  try {
    return new Intl.DateTimeFormat('ar-EG', {
      timeZone: 'Africa/Cairo', dateStyle: 'medium', timeStyle: 'short',
    }).format(new Date(iso));
  } catch { return iso; }
}

function sha256(s) { return crypto.createHash('sha256').update(String(s)).digest(); }
function pinOk(pin) {
  const a = sha256(pin || '');
  const b = sha256(ADMIN_PIN);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function makeSessionToken() {
  const exp = Date.now() + 12 * 60 * 60 * 1000; // 12h
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update('admin|' + exp).digest('hex');
  return exp + '.' + sig;
}
function sessionOk(cookieHeader) {
  if (!cookieHeader) return false;
  const m = /(?:^|;\s*)admin_session=([^;]+)/.exec(cookieHeader);
  if (!m) return false;
  const [exp, sig] = m[1].split('.');
  if (!exp || !sig) return false;
  if (parseInt(exp, 10) < Date.now()) return false;
  const want = crypto.createHmac('sha256', SESSION_SECRET).update('admin|' + exp).digest('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(want));
  } catch { return false; }
}

// simple per-IP rate limit (in-memory)
const hits = new Map();
function rateLimit(ip, key, max, windowMs) {
  const now = Date.now();
  const k = ip + ':' + key;
  const arr = (hits.get(k) || []).filter((t) => now - t < windowMs);
  arr.push(now);
  hits.set(k, arr);
  return arr.length <= max;
}

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
  });
  res.end(body);
}

function readBody(req, maxBytes = 3 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > maxBytes) { reject(new Error('body too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json', '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.svg': 'image/svg+xml' };

function serveStatic(req, res, pathname) {
  let file = pathname === '/' ? '/index.html' : pathname;
  const safe = path.normalize(file).replace(/^(\.\.[\/\\])+/, '');
  const full = path.join(__dirname, 'public', safe);
  if (!full.startsWith(path.join(__dirname, 'public'))) { res.writeHead(403); return res.end(); }
  fs.readFile(full, (err, data) => {
    if (err) { res.writeHead(404, { 'Content-Type': 'text/plain' }); return res.end('Not found'); }
    res.writeHead(200, {
      'Content-Type': MIME[path.extname(full)] || 'application/octet-stream',
      'X-Content-Type-Options': 'nosniff',
    });
    res.end(data);
  });
}

function csvEscape(v) {
  const s = String(v == null ? '' : v);
  return '"' + s.replace(/"/g, '""') + '"';
}

const server = http.createServer(async (req, res) => {
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';
  const u = new URL(req.url, 'http://x');
  const pathname = u.pathname;

  try {
    // ---- health ----
    if (req.method === 'GET' && pathname === '/api/health') {
      return sendJson(res, 200, { ok: true, checkins: checkins.length });
    }

    // ---- photos ----
    if (req.method === 'GET' && pathname.startsWith('/photos/')) {
      const name = pathname.slice('/photos/'.length);
      if (!/^[A-Za-z0-9_-]+\.(jpg|png)$/.test(name)) { res.writeHead(400); return res.end(); }
      const full = path.join(PHOTOS_DIR, name);
      if (!full.startsWith(PHOTOS_DIR)) { res.writeHead(403); return res.end(); }
      return fs.readFile(full, (err, data) => {
        if (err) { res.writeHead(404); return res.end(); }
        res.writeHead(200, { 'Content-Type': name.endsWith('.png') ? 'image/png' : 'image/jpeg', 'Cache-Control': 'public, max-age=86400' });
        res.end(data);
      });
    }

    // ---- check-in ----
    if (req.method === 'POST' && pathname === '/api/checkin') {
      if (!rateLimit(ip, 'checkin', 10, 60 * 1000)) return sendJson(res, 429, { ok: false, error: 'too_many' });
      let body;
      try { body = JSON.parse(await readBody(req)); } catch { return sendJson(res, 400, { ok: false, error: 'bad_body' }); }
      const name = String(body.name || '').trim();
      const section = String(body.section || '').trim();
      const lat = Number(body.lat);
      const lng = Number(body.lng);
      const photo = String(body.photo || '');
      if (!name || name.length > 80) return sendJson(res, 400, { ok: false, error: 'bad_name' });
      if (!section || section.length > 80) return sendJson(res, 400, { ok: false, error: 'bad_section' });
      if (!Number.isFinite(lat) || lat < -90 || lat > 90 || !Number.isFinite(lng) || lng < -180 || lng > 180) {
        return sendJson(res, 400, { ok: false, error: 'bad_location' });
      }
      const pm = /^data:image\/(jpeg|jpg|png);base64,([A-Za-z0-9+/=]+)$/.exec(photo);
      if (!pm) return sendJson(res, 400, { ok: false, error: 'photo_required' });
      const buf = Buffer.from(pm[2], 'base64');
      if (buf.length < 2000 || buf.length > 3 * 1024 * 1024) return sendJson(res, 400, { ok: false, error: 'bad_photo' });

      // server-side geofence — the only check that matters
      const distanceM = haversineM(STADIUM.lat, STADIUM.lng, lat, lng);
      if (distanceM > STADIUM.radiusM) {
        return sendJson(res, 403, { ok: false, error: 'outside', distanceM: Math.round(distanceM), radiusM: STADIUM.radiusM });
      }

      const id = crypto.randomUUID();
      const ext = pm[1] === 'png' ? 'png' : 'jpg';
      fs.writeFileSync(path.join(PHOTOS_DIR, id + '.' + ext), buf);
      const rec = {
        id, name, section,
        createdAt: new Date().toISOString(),
        createdAtCairo: cairoTime(new Date().toISOString()),
        distanceM: Math.round(distanceM),
        lat, lng,
        photo: '/photos/' + id + '.' + ext,
      };
      checkins.unshift(rec);
      await saveDb();
      return sendJson(res, 201, { ok: true, checkin: rec });
    }

    // ---- admin login ----
    if (req.method === 'POST' && pathname === '/api/admin/login') {
      if (!rateLimit(ip, 'login', 5, 60 * 1000)) return sendJson(res, 429, { ok: false, error: 'too_many' });
      let body;
      try { body = JSON.parse(await readBody(req, 1024)); } catch { return sendJson(res, 400, { ok: false, error: 'bad_body' }); }
      if (!pinOk(body.pin)) return sendJson(res, 401, { ok: false, error: 'wrong_pin' });
      res.writeHead(200, {
        'Content-Type': 'application/json; charset=utf-8',
        'Set-Cookie': 'admin_session=' + makeSessionToken() + '; HttpOnly; SameSite=Lax; Path=/; Max-Age=43200',
        'Cache-Control': 'no-store',
      });
      return res.end(JSON.stringify({ ok: true }));
    }

    // ---- admin: list / stats / delete / export (auth required) ----
    const authed = sessionOk(req.headers.cookie);
    if (pathname.startsWith('/api/admin/') && !authed) {
      return sendJson(res, 401, { ok: false, error: 'unauthorized' });
    }
    if (req.method === 'GET' && pathname === '/api/admin/checkins') {
      return sendJson(res, 200, { ok: true, checkins });
    }
    if (req.method === 'GET' && pathname === '/api/admin/stats') {
      const today = new Date().toISOString().slice(0, 10);
      const bySection = {};
      let todayCount = 0;
      for (const c of checkins) {
        bySection[c.section] = (bySection[c.section] || 0) + 1;
        if (c.createdAt.slice(0, 10) === today) todayCount++;
      }
      return sendJson(res, 200, { ok: true, total: checkins.length, today: todayCount, bySection });
    }
    if (req.method === 'DELETE' && pathname.startsWith('/api/admin/checkins/')) {
      const id = pathname.slice('/api/admin/checkins/'.length);
      const idx = checkins.findIndex((c) => c.id === id);
      if (idx === -1) return sendJson(res, 404, { ok: false, error: 'not_found' });
      const [gone] = checkins.splice(idx, 1);
      if (gone && gone.photo) {
        try { fs.unlinkSync(path.join(PHOTOS_DIR, path.basename(gone.photo))); } catch {}
      }
      await saveDb();
      return sendJson(res, 200, { ok: true });
    }
    if (req.method === 'GET' && pathname === '/api/admin/export') {
      const rows = [['الاسم', 'السكشن', 'الوقت (القاهرة)', 'المسافة من الاستاد (متر)', 'الصورة']];
      for (const c of checkins) rows.push([c.name, c.section, c.createdAtCairo, c.distanceM, c.photo]);
      const csv = '\uFEFF' + rows.map((r) => r.map(csvEscape).join(',')).join('\r\n');
      res.writeHead(200, {
        'Content-Type': 'text/csv; charset=utf-8',
        'Content-Disposition': 'attachment; filename="third-north-checkins.csv"',
        'Cache-Control': 'no-store',
      });
      return res.end(csv);
    }

    // ---- static ----
    if (req.method === 'GET') return serveStatic(req, res, pathname);
    res.writeHead(405);
    res.end();
  } catch (e) {
    console.error(e);
    if (!res.headersSent) sendJson(res, 500, { ok: false, error: 'server_error' });
    else res.end();
  }
});

server.listen(PORT, HOST, () => {
  console.log(`Third North listening on http://${HOST}:${PORT}`);
  console.log(`Stadium ${STADIUM.lat}, ${STADIUM.lng} radius ${STADIUM.radiusM}m — checkins: ${checkins.length}`);
});
