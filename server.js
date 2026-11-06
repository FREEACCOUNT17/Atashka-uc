// ATAJAN UC - hakyky server (Node.js + Express). Maglumatlar data/db.json faýlynda saklanýar.
const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const UPLOAD_DIR = path.join(DATA_DIR, 'uploads');
const DB_FILE = path.join(DATA_DIR, 'db.json');
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// ---------- Parol hash ----------
function hashPass(p) {
  const salt = crypto.randomBytes(16).toString('hex');
  return salt + ':' + crypto.scryptSync(p, salt, 64).toString('hex');
}
function checkPass(p, stored) {
  const [salt, h] = stored.split(':');
  const a = Buffer.from(h, 'hex');
  const b = crypto.scryptSync(p, salt, 64);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// ---------- DB ----------
const defaultDB = () => ({
  isShopOpen: true,
  paymentPhone: '+993 65 123456',
  admin: {
    user: process.env.ADMIN_USER || 'atajan',
    pass: hashPass(process.env.ADMIN_PASS || 'atajan1066')
  },
  packages: [
    { id: 1, amount: 60, price: 15 },
    { id: 2, amount: 325, price: 70 },
    { id: 3, amount: 660, price: 130 },
    { id: 4, amount: 1800, price: 340 },
    { id: 5, amount: 3850, price: 700 },
    { id: 6, amount: 8100, price: 1400 }
  ],
  orders: [],
  visitors: [],
  buyers: {}
});
let db;
try { db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
catch { db = defaultDB(); }
function save() {
  const tmp = DB_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db));
  fs.renameSync(tmp, DB_FILE);
}
save();

// ---------- Sessiýalar ----------
const adminSessions = new Map(); // token -> expiry
const SESSION_MS = 12 * 3600 * 1000;
const attempts = new Map(); // ip -> {n, until}

function adminAuth(req, res, next) {
  const t = req.get('x-admin-token');
  const exp = t && adminSessions.get(t);
  if (!exp || exp < Date.now()) return res.status(401).json({ error: 'unauthorized' });
  next();
}
function buyerAuth(req, res, next) {
  const b = db.buyers[req.get('x-buyer-token')];
  if (!b) return res.status(401).json({ error: 'login_required' });
  req.buyer = b;
  next();
}

const app = express();
app.set('trust proxy', 1);
app.use((req, res, next) => {
  res.set({ 'Access-Control-Allow-Origin': process.env.CORS_ORIGIN || '*',
    'Access-Control-Allow-Headers': 'Content-Type, x-admin-token, x-buyer-token',
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS' });
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});
app.use(express.json({ limit: '8mb' }));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

const cleanPhone = p => String(p || '').replace(/[^0-9+]/g, '');
const validPhone = p => { const c = cleanPhone(p); return c.length >= 8 && c.length <= 15; };

// ---------- Köpçülik API ----------
app.get('/api/state', (req, res) => {
  res.json({ isShopOpen: db.isShopOpen, paymentPhone: db.paymentPhone, packages: db.packages });
});

app.post('/api/register', (req, res) => {
  const name = String(req.body.name || '').trim().slice(0, 60);
  const phone = String(req.body.phone || '').trim().slice(0, 25);
  if (!name || !validPhone(phone)) return res.status(400).json({ error: 'bad_input' });
  const token = crypto.randomBytes(24).toString('hex');
  db.buyers[token] = { name, phone };
  db.visitors.unshift({ name, phone, time: new Date().toISOString() });
  db.visitors = db.visitors.slice(0, 500);
  save();
  res.json({ token, name, phone });
});

app.get('/api/my-orders', buyerAuth, (req, res) => {
  const mine = db.orders
    .filter(o => o.phone === req.buyer.phone)
    .map(o => ({ id: o.id, date: o.date, ucAmount: o.ucAmount, pubgId: o.pubgId, status: o.status }));
  res.json(mine);
});

app.post('/api/orders', buyerAuth, (req, res) => {
  if (!db.isShopOpen) return res.status(403).json({ error: 'closed' });
  const pubgId = String(req.body.pubgId || '').trim().slice(0, 30);
  const ids = Array.isArray(req.body.ids) ? req.body.ids.slice(0, 50) : [];
  if (!/^[0-9]{5,15}$/.test(pubgId) || !ids.length) return res.status(400).json({ error: 'bad_input' });
  let uc = 0, price = 0;
  for (const id of ids) {
    const p = db.packages.find(x => x.id === Number(id));
    if (!p) return res.status(400).json({ error: 'bad_package' });
    uc += p.amount; price += p.price;
  }
  const id = Date.now();
  let shot = '';
  const m = /^data:image\/(png|jpeg|webp);base64,([A-Za-z0-9+/=]+)$/.exec(req.body.screenshot || '');
  if (m) {
    const buf = Buffer.from(m[2], 'base64');
    if (buf.length > 6 * 1024 * 1024) return res.status(413).json({ error: 'too_big' });
    shot = id + '.' + (m[1] === 'jpeg' ? 'jpg' : m[1]);
    fs.writeFileSync(path.join(UPLOAD_DIR, shot), buf);
  }
  db.orders.unshift({
    id, name: req.buyer.name, phone: req.buyer.phone, pubgId,
    ucAmount: uc, price, shot, status: 'pending', date: new Date().toISOString()
  });
  save();
  res.json({ ok: true, id });
});

// ---------- Owner API ----------
app.post('/api/admin/login', (req, res) => {
  const ip = req.ip;
  const a = attempts.get(ip) || { n: 0, until: 0 };
  if (a.until > Date.now()) return res.status(429).json({ error: 'too_many' });
  const u = String(req.body.username || ''), p = String(req.body.password || '');
  if (u === db.admin.user && checkPass(p, db.admin.pass)) {
    attempts.delete(ip);
    const t = crypto.randomBytes(32).toString('hex');
    adminSessions.set(t, Date.now() + SESSION_MS);
    return res.json({ token: t });
  }
  a.n++;
  if (a.n >= 5) { a.until = Date.now() + 5 * 60 * 1000; a.n = 0; }
  attempts.set(ip, a);
  res.status(401).json({ error: 'wrong' });
});

app.get('/api/admin/data', adminAuth, (req, res) => {
  res.json({
    isShopOpen: db.isShopOpen, paymentPhone: db.paymentPhone, packages: db.packages,
    username: db.admin.user, visitors: db.visitors,
    orders: db.orders.map(o => ({ ...o, hasShot: !!o.shot, shot: undefined }))
  });
});

app.post('/api/admin/shop', adminAuth, (req, res) => {
  db.isShopOpen = !!req.body.isOpen; save(); res.json({ ok: true });
});
app.post('/api/admin/payment', adminAuth, (req, res) => {
  const v = String(req.body.phone || '').trim().slice(0, 25);
  if (!v) return res.status(400).json({ error: 'bad_input' });
  db.paymentPhone = v; save(); res.json({ ok: true });
});
app.post('/api/admin/credentials', adminAuth, (req, res) => {
  const u = String(req.body.username || '').trim(), p = String(req.body.password || '');
  if (u.length < 3 || p.length < 6) return res.status(400).json({ error: 'weak' });
  db.admin = { user: u, pass: hashPass(p) }; save(); res.json({ ok: true });
});
app.post('/api/admin/prices', adminAuth, (req, res) => {
  const prices = req.body.prices || {};
  db.packages.forEach(p => {
    const v = Number(prices[p.id]);
    if (v > 0 && v < 1e7) p.price = v;
  });
  save(); res.json({ ok: true });
});
app.post('/api/admin/orders/:id/status', adminAuth, (req, res) => {
  const o = db.orders.find(x => x.id === Number(req.params.id));
  const s = req.body.status;
  if (!o || !['pending', 'approved', 'rejected'].includes(s)) return res.status(400).json({ error: 'bad_input' });
  o.status = s; save(); res.json({ ok: true });
});
app.delete('/api/admin/orders/:id', adminAuth, (req, res) => {
  const o = db.orders.find(x => x.id === Number(req.params.id));
  if (o && o.shot) fs.rmSync(path.join(UPLOAD_DIR, o.shot), { force: true });
  db.orders = db.orders.filter(x => x.id !== Number(req.params.id));
  save(); res.json({ ok: true });
});
app.get('/api/admin/shot/:id', adminAuth, (req, res) => {
  const o = db.orders.find(x => x.id === Number(req.params.id));
  if (!o || !o.shot) return res.status(404).end();
  res.sendFile(path.join(UPLOAD_DIR, path.basename(o.shot)));
});

app.listen(PORT, () => console.log('ATAJAN UC işleýär: http://localhost:' + PORT));
