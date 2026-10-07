const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { scryptSync, timingSafeEqual, randomBytes } = crypto;

const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const DATA_FILE = path.join(ROOT, 'data', 'users.json');
const BOOKINGS_FILE = path.join(ROOT, 'data', 'bookings.json');

// Secrets — set in Render Environment for stability across restarts, or auto-generated
let JWT_SECRET = process.env.JWT_SECRET || '';
let ADMIN_SETUP_TOKEN = process.env.ADMIN_SETUP_TOKEN || '';
if (!JWT_SECRET || JWT_SECRET.length < 32) JWT_SECRET = randomBytes(48).toString('hex');
if (!ADMIN_SETUP_TOKEN || ADMIN_SETUP_TOKEN.length < 24) ADMIN_SETUP_TOKEN = randomBytes(24).toString('hex');

const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript',
  '.css': 'text/css',
  '.json': 'application/json',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.webp': 'image/webp'
};

function send(res, code, body, type) {
  const buf = Buffer.isBuffer(body) ? body : Buffer.from(body || '', 'utf8');
  res.writeHead(code, {
    'Content-Type': type || 'text/plain; charset=utf-8',
    'Content-Length': buf.length,
    'Cache-Control': 'no-store'
  });
  res.end(buf);
}

function sendJson(res, code, obj) {
  send(res, code, JSON.stringify(obj), 'application/json; charset=utf-8');
}

function ensureData() {
  const dir = path.dirname(DATA_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  if (!fs.existsSync(DATA_FILE)) fs.writeFileSync(DATA_FILE, '[]', 'utf8');
  if (!fs.existsSync(BOOKINGS_FILE)) fs.writeFileSync(BOOKINGS_FILE, '[]', 'utf8');
}

function readJson(file) {
  ensureData();
  try {
    const list = JSON.parse(fs.readFileSync(file, 'utf8'));
    return Array.isArray(list) ? list : [];
  } catch (_) {
    return [];
  }
}

function writeJson(file, data) {
  ensureData();
  fs.writeFileSync(file, JSON.stringify(data, null, 2), 'utf8');
}

function readUsers() { return readJson(DATA_FILE); }
function writeUsers(u) { writeJson(DATA_FILE, u); }
function readBookings() { return readJson(BOOKINGS_FILE); }
function writeBookings(b) { writeJson(BOOKINGS_FILE, b); }

function uid() { return crypto.randomUUID(); }
function now() { return new Date().toISOString(); }

function hashPassword(pw) {
  const salt = randomBytes(16).toString('hex');
  const hash = scryptSync(pw, salt, 64).toString('hex');
  return salt + ':' + hash;
}

function verifyPassword(pw, stored) {
  try {
    const [salt, hash] = String(stored).split(':');
    if (!salt || !hash) return false;
    const h = scryptSync(pw, salt, 64);
    const a = Buffer.from(hash, 'hex');
    return a.length === h.length && timingSafeEqual(a, h);
  } catch (_) {
    return false;
  }
}

// Minimal JWT (HS256) — no external deps
function b64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}
function tokenFor(user) {
  const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const exp = Math.floor(Date.now() / 1000) + 7 * 24 * 3600;
  const payload = b64url(JSON.stringify({ sub: user.id, role: user.role, email: user.email, exp, iss: 'rebel-ink' }));
  const data = header + '.' + payload;
  const sig = b64url(crypto.createHmac('sha256', JWT_SECRET).update(data).digest());
  return data + '.' + sig;
}
function verifyToken(token) {
  try {
    const parts = String(token).split('.');
    if (parts.length !== 3) return null;
    const data = parts[0] + '.' + parts[1];
    const sig = b64url(crypto.createHmac('sha256', JWT_SECRET).update(data).digest());
    if (sig !== parts[2]) return null;
    const payload = JSON.parse(Buffer.from(parts[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString());
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;
    if (payload.iss !== 'rebel-ink') return null;
    return payload;
  } catch (_) {
    return null;
  }
}

function safeUser(u) {
  if (!u) return null;
  return {
    _id: u.id,
    name: u.name,
    phone: u.phone || '',
    country: u.country || '',
    state: u.state || '',
    email: u.email,
    role: u.role,
    status: u.status,
    adminNotes: u.admin_notes || '',
    createdAt: u.created_at,
    updatedAt: u.updated_at,
    lastLoginAt: u.last_login_at || null
  };
}

function cleanText(v, max) { return String(v ?? '').trim().slice(0, max); }
function normalizeEmail(e) { return String(e || '').trim().toLowerCase(); }
function validPassword(pw) {
  return typeof pw === 'string' && pw.length >= 8 && pw.length <= 128 &&
    /[a-zA-Z]/.test(pw) && /[0-9]/.test(pw) && /[^a-zA-Z0-9]/.test(pw);
}
function validPhotos(photos) {
  if (!Array.isArray(photos) || photos.length > 5) return false;
  return photos.every(p => p && typeof p.name === 'string' && typeof p.dataUrl === 'string' &&
    /^data:image\/(jpeg|jpg|png|webp|gif);base64,/i.test(p.dataUrl) && p.dataUrl.length <= 3500000);
}
function sameSecret(a, b) {
  const aa = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return aa.length === bb.length && timingSafeEqual(aa, bb);
}
function hasAdmin() {
  return readUsers().some(u => u.role === 'admin');
}
function findByEmail(email) {
  return readUsers().find(u => u.email === email) || null;
}
function findById(id) {
  return readUsers().find(u => u.id === id) || null;
}

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    let buf = '';
    req.on('data', c => {
      buf += c;
      if (buf.length > (limit || 6e6)) {
        req.destroy();
        reject(new Error('too large'));
      }
    });
    req.on('end', () => resolve(buf));
    req.on('error', reject);
  });
}

function getAuthUser(req) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : '';
  if (!token) return null;
  const payload = verifyToken(token);
  if (!payload) return null;
  const user = findById(payload.sub);
  if (!user || user.status === 'suspended') return null;
  return user;
}

function setupPage() {
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Rebel Ink — Admin Setup</title>
<style>body{font-family:Arial,sans-serif;background:#f5f7fb;margin:0;padding:30px;color:#172033}.card{max-width:520px;margin:40px auto;background:#fff;padding:30px;border-radius:16px;box-shadow:0 10px 35px #0001}h1{margin-top:0}.field{margin:15px 0}label{display:block;font-weight:700;margin-bottom:7px}input{width:100%;box-sizing:border-box;padding:12px;border:1px solid #ccd4df;border-radius:8px;font-size:16px}.btn{width:100%;padding:13px;border:0;border-radius:8px;background:#1e3a5f;color:#fff;font-weight:700;font-size:16px;cursor:pointer}.msg{margin:14px 0;padding:12px;border-radius:8px;display:none;white-space:pre-wrap}.ok{background:#ecfdf5;color:#065f46}.err{background:#fef2f2;color:#991b1b}.small{font-size:13px;color:#64748b;line-height:1.5}</style></head>
<body><div class="card"><h1>Rebel Ink — Admin Setup</h1>
<p class="small">Create the first administrator. This page closes after setup.</p>
<div id="msg" class="msg"></div>
<form id="f">
<div class="field"><label>Setup token</label><input id="token" required></div>
<div class="field"><label>Admin name</label><input id="name" required value="Rebel Ink Administrator"></div>
<div class="field"><label>Admin email</label><input id="email" type="email" required></div>
<div class="field"><label>Password</label><input id="password" type="password" required minlength="8"></div>
<div class="field"><label>Confirm password</label><input id="confirm" type="password" required minlength="8"></div>
<button class="btn">Create Administrator</button>
</form></div>
<script>
const q=new URLSearchParams(location.search);document.getElementById('token').value=q.get('token')||'';
const msg=document.getElementById('msg');
document.getElementById('f').onsubmit=async e=>{
  e.preventDefault();msg.style.display='none';
  const p=document.getElementById('password').value,c=document.getElementById('confirm').value;
  if(p!==c){msg.className='msg err';msg.textContent='Passwords do not match.';msg.style.display='block';return}
  try{
    const r=await fetch('/api/admin/setup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token:document.getElementById('token').value,name:document.getElementById('name').value,email:document.getElementById('email').value,password:p})});
    const d=await r.json();
    if(!r.ok)throw new Error(d.error||'Setup failed');
    msg.className='msg ok';msg.textContent='Admin created! Go to the main site to log in.';msg.style.display='block';
    setTimeout(()=>location.href='/',1500);
  }catch(err){msg.className='msg err';msg.textContent=err.message;msg.style.display='block'}
};
</script></body></html>`;
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url || '/', 'http://localhost');
  const urlPath = decodeURIComponent(url.pathname);
  const method = req.method || 'GET';

  try {
    // Health
    if (urlPath === '/api/health') {
      return sendJson(res, 200, { ok: true, service: 'rebel-ink', storage: 'json-file', time: new Date().toISOString() });
    }

    // Admin setup page
    if (urlPath === '/admin-setup' && method === 'GET') {
      if (hasAdmin()) return send(res, 404, 'Admin setup is already completed.');
      return send(res, 200, setupPage(), 'text/html; charset=utf-8');
    }

    // Admin setup API
    if (urlPath === '/api/admin/setup' && method === 'POST') {
      const body = JSON.parse(await readBody(req));
      if (hasAdmin()) return sendJson(res, 409, { error: 'Admin setup has already been completed.' });
      if (!sameSecret(body.token || '', ADMIN_SETUP_TOKEN)) return sendJson(res, 403, { error: 'Invalid setup token.' });
      const name = cleanText(body.name, 120) || 'Rebel Ink Administrator';
      const email = normalizeEmail(body.email);
      const password = body.password || '';
      if (!/^\S+@\S+\.\S+$/.test(email)) return sendJson(res, 400, { error: 'Enter a valid email address.' });
      if (!validPassword(password)) return sendJson(res, 400, { error: 'Password must be at least 8 characters and include letters, numbers and a special character.' });
      if (findByEmail(email)) return sendJson(res, 409, { error: 'That email is already registered.' });
      const t = now();
      const user = {
        id: uid(), name, phone: '', country: 'United States', state: '',
        email, password_hash: hashPassword(password), role: 'admin', status: 'approved',
        admin_notes: '', created_at: t, updated_at: t, last_login_at: null
      };
      const users = readUsers();
      users.push(user);
      writeUsers(users);
      return sendJson(res, 201, { message: 'Administrator created successfully.', user: safeUser(user) });
    }

    // Register
    if (urlPath === '/api/register' && method === 'POST') {
      const body = JSON.parse(await readBody(req));
      const name = cleanText(body.name, 120);
      const phone = cleanText(body.phone, 40);
      const country = cleanText(body.country, 80);
      const state = cleanText(body.state, 80);
      const email = normalizeEmail(body.email);
      const password = body.password;
      if (!name || !phone || !country || !email || !validPassword(password)) {
        return sendJson(res, 400, { error: 'Please provide valid registration details and a strong password.' });
      }
      if (country === 'United States' && !state) return sendJson(res, 400, { error: 'US state is required.' });
      if (!/^\S+@\S+\.\S+$/.test(email)) return sendJson(res, 400, { error: 'Enter a valid email address.' });
      if (findByEmail(email)) return sendJson(res, 409, { error: 'An account with that email already exists.' });
      const t = now();
      const user = {
        id: uid(), name, phone, country, state, email,
        password_hash: hashPassword(password), role: 'member', status: 'pending',
        admin_notes: '', created_at: t, updated_at: t, last_login_at: null
      };
      const users = readUsers();
      users.push(user);
      writeUsers(users);
      return sendJson(res, 201, {
        message: 'Account created. Your account is pending admin approval. You will see the approval status in your member portal.',
        user: safeUser(user)
      });
    }

    // Login
    if (urlPath === '/api/login' && method === 'POST') {
      const body = JSON.parse(await readBody(req));
      const email = normalizeEmail(body.email);
      const password = body.password || '';
      const user = findByEmail(email);
      if (!user || !verifyPassword(password, user.password_hash)) {
        return sendJson(res, 401, { error: 'Invalid email or password.' });
      }
      if (user.status === 'suspended') return sendJson(res, 403, { error: 'This account is suspended. Contact the administrator.' });
      user.last_login_at = now();
      user.updated_at = now();
      writeUsers(readUsers().map(u => u.id === user.id ? user : u));
      return sendJson(res, 200, { token: tokenFor(user), user: safeUser(user) });
    }

    // Admin login
    if (urlPath === '/api/admin/login' && method === 'POST') {
      const body = JSON.parse(await readBody(req));
      const email = normalizeEmail(body.email);
      const password = body.password || '';
      const user = findByEmail(email);
      if (!user || user.role !== 'admin' || !verifyPassword(password, user.password_hash)) {
        return sendJson(res, 401, { error: 'Invalid admin credentials.' });
      }
      user.last_login_at = now();
      user.updated_at = now();
      writeUsers(readUsers().map(u => u.id === user.id ? user : u));
      return sendJson(res, 200, { token: tokenFor(user), user: safeUser(user) });
    }

    // Password reset disabled
    if (urlPath === '/api/reset-password' && method === 'POST') {
      return sendJson(res, 503, { error: 'Password reset is disabled until secure email verification is configured. Contact the administrator.' });
    }

    // Me
    if (urlPath === '/api/me' && method === 'GET') {
      const user = getAuthUser(req);
      if (!user) return sendJson(res, 401, { error: 'Authentication required.' });
      const bookings = readBookings()
        .filter(b => b.user_id === user.id)
        .sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)))
        .map(b => ({
          _id: b.id, service: b.service, date: b.date ? String(b.date).slice(0, 10) : '',
          problem: b.problem, photos: b.photos || [], status: b.status,
          adminNote: b.admin_note || '', createdAt: b.created_at, updatedAt: b.updated_at
        }));
      return sendJson(res, 200, { user: { ...safeUser(user), bookings } });
    }

    // Create booking
    if (urlPath === '/api/bookings' && method === 'POST') {
      const user = getAuthUser(req);
      if (!user) return sendJson(res, 401, { error: 'Authentication required.' });
      if (user.role !== 'admin' && user.status !== 'approved') {
        return sendJson(res, 403, { error: 'Your account must be approved before you can book an appointment.' });
      }
      const body = JSON.parse(await readBody(req));
      const service = cleanText(body.service, 180);
      const date = cleanText(body.date, 30);
      const problem = cleanText(body.problem, 5000);
      const photos = body.photos || [];
      if (!service || !problem) return sendJson(res, 400, { error: 'Service and problem/goals are required.' });
      if (!validPhotos(photos)) return sendJson(res, 400, { error: 'Photos must be up to 5 supported images. Please use smaller images if the upload is too large.' });
      if (date && !/^\d{4}-\d{2}-\d{2}$/.test(date)) return sendJson(res, 400, { error: 'Invalid preferred date.' });
      const t = now();
      const booking = {
        id: uid(), user_id: user.id, service, date: date || null, problem,
        photos, status: 'Pending', admin_note: '', approved_at: null, rejected_at: null,
        created_at: t, updated_at: t
      };
      const all = readBookings();
      all.push(booking);
      writeBookings(all);
      return sendJson(res, 201, {
        message: 'Appointment request submitted. Admin review is required.',
        booking: {
          _id: booking.id, service: booking.service, date: booking.date || '',
          problem: booking.problem, photos: booking.photos, status: booking.status,
          adminNote: '', createdAt: booking.created_at, updatedAt: booking.updated_at
        }
      });
    }

    // Admin members
    if (urlPath === '/api/admin/members' && method === 'GET') {
      const user = getAuthUser(req);
      if (!user || user.role !== 'admin') return sendJson(res, 403, { error: 'Admin access required.' });
      const members = readUsers().filter(u => u.role === 'member');
      const bookings = readBookings();
      const list = members
        .sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)))
        .map(u => ({
          ...safeUser(u),
          bookings: bookings.filter(b => b.user_id === u.id).map(b => ({
            _id: b.id, service: b.service, date: b.date || '', problem: b.problem,
            photos: b.photos || [], status: b.status, adminNote: b.admin_note || '',
            createdAt: b.created_at, updatedAt: b.updated_at
          }))
        }));
      const pendingBookings = bookings.filter(b => b.status === 'Pending').length;
      return sendJson(res, 200, {
        members: list,
        stats: {
          total: list.length,
          withBookings: new Set(bookings.map(b => b.user_id)).size,
          pending: list.filter(m => m.status === 'pending').length,
          pendingBookings
        }
      });
    }

    // Member status
    if (urlPath.startsWith('/api/admin/members/') && urlPath.endsWith('/status') && method === 'PATCH') {
      const user = getAuthUser(req);
      if (!user || user.role !== 'admin') return sendJson(res, 403, { error: 'Admin access required.' });
      const id = urlPath.split('/')[4];
      const body = JSON.parse(await readBody(req));
      const status = body.status;
      if (!['approved', 'suspended', 'pending'].includes(status)) return sendJson(res, 400, { error: 'Invalid member status.' });
      const users = readUsers();
      const idx = users.findIndex(u => u.id === id && u.role === 'member');
      if (idx < 0) return sendJson(res, 404, { error: 'Member not found.' });
      users[idx].status = status;
      users[idx].updated_at = now();
      writeUsers(users);
      return sendJson(res, 200, { message: `Member ${status}.`, user: safeUser(users[idx]) });
    }

    // Member notes
    if (urlPath.startsWith('/api/admin/members/') && urlPath.endsWith('/notes') && method === 'PATCH') {
      const user = getAuthUser(req);
      if (!user || user.role !== 'admin') return sendJson(res, 403, { error: 'Admin access required.' });
      const id = urlPath.split('/')[4];
      const body = JSON.parse(await readBody(req));
      const users = readUsers();
      const idx = users.findIndex(u => u.id === id && u.role === 'member');
      if (idx < 0) return sendJson(res, 404, { error: 'Member not found.' });
      users[idx].admin_notes = cleanText(body.notes, 5000);
      users[idx].updated_at = now();
      writeUsers(users);
      return sendJson(res, 200, { message: 'Notes saved.' });
    }

    // Booking status
    if (urlPath.startsWith('/api/admin/bookings/') && urlPath.endsWith('/status') && method === 'PATCH') {
      const user = getAuthUser(req);
      if (!user || user.role !== 'admin') return sendJson(res, 403, { error: 'Admin access required.' });
      const parts = urlPath.split('/');
      const userId = parts[4];
      const bookingId = parts[5];
      const body = JSON.parse(await readBody(req));
      const status = body.status;
      if (!['Pending', 'Approved', 'Rejected', 'Done', 'Cancelled'].includes(status)) {
        return sendJson(res, 400, { error: 'Invalid appointment status.' });
      }
      const bookings = readBookings();
      const idx = bookings.findIndex(b => b.id === bookingId && b.user_id === userId);
      if (idx < 0) return sendJson(res, 404, { error: 'Appointment not found.' });
      bookings[idx].status = status;
      bookings[idx].admin_note = cleanText(body.adminNote, 3000);
      bookings[idx].updated_at = now();
      if (status === 'Approved') bookings[idx].approved_at = now();
      if (status === 'Rejected') bookings[idx].rejected_at = now();
      writeBookings(bookings);
      return sendJson(res, 200, { message: `Appointment ${status.toLowerCase()}.` });
    }

    // CSV export
    if (urlPath === '/api/admin/export' && method === 'GET') {
      const user = getAuthUser(req);
      if (!user || user.role !== 'admin') return sendJson(res, 403, { error: 'Admin access required.' });
      const members = readUsers().filter(u => u.role === 'member');
      const bookings = readBookings();
      const esc = v => {
        const s = String(v ?? '');
        return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
      };
      const rows = [['Member ID', 'Name', 'Email', 'Phone', 'Country', 'State', 'Account Status', 'Member Since', 'Appointment ID', 'Service', 'Preferred Date', 'Appointment Status', 'Problem', 'Admin Note', 'Appointment Created']];
      for (const m of members) {
        const mine = bookings.filter(b => b.user_id === m.id);
        if (!mine.length) rows.push([m.id, m.name, m.email, m.phone, m.country, m.state, m.status, m.created_at, '', '', '', '', '', m.admin_notes || '', '']);
        for (const b of mine) {
          rows.push([m.id, m.name, m.email, m.phone, m.country, m.state, m.status, m.created_at, b.id, b.service, b.date, b.status, b.problem, b.admin_note, b.created_at]);
        }
      }
      const csv = '\ufeff' + rows.map(r => r.map(esc).join(',')).join('\r\n');
      res.writeHead(200, {
        'Content-Type': 'text/csv; charset=utf-8',
        'Content-Disposition': 'attachment; filename="rebel-ink-members.csv"'
      });
      return res.end(csv);
    }

    // Static files — same pattern as HairInk
    let filePath = path.join(ROOT, urlPath === '/' ? 'index.html' : urlPath);
    if (!filePath.startsWith(ROOT)) return send(res, 403, 'Forbidden');
    fs.readFile(filePath, (err, data) => {
      if (err) {
        fs.readFile(path.join(ROOT, 'public', 'index.html'), (e2, d2) => {
          if (e2) return send(res, 404, 'Not found');
          send(res, 200, d2, 'text/html; charset=utf-8');
        });
        return;
      }
      send(res, 200, data, TYPES[path.extname(filePath).toLowerCase()] || 'application/octet-stream');
    });
  } catch (e) {
    console.error(e);
    if (!res.headersSent) sendJson(res, 500, { error: 'Server error.' });
  }
});

function ensureDefaultAdmin() {
  ensureData();
  if (hasAdmin()) return;
  const email = 'admin@rebelink.com';
  if (findByEmail(email)) return;
  const t = now();
  const user = {
    id: uid(),
    name: 'Rebel Ink Administrator',
    phone: '',
    country: 'United States',
    state: '',
    email,
    password_hash: hashPassword('Admin123#'),
    role: 'admin',
    status: 'approved',
    admin_notes: '',
    created_at: t,
    updated_at: t,
    last_login_at: null
  };
  const users = readUsers();
  users.push(user);
  writeUsers(users);
  // Credentials are NOT printed in logs or shown on the website.
}

ensureData();
ensureDefaultAdmin();
server.listen(PORT, () => {
  console.log('Rebel Ink on port ' + PORT);
  console.log('Storage: data/users.json + data/bookings.json');
  console.log('Admin panel ready. Use your private admin credentials to sign in.');
});
