// server.js
// Minimal quiz backend: Express + SQLite + bcrypt + JWT + Google OAuth
// Install:
// npm install express sqlite3 bcrypt jsonwebtoken cors helmet body-parser

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const bodyParser = require('body-parser');
const path = require('path');
const fetch = global.fetch || require('node-fetch'); // Node 18+ has fetch; fallback if needed

const app = express();
app.use(helmet());
app.use(cors());
app.use(bodyParser.json({ limit: '4mb' }));

const PORT = process.env.PORT || 4000;
const DB_FILE = process.env.DB_FILE || path.join(__dirname, 'data.db');
const SECRET = process.env.JWT_SECRET || 'change_this_secret';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'ergashoff026@gmail.com'; // set in env for prod
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'obidjon026';       // set in env for prod

// Google OAuth config (put real ones in env in production)
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '930339744944-53ikbg8gsjfsbp5or46esnkt7gkmu7a1.apps.googleusercontent.com';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || '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';
// Must match exactly the value registered in Google Console
const GOOGLE_REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI || 'https://68c836c45881f.clouduz.ru/api/auth/google/callback';
// Where to send user after successful Google login (frontend page)
const FRONTEND_AFTER_LOGIN = process.env.FRONTEND_AFTER_LOGIN || 'https://68c836c45881f.clouduz.ru/quiz_frontend_with_api.html';

const db = new sqlite3.Database(DB_FILE);

console.log('Using DB file:', DB_FILE);

// Init tables
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY, name TEXT, email TEXT UNIQUE, password TEXT
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS tests (
    id TEXT PRIMARY KEY, title TEXT, durationSec INTEGER, payload TEXT
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS results (
    id TEXT PRIMARY KEY, userId TEXT, userName TEXT, testId TEXT, score INTEGER, total INTEGER, date INTEGER, answers TEXT
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT)`);
});

// Promise helpers
const run = (sql, params = []) =>
  new Promise((res, rej) =>
    db.run(sql, params, function (err) {
      if (err) rej(err);
      else res(this);
    })
  );
const get = (sql, params = []) =>
  new Promise((res, rej) =>
    db.get(sql, params, (err, row) => (err ? rej(err) : res(row)))
  );
const all = (sql, params = []) =>
  new Promise((res, rej) =>
    db.all(sql, params, (err, rows) => (err ? rej(err) : res(rows)))
  );

function uid(prefix = 'id') {
  return prefix + '_' + Math.random().toString(36).slice(2, 9);
}

// Auth middleware
function authenticate(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).send({ error: 'Unauthorized' });
  const token = auth.split(' ')[1];
  if (!token) return res.status(401).send({ error: 'No token' });
  try {
    const payload = jwt.verify(token, SECRET);
    req.user = payload;
    next();
  } catch (e) {
    return res.status(401).send({ error: 'Invalid token' });
  }
}

function requireAdmin(req, res, next) {
  if (!req.user) return res.status(403).send({ error: 'Require admin' });
  if (ADMIN_EMAIL) {
    if (req.user.email !== ADMIN_EMAIL) return res.status(403).send({ error: 'Forbidden' });
    return next();
  }
  next();
}

/* Routes */

// root
app.get('/', (req, res) => res.send({ ok: true, msg: 'Quiz backend running' }));

/* ---------- AUTH: register + login ---------- */

// register
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).send({ error: 'Invalid payload' });

    const existing = await get('SELECT * FROM users WHERE email = ?', [email]);
    if (existing) return res.status(400).send({ error: 'Email already exists' });

    const hashed = await bcrypt.hash(password, 10);
    const id = uid('u');
    await run('INSERT INTO users(id,name,email,password) VALUES(?,?,?,?)', [id, name, email, hashed]);

    const token = jwt.sign({ id, name, email }, SECRET, { expiresIn: '7d' });
    res.send({ ok: true, token, user: { id, name, email } });
  } catch (err) {
    console.error('Register error', err);
    res.status(500).send({ error: err.message });
  }
});

// login (includes hardcoded admin check + normal users)
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).send({ error: 'Invalid payload' });

    // Hardcoded admin: exact email + password
    if (email === ADMIN_EMAIL) {
      if (password !== ADMIN_PASSWORD) return res.status(401).send({ error: 'Admin paroli noto‘g‘ri!' });

      // Ensure admin user exists in DB (create if missing)
      let adminUser = await get('SELECT * FROM users WHERE email = ?', [email]);
      if (!adminUser) {
        const newId = uid('u');
        await run('INSERT INTO users(id,name,email,password) VALUES(?,?,?,?)', [newId, 'Admin', email, '']);
        adminUser = await get('SELECT * FROM users WHERE id = ?', [newId]);
      }
      const token = jwt.sign({ id: adminUser.id, name: adminUser.name || 'Admin', email: adminUser.email, role: 'admin' }, SECRET, { expiresIn: '7d' });
      return res.send({ ok: true, token, user: { id: adminUser.id, name: adminUser.name || 'Admin', email: adminUser.email } });
    }

    // Normal user login
    const user = await get('SELECT * FROM users WHERE email = ?', [email]);
    if (!user) return res.status(401).send({ error: 'Invalid credentials' });
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).send({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: user.id, name: user.name, email: user.email }, SECRET, { expiresIn: '7d' });
    res.send({ ok: true, token, user: { id: user.id, name: user.name, email: user.email } });
  } catch (e) {
    console.error('Login error', e);
    res.status(500).send({ error: e.message });
  }
});

/* ---------- Tests endpoints ---------- */

// create test (admin)
app.post('/api/tests', authenticate, requireAdmin, async (req, res) => {
  try {
    const { title, durationSec, questions } = req.body;
    if (!title || !Array.isArray(questions) || questions.length === 0) return res.status(400).send({ error: 'Invalid test data' });
    const id = uid('t');
    await run('INSERT INTO tests(id,title,durationSec,payload) VALUES(?,?,?,?)', [id, title, durationSec || null, JSON.stringify(questions)]);
    res.send({ ok: true, id });
  } catch (e) {
    console.error('Create test error', e);
    res.status(500).send({ error: e.message });
  }
});

// list tests
app.get('/api/tests', async (req, res) => {
  try {
    const rows = await all('SELECT id,title,durationSec,payload FROM tests');
    const out = rows.map(r => ({ id: r.id, title: r.title, durationSec: r.durationSec, questions: JSON.parse(r.payload || '[]') }));
    res.send(out);
  } catch (e) {
    console.error('List tests error', e);
    res.status(500).send({ error: e.message });
  }
});

// get test
app.get('/api/tests/:id', async (req, res) => {
  try {
    const row = await get('SELECT id,title,durationSec,payload FROM tests WHERE id=?', [req.params.id]);
    if (!row) return res.status(404).send({ error: 'Not found' });
    res.send({ id: row.id, title: row.title, durationSec: row.durationSec, questions: JSON.parse(row.payload || '[]') });
  } catch (e) {
    console.error('Get test error', e);
    res.status(500).send({ error: e.message });
  }
});

// set active (admin)
app.post('/api/active', authenticate, requireAdmin, async (req, res) => {
  try {
    const { testId } = req.body;
    await run('INSERT OR REPLACE INTO meta(k,v) VALUES(?,?)', ['activeTestId', testId]);
    res.send({ ok: true });
  } catch (e) {
    console.error('Set active error', e);
    res.status(500).send({ error: e.message });
  }
});

// get active
app.get('/api/active', async (req, res) => {
  try {
    const m = await get('SELECT v FROM meta WHERE k=?', ['activeTestId']);
    if (!m || !m.v) return res.send({ active: null });
    const t = await get('SELECT id,title,durationSec,payload FROM tests WHERE id=?', [m.v]);
    if (!t) return res.send({ active: null });
    res.send({ active: { id: t.id, title: t.title, durationSec: t.durationSec, questions: JSON.parse(t.payload || '[]') } });
  } catch (e) {
    console.error('Get active error', e);
    res.status(500).send({ error: e.message });
  }
});

/* ---------- Results ---------- */

// submit result
app.post('/api/results', authenticate, async (req, res) => {
  try {
    const { testId, score, total, answers, testTitle } = req.body;
    if (typeof score !== 'number' || typeof total !== 'number') return res.status(400).send({ error: 'Invalid payload' });
    const id = uid('r');
    await run(
      'INSERT INTO results(id,userId,userName,testId,score,total,date,answers) VALUES(?,?,?,?,?,?,?,?)',
      [id, req.user.id, req.user.name || req.user.email || '', testId, score, total, Date.now(), JSON.stringify(answers)]
    );
    res.send({ ok: true, id });
  } catch (e) {
    console.error('Submit result error', e);
    res.status(500).send({ error: e.message });
  }
});

// list results (admin)
app.get('/api/results', authenticate, requireAdmin, async (req, res) => {
  try {
    const rows = await all('SELECT * FROM results ORDER BY date DESC');
    const out = rows.map(r => ({ id: r.id, userId: r.userId, userName: r.userName, testId: r.testId, score: r.score, total: r.total, date: r.date, answers: JSON.parse(r.answers || '[]') }));
    res.send(out);
  } catch (e) {
    console.error('List results error', e);
    res.status(500).send({ error: e.message });
  }
});

// results CSV (admin)
app.get('/api/results/csv', authenticate, requireAdmin, async (req, res) => {
  try {
    const rows = await all('SELECT * FROM results ORDER BY date DESC');
    const csvRows = [['userName','testId','score','total','date','answers']];
    rows.forEach(r => {
      csvRows.push([ r.userName, r.testId, r.score, r.total, new Date(r.date).toISOString(), JSON.stringify(JSON.parse(r.answers || '[]')) ]);
    });
    const csv = csvRows.map(r => r.map(c => `"${String(c).replace(/"/g,'""')}"`).join(',')).join('\n');
    res.setHeader('Content-Type','text/csv');
    res.setHeader('Content-Disposition','attachment; filename="results.csv"');
    res.send(csv);
  } catch (e) {
    console.error('CSV error', e);
    res.status(500).send({ error: e.message });
  }
});

// reset (admin)
app.post('/api/reset', authenticate, requireAdmin, async (req, res) => {
  try {
    await run('DELETE FROM tests');
    await run('DELETE FROM results');
    await run('INSERT OR REPLACE INTO meta(k,v) VALUES(?,?)', ['activeTestId', null]);
    res.send({ ok: true });
  } catch (e) {
    console.error('Reset error', e);
    res.status(500).send({ error: e.message });
  }
});

/* ---------- Google OAuth (server-side) ---------- */

// helper: build Google auth url
function buildGoogleAuthUrl(state){
  const params = new URLSearchParams({
    client_id: GOOGLE_CLIENT_ID,
    redirect_uri: GOOGLE_REDIRECT_URI,
    response_type: 'code',
    scope: 'openid email profile',
    access_type: 'offline',
    prompt: 'select_account',
  });
  if(state) params.set('state', state);
  return 'https://accounts.google.com/o/oauth2/v2/auth?' + params.toString();
}

// Route: start OAuth flow (redirects user to Google)
app.get('/api/auth/google', (req, res) => {
  const state = req.query.state || '';
  res.redirect(buildGoogleAuthUrl(state));
});

// Route: Google callback (exchange code -> tokens -> get user info -> upsert user -> mint JWT)
app.get('/api/auth/google/callback', async (req, res) => {
  try {
    const code = req.query.code;
    if (!code) return res.status(400).send('Code param missing');

    // exchange code for tokens
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        redirect_uri: GOOGLE_REDIRECT_URI,
        grant_type: 'authorization_code'
      })
    });
    const tokenData = await tokenRes.json();
    if (tokenData.error) return res.status(400).send('Token exchange error: ' + (tokenData.error_description || tokenData.error));

    const access_token = tokenData.access_token;

    // fetch userinfo
    const userInfoRes = await fetch('https://www.googleapis.com/oauth2/v3/userinfo?access_token=' + encodeURIComponent(access_token));
    const userInfo = await userInfoRes.json();
    if (userInfo.error) return res.status(400).send('Userinfo error: ' + JSON.stringify(userInfo));

    const email = userInfo.email || '';
    const name = userInfo.name || (userInfo.given_name || '') + ' ' + (userInfo.family_name || '');
    const photo = userInfo.picture || '';

    // Upsert user into users table (create if not exists)
    let user = await get('SELECT * FROM users WHERE email = ?', [email]);
    if (!user) {
      const newId = uid('u');
      await run('INSERT INTO users(id,name,email,password) VALUES(?,?,?,?)', [newId, name, email, '']);
      user = await get('SELECT * FROM users WHERE id = ?', [newId]);
    } else {
      // update name if empty
      if (!user.name && name) {
        await run('UPDATE users SET name = ? WHERE id = ?', [name, user.id]);
        user = await get('SELECT * FROM users WHERE id = ?', [user.id]);
      }
    }

    // create JWT
    const payload = { id: user.id, name: user.name || name, email: user.email || email, auth_provider: 'google' };
    const token = jwt.sign(payload, SECRET, { expiresIn: '7d' });

    // redirect to frontend with token and optional user info (frontend will clean URL)
    const redirectUrl = new URL(FRONTEND_AFTER_LOGIN);
    redirectUrl.searchParams.set('token', token);
    redirectUrl.searchParams.set('name', encodeURIComponent(payload.name || ''));
    if (photo) redirectUrl.searchParams.set('photo', encodeURIComponent(photo));
    redirectUrl.searchParams.set('email', encodeURIComponent(user.email || ''));

    res.redirect(redirectUrl.toString());

  } catch (err) {
    console.error('Google callback error', err);
    res.status(500).send('Server error during Google OAuth');
  }
});

/* ---------- Start server ---------- */
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));