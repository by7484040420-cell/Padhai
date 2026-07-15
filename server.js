// PadhAI Backend Server
// Sirf Node.js ke built-in modules — koi npm install nahi chahiye
// Chalane ke liye: node server.js

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const url = require('url');

const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'database.json');

function loadDB() {
  if (!fs.existsSync(DB_FILE)) {
    return { users: {}, sessions: {}, profiles: {}, progress: {} };
  }
  const db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  db.profiles = db.profiles || {};
  db.progress = db.progress || {};
  return db;
}
function saveDB(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

function hashPassword(password, salt) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { salt, hash };
}
function verifyPassword(password, salt, hash) {
  return crypto.scryptSync(password, salt, 64).toString('hex') === hash;
}
function makeToken() {
  return crypto.randomBytes(24).toString('hex');
}

function sendJSON(res, status, data) {
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS'
  });
  res.end(JSON.stringify(data));
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => (body += chunk));
    req.on('end', () => {
      try { resolve(body ? JSON.parse(body) : {}); } catch (e) { reject(e); }
    });
  });
}
function getUserFromToken(db, req) {
  const auth = req.headers['authorization'];
  if (!auth) return null;
  const token = auth.replace('Bearer ', '');
  return db.sessions[token] || null;
}

const server = http.createServer(async (req, res) => {
  const parsed = url.parse(req.url, true);
  const pathname = parsed.pathname;

  if (req.method === 'OPTIONS') return sendJSON(res, 200, {});

  const db = loadDB();

  try {
    // ---- SIGNUP ----
    if (pathname === '/api/signup' && req.method === 'POST') {
      const { username, password } = await readBody(req);
      if (!username || !password || username.trim().length < 3 || password.length < 4) {
        return sendJSON(res, 400, { error: 'Username kam se kam 3 characters aur password kam se kam 4 characters ka hona chahiye' });
      }
      const uname = username.trim().toLowerCase();
      if (db.users[uname]) return sendJSON(res, 400, { error: 'Yeh username pehle se registered hai' });
      const { salt, hash } = hashPassword(password);
      db.users[uname] = { username: username.trim(), salt, hash, createdAt: Date.now() };
      const token = makeToken();
      db.sessions[token] = uname;
      saveDB(db);
      return sendJSON(res, 200, { token, username: username.trim() });
    }

    // ---- LOGIN ----
    if (pathname === '/api/login' && req.method === 'POST') {
      const { username, password } = await readBody(req);
      const uname = (username || '').trim().toLowerCase();
      const user = db.users[uname];
      if (!user || !verifyPassword(password, user.salt, user.hash)) {
        return sendJSON(res, 401, { error: 'Galat username ya password' });
      }
      const token = makeToken();
      db.sessions[token] = uname;
      saveDB(db);
      return sendJSON(res, 200, { token, username: user.username, profile: db.profiles[uname] || null });
    }

    // ---- SAVE PROFILE (exam choice, qualification) ----
    if (pathname === '/api/profile' && req.method === 'POST') {
      const me = getUserFromToken(db, req);
      if (!me) return sendJSON(res, 401, { error: 'Login required' });
      const data = await readBody(req);
      db.profiles[me] = { ...(db.profiles[me] || {}), ...data, updatedAt: Date.now() };
      saveDB(db);
      return sendJSON(res, 200, { profile: db.profiles[me] });
    }

    // ---- GET PROFILE ----
    if (pathname === '/api/profile' && req.method === 'GET') {
      const me = getUserFromToken(db, req);
      if (!me) return sendJSON(res, 401, { error: 'Login required' });
      return sendJSON(res, 200, { profile: db.profiles[me] || null });
    }

    // ---- SAVE PROGRESS (lesson completed / quiz score) ----
    if (pathname === '/api/progress' && req.method === 'POST') {
      const me = getUserFromToken(db, req);
      if (!me) return sendJSON(res, 401, { error: 'Login required' });
      const data = await readBody(req);
      if (!db.progress[me]) db.progress[me] = { completedLessons: [], quizScores: {} };
      if (data.lessonId && !db.progress[me].completedLessons.includes(data.lessonId)) {
        db.progress[me].completedLessons.push(data.lessonId);
      }
      if (data.quizId) {
        db.progress[me].quizScores[data.quizId] = { score: data.score, total: data.total, at: Date.now() };
      }
      saveDB(db);
      return sendJSON(res, 200, { progress: db.progress[me] });
    }

    // ---- GET PROGRESS ----
    if (pathname === '/api/progress' && req.method === 'GET') {
      const me = getUserFromToken(db, req);
      if (!me) return sendJSON(res, 401, { error: 'Login required' });
      return sendJSON(res, 200, { progress: db.progress[me] || { completedLessons: [], quizScores: {} } });
    }

    // ---- Serve frontend ----
    if (pathname === '/' || pathname === '/index.html') {
      const filePath = path.join(__dirname, 'public', 'index.html');
      if (fs.existsSync(filePath)) {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        return res.end(fs.readFileSync(filePath));
      }
    }

    sendJSON(res, 404, { error: 'Not found' });
  } catch (e) {
    sendJSON(res, 500, { error: 'Server error: ' + e.message });
  }
});

server.listen(PORT, () => {
  console.log(`PadhAI backend chal raha hai: http://localhost:${PORT}`);
});
