// MDbankA+ — واجهة الحسابات على Cloudflare Pages Functions + D1
// المسارات: POST /api/register | /api/login | /api/logout | /api/delete-account
//          GET  /api/me | /api/data      PUT /api/data

const ITERATIONS = 100000;           // أقصى قيمة تسمح بها Workers لـ PBKDF2
const SESSION_DAYS = 30;
const COOKIE = 'mdb_session';
const MAX_DATA_BYTES = 900000;       // حد أمان تحت حد صف D1

const enc = new TextEncoder();
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const now = () => Math.floor(Date.now() / 1000);

const MSG = {
  invalid_name: 'أدخل الاسم (حرفان على الأقل).',
  invalid_email: 'أدخل بريدًا إلكترونيًا صحيحًا.',
  weak_password: 'الرقم السري يجب أن يكون 6 أحرف أو أرقام على الأقل.',
  email_taken: 'هذا البريد مسجل بالفعل. اختر «دخول».',
  bad_credentials: 'البريد أو الرقم السري غير صحيح.',
  too_many: 'محاولات كثيرة. حاول مرة أخرى بعد قليل.',
  unauthorized: 'انتهت الجلسة. سجّل الدخول من جديد.',
  too_large: 'حجم البيانات أكبر من المسموح.',
  bad_request: 'طلب غير صالح.',
  forbidden: 'طلب مرفوض.',
  not_found: 'غير موجود.',
  server: 'حدث خطأ في الخادم.',
};

function json(obj, status = 200, headers = {}) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers },
  });
}
const fail = (code, status) => json({ error: code, message: MSG[code] || code }, status);

// ---------- كلمات السر والجلسات ----------
async function derive(password, salt, iterations) {
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  return crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, key, 256);
}
async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  return `pbkdf2$${ITERATIONS}$${b64(salt)}$${b64(await derive(password, salt, ITERATIONS))}`;
}
function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
let DUMMY = null; // لتساوي زمن الرد عند بريد غير موجود
async function verifyPassword(password, stored) {
  const [, it, s, h] = String(stored).split('$');
  const iterations = Math.min(Number(it) || ITERATIONS, ITERATIONS);
  return safeEqual(b64(await derive(password, unb64(s), iterations)), h);
}
async function sha256hex(str) {
  const d = await crypto.subtle.digest('SHA-256', enc.encode(str));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
function newToken() {
  return b64(crypto.getRandomValues(new Uint8Array(32))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
const cookieHeader = (value, maxAge) =>
  `${COOKIE}=${value}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAge}`;

async function createSession(db, userId) {
  const token = newToken();
  const t = now();
  await db.prepare('DELETE FROM sessions WHERE user_id=? AND expires_at<?').bind(userId, t).run();
  await db
    .prepare('INSERT INTO sessions(token_hash,user_id,created_at,expires_at) VALUES(?,?,?,?)')
    .bind(await sha256hex(token), userId, t, t + SESSION_DAYS * 86400)
    .run();
  return cookieHeader(token, SESSION_DAYS * 86400);
}
function readCookie(request, name) {
  const m = (request.headers.get('Cookie') || '').match(new RegExp('(?:^|;\\s*)' + name + '=([^;]+)'));
  return m ? m[1] : null;
}
async function currentUser(db, request) {
  const token = readCookie(request, COOKIE);
  if (!token) return null;
  return db
    .prepare(
      `SELECT u.id, u.email, u.name FROM sessions s JOIN users u ON u.id = s.user_id
       WHERE s.token_hash=? AND s.expires_at>?`
    )
    .bind(await sha256hex(token), now())
    .first();
}

// ---------- تحديد المحاولات ----------
async function limited(db, key, max, windowSec) {
  const t = now();
  const row = await db.prepare('SELECT count,reset_at FROM rate_limits WHERE key=?').bind(key).first();
  if (!row || row.reset_at <= t) {
    await db.prepare('INSERT OR REPLACE INTO rate_limits(key,count,reset_at) VALUES(?,?,?)').bind(key, 1, t + windowSec).run();
    return false;
  }
  if (row.count >= max) return true;
  await db.prepare('UPDATE rate_limits SET count=count+1 WHERE key=?').bind(key).run();
  return false;
}

// ---------- أدوات ----------
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
async function body(request) {
  if (!(request.headers.get('Content-Type') || '').includes('application/json')) return null;
  try { return await request.json(); } catch { return null; }
}
const publicUser = (u) => ({ email: u.email, name: u.name });

export async function onRequest({ request, env }) {
  const url = new URL(request.url);
  const route = url.pathname.replace(/^\/api\/?/, '').replace(/\/$/, '');
  const method = request.method;
  const db = env.DB;
  if (!db) return fail('server', 500);

  // حماية CSRF: الطلبات المعدِّلة يجب أن تأتي من نفس الموقع
  if (method !== 'GET' && method !== 'HEAD') {
    const origin = request.headers.get('Origin');
    if (origin && origin !== url.origin) return fail('forbidden', 403);
  }
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';

  try {
    // ----- تسجيل حساب جديد -----
    if (method === 'POST' && route === 'register') {
      const b = await body(request);
      if (!b) return fail('bad_request', 400);
      const name = String(b.name || '').trim().slice(0, 80);
      const email = String(b.email || '').trim().toLowerCase().slice(0, 200);
      const password = String(b.password || '');
      if (name.length < 2) return fail('invalid_name', 400);
      if (!EMAIL_RE.test(email)) return fail('invalid_email', 400);
      if (password.length < 6 || password.length > 200) return fail('weak_password', 400);
      if (await limited(db, `reg:${ip}`, 10, 3600)) return fail('too_many', 429);
      if (await db.prepare('SELECT 1 FROM users WHERE email=?').bind(email).first()) return fail('email_taken', 409);

      const id = crypto.randomUUID();
      try {
        await db
          .prepare('INSERT INTO users(id,email,name,password_hash,created_at,last_login_at) VALUES(?,?,?,?,?,?)')
          .bind(id, email, name, await hashPassword(password), now(), now())
          .run();
      } catch (e) {
        if (/UNIQUE/i.test(String(e.message || e))) return fail('email_taken', 409);
        throw e;
      }
      return json({ user: { email, name } }, 201, { 'Set-Cookie': await createSession(db, id) });
    }

    // ----- تسجيل الدخول -----
    if (method === 'POST' && route === 'login') {
      const b = await body(request);
      if (!b) return fail('bad_request', 400);
      const email = String(b.email || '').trim().toLowerCase().slice(0, 200);
      const password = String(b.password || '').slice(0, 200);
      const rlKey = `login:${email}:${ip}`;
      if (await limited(db, rlKey, 10, 900)) return fail('too_many', 429);

      const u = await db.prepare('SELECT id,email,name,password_hash FROM users WHERE email=?').bind(email).first();
      if (!u) {
        DUMMY ??= await hashPassword('dummy-password');
        await verifyPassword(password, DUMMY);
        return fail('bad_credentials', 401);
      }
      if (!(await verifyPassword(password, u.password_hash))) return fail('bad_credentials', 401);

      await db.prepare('DELETE FROM rate_limits WHERE key=?').bind(rlKey).run();
      await db.prepare('UPDATE users SET last_login_at=? WHERE id=?').bind(now(), u.id).run();
      return json({ user: publicUser(u) }, 200, { 'Set-Cookie': await createSession(db, u.id) });
    }

    // ----- الجلسة الحالية -----
    if (method === 'GET' && route === 'me') {
      const u = await currentUser(db, request);
      return u ? json({ user: publicUser(u) }) : fail('unauthorized', 401);
    }

    // ----- تسجيل الخروج -----
    if (method === 'POST' && route === 'logout') {
      const token = readCookie(request, COOKIE);
      if (token) await db.prepare('DELETE FROM sessions WHERE token_hash=?').bind(await sha256hex(token)).run();
      return json({ ok: true }, 200, { 'Set-Cookie': cookieHeader('', 0) });
    }

    // ----- بيانات التقدّم -----
    if (route === 'data' && (method === 'GET' || method === 'PUT')) {
      const u = await currentUser(db, request);
      if (!u) return fail('unauthorized', 401);
      if (method === 'GET') {
        const row = await db.prepare('SELECT data,updated_at FROM user_data WHERE user_id=?').bind(u.id).first();
        return json({ data: row ? JSON.parse(row.data) : null, updated_at: row ? row.updated_at : null });
      }
      const raw = await request.text();
      if (raw.length > MAX_DATA_BYTES) return fail('too_large', 413);
      let parsed;
      try { parsed = JSON.parse(raw); } catch { return fail('bad_request', 400); }
      if (!parsed || typeof parsed.data !== 'object' || parsed.data === null) return fail('bad_request', 400);
      await db
        .prepare(
          `INSERT INTO user_data(user_id,data,updated_at) VALUES(?,?,?)
           ON CONFLICT(user_id) DO UPDATE SET data=excluded.data, updated_at=excluded.updated_at`
        )
        .bind(u.id, JSON.stringify(parsed.data), now())
        .run();
      return json({ ok: true });
    }

    // ----- حذف الحساب (يتطلب كلمة السر) -----
    if (method === 'POST' && route === 'delete-account') {
      const u = await currentUser(db, request);
      if (!u) return fail('unauthorized', 401);
      const b = await body(request);
      const row = await db.prepare('SELECT password_hash FROM users WHERE id=?').bind(u.id).first();
      if (!b || !row || !(await verifyPassword(String(b.password || ''), row.password_hash))) return fail('bad_credentials', 401);
      await db.batch([
        db.prepare('DELETE FROM sessions WHERE user_id=?').bind(u.id),
        db.prepare('DELETE FROM user_data WHERE user_id=?').bind(u.id),
        db.prepare('DELETE FROM users WHERE id=?').bind(u.id),
      ]);
      return json({ ok: true }, 200, { 'Set-Cookie': cookieHeader('', 0) });
    }

    return fail('not_found', 404);
  } catch (e) {
    console.error(e);
    return fail('server', 500);
  }
}
