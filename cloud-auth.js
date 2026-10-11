/* MDbankA+ — ربط تسجيل الدخول بقاعدة بيانات Cloudflare D1 (يُحمَّل بعد سكربتات الصفحة الأصلية) */
(function () {
  'use strict';
  var SCOPED = ['qbank_stats_v1', 'qbank_prog_v1'];      // كائنات مفهرسة حسب scope المستخدم
  var PLAIN = ['qbank_settings_v1', 'qbank_theme_v1'];   // إعدادات عامة
  var HISTORY = 'qbank_surgery_question_history_v2::';   // سجل الأسئلة (مفتاح لكل مستخدم)
  var ready = false, lastPushed = '', timer = null;

  function $(id) { return document.getElementById(id); }
  function scope() { try { return state.auth.scope || 'guest'; } catch (e) { return 'guest'; } }
  function isCloud() { return /^user:/.test(scope()); }
  function readJ(k) { try { return JSON.parse(localStorage.getItem(k) || 'null'); } catch (e) { return null; } }

  async function api(path, opts) {
    opts = opts || {};
    try {
      var r = await fetch('/api' + path, {
        method: opts.method || 'GET',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: opts.body ? JSON.stringify(opts.body) : undefined,
        keepalive: !!opts.keepalive
      });
      var data = {}; try { data = await r.json(); } catch (e) {}
      return { ok: r.ok, status: r.status, data: data };
    } catch (e) {
      return { ok: false, status: 0, data: { message: 'تعذر الاتصال بالخادم. تحقق من الإنترنت.' } };
    }
  }

  // ---- مزامنة التقدّم ----
  function collect() {
    var sc = scope(), out = { v: 1, scoped: {}, plain: {}, history: null };
    SCOPED.forEach(function (k) { var o = readJ(k); if (o && o[sc] !== undefined) out.scoped[k] = o[sc]; });
    PLAIN.forEach(function (k) { var v = localStorage.getItem(k); if (v !== null) out.plain[k] = v; });
    var h = localStorage.getItem(HISTORY + sc); if (h !== null) out.history = h;
    return out;
  }
  function apply(d) {
    if (!d || d.v !== 1) return;
    var sc = scope();
    Object.keys(d.scoped || {}).forEach(function (k) {
      if (SCOPED.indexOf(k) < 0) return;
      var o = readJ(k) || {}; o[sc] = d.scoped[k]; localStorage.setItem(k, JSON.stringify(o));
    });
    Object.keys(d.plain || {}).forEach(function (k) { if (PLAIN.indexOf(k) >= 0) localStorage.setItem(k, d.plain[k]); });
    if (d.history != null) localStorage.setItem(HISTORY + sc, d.history);
  }
  async function push(force) {
    if (!ready || !isCloud()) return;
    var snap = JSON.stringify(collect());
    if (!force && snap === lastPushed) return;
    var r = await api('/data', { method: 'PUT', body: { data: JSON.parse(snap) }, keepalive: true });
    if (r.ok) lastPushed = snap;
  }
  function startSync() {
    if (timer) clearInterval(timer);
    timer = setInterval(function () { push(false); }, 20000);
  }

  async function enter(u) {
    ready = false;
    state.auth = { scope: 'user:' + u.email, name: u.name, email: u.email };
    var r = await api('/data');
    if (r.ok && r.data && r.data.data) apply(r.data.data);
    lastPushed = r.ok && r.data && r.data.data ? JSON.stringify(collect()) : '';
    ready = true;
    startSync();
    finishAuth();
  }

  // ---- استبدال دوال الدخول الأصلية ----
  window.handleUserAuth = async function () {
    var name = $('authName').value.trim();
    var email = $('authEmail').value.trim().toLowerCase();
    var password = $('authPassword').value;
    var signup = userAuthMode === 'signup';
    if (signup && name.length < 2) return setAuthMsg('userMsg', 'أدخل الاسم أولاً.', 'bad');
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return setAuthMsg('userMsg', 'أدخل بريدًا إلكترونيًا صحيحًا.', 'bad');
    if (password.length < 6) return setAuthMsg('userMsg', 'الرقم السري يجب أن يكون 6 أحرف أو أرقام على الأقل.', 'bad');
    var btn = $('userPrimaryBtn'); if (btn) btn.disabled = true;
    setAuthMsg('userMsg', 'جارٍ الاتصال...', '');
    var r = await api(signup ? '/register' : '/login', { method: 'POST', body: { name: name, email: email, password: password } });
    if (btn) btn.disabled = false;
    if (!r.ok) return setAuthMsg('userMsg', (r.data && r.data.message) || 'تعذر إكمال الطلب.', 'bad');
    setAuthMsg('userMsg', signup ? 'تم إنشاء الحساب.' : 'تم تسجيل الدخول.', 'ok');
    await enter(r.data.user);
  };

  var _setMode = window.setUserAuthMode;
  window.setUserAuthMode = function (m) {
    _setMode.apply(this, arguments);
    var b = $('userPrimaryBtn'); if (b) b.textContent = m === 'signup' ? 'إنشاء الحساب' : 'دخول';
  };

  var _signOut = window.signOutUser;
  window.signOutUser = async function () {
    if (isCloud()) {
      await push(true);
      await api('/logout', { method: 'POST' });
      ready = false; if (timer) clearInterval(timer);
    }
    return _signOut.apply(this, arguments);
  };

  var _delete = window.deleteMyAccount;
  window.deleteMyAccount = async function () {
    if (!isCloud()) return _delete.apply(this, arguments);
    if (!confirm('هل تريد حذف الحساب نهائيًا؟ لا يمكن التراجع عن هذا الإجراء.')) return;
    var pw = prompt('أدخل الرقم السري لتأكيد الحذف:');
    if (!pw) return;
    var r = await api('/delete-account', { method: 'POST', body: { password: pw } });
    if (!r.ok) return alert((r.data && r.data.message) || 'تعذر حذف الحساب.');
    ready = false; if (timer) clearInterval(timer);
    state.auth = { scope: 'guest', name: '', email: '' };
    $('authGate').classList.remove('hidden');
    switchAuth('user'); setUserAuthMode('login'); setAuthMsg('userMsg', 'تم حذف الحساب.', 'ok');
  };

  window.sendPasswordReset = function () {
    setAuthMsg('forgotMsg', 'استعادة الرقم السري بالبريد غير مفعّلة بعد. تواصل مع المشرف.', 'bad');
  };

  // حفظ عند إخفاء الصفحة/إغلاقها
  document.addEventListener('visibilitychange', function () { if (document.visibilityState === 'hidden') push(false); });
  window.addEventListener('pagehide', function () { push(false); });

  // استعادة الجلسة عند فتح الصفحة
  window.setUserAuthMode(userAuthMode);
  api('/me').then(function (r) { if (r.ok && r.data && r.data.user) enter(r.data.user); });
})();
