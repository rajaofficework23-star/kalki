/* KalkiChat Web v1 — app logic (plain script, no build step).
 * Requires: firebase-app-compat, firebase-auth-compat, firebase-firestore-compat,
 *            firebase-config.js (KALKI_FIREBASE_CONFIG), crypto.js (KCrypto).
 */
(function () {
'use strict';

/* ============================== utils ============================== */
function $(id) { return document.getElementById(id); }
function showScreen(id) {
  ['screen-pin','screen-key','screen-username','screen-password',
   'screen-restore','screen-main','screen-chat'].forEach(function (s) {
    $(s).classList.toggle('hidden', s !== id);
  });
}
var toastTimer = null;
function toast(msg) {
  var t = $('toast'); t.textContent = msg; t.classList.remove('hidden');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(function () { t.classList.add('hidden'); }, 2800);
}
function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
  });
}
function fmtTime(ts) {
  if (!ts) return '';
  var d = new Date(ts), now = new Date();
  var hh = d.getHours(), mm = ('0' + d.getMinutes()).slice(-2);
  var ap = hh >= 12 ? 'PM' : 'AM'; hh = hh % 12 || 12;
  if (d.toDateString() === now.toDateString()) return hh + ':' + mm + ' ' + ap;
  var y = new Date(now); y.setDate(now.getDate() - 1);
  if (d.toDateString() === y.toDateString()) return 'Yesterday';
  return d.getDate() + '/' + (d.getMonth() + 1) + '/' + d.getFullYear();
}
function fmtLastSeen(ts) {
  if (!ts) return 'offline';
  var diff = Date.now() - ts;
  if (diff < 2 * 60 * 1000) return 'online';
  var m = Math.floor(diff / 60000);
  if (m < 60) return 'last seen ' + m + ' min ago';
  var h = Math.floor(m / 60);
  if (h < 24) return 'last seen ' + h + ' hr ago';
  return 'last seen ' + fmtTime(ts);
}
function showErr(id, msg) {
  var e = $(id); e.textContent = msg; e.classList.remove('hidden');
}
function hideErr(id) { $(id).classList.add('hidden'); }

/* ============================== state ============================== */
var S = {
  uid: null, username: null, usernameLower: null,
  authUid: null,             // firebase anonymous uid; S.uid is the IDENTITY uid
                            // (for linked logins S.uid = main claimed uid, authUid = this device's anon uid)
  linkedUid: null,          // android uid when this web login is linked to a phone identity
  priv32: null,             // my web HPKE private key
  linkedPriv32: null,       // imported android HPKE private key (backup restore)
  pubB64: null,             // my web public keyset b64
  groupKeys: {},            // groupId -> {key:Uint8Array, keyId:number}
  oldChatIds: [], oldGroupIds: [],
  chats: [], groups: [],
  open: null,               // {kind:'chat'|'group', id, name, readonly, ...}
  sessionId: null,
  timers: [], unsubs: [],
  myProfile: {},
  isAdmin: false,           // true when admins/master.uid == my identity
};
var LS = {
  uid: 'kc_uid', username: 'kc_username', linkedUid: 'kc_linked_uid',
  authUid: 'kc_auth_uid',
  keyOk: 'kc_key_ok', keyIssue: 'kc_key_issue', lastSeen: 'kc_last_seen',
  pin: 'kc_pin', priv: 'kc_priv_b64', linkedPriv: 'kc_linked_priv_b64',
  backupDone: 'kc_backup_done',
};
function lsGet(k) { try { return localStorage.getItem(k); } catch (e) { return null; } }
function lsSet(k, v) { try { localStorage.setItem(k, v); } catch (e) {} }
function lsDel(k) { try { localStorage.removeItem(k); } catch (e) {} }

var db = null, auth = null;

/* ============================== PIN lock ============================== */
/* 6-digit web PIN. Verifier in localStorage: {saltB64, hashB64, iter}.
 * Fresh tab load always asks; sessionStorage.kc_unlocked=1 skips until tab closes. */
async function pinVerifier(pin) {
  var salt = KCrypto.getRandom(16);
  var hash = await KCrypto.pbkdf2(KCrypto.te.encode('kcpin:' + pin), salt, 100000, 32);
  return JSON.stringify({ saltB64: KCrypto.bytesToB64(salt),
                          hashB64: KCrypto.bytesToB64(hash), iter: 100000 });
}
async function pinCheck(pin) {
  try {
    var v = JSON.parse(lsGet(LS.pin));
    var salt = KCrypto.b64ToBytes(v.saltB64);
    var hash = await KCrypto.pbkdf2(KCrypto.te.encode('kcpin:' + pin), salt, v.iter || 100000, 32);
    var want = KCrypto.b64ToBytes(v.hashB64);
    if (hash.length !== want.length) return false;
    var diff = 0;
    for (var i = 0; i < hash.length; i++) diff |= hash[i] ^ want[i];
    return diff === 0;
  } catch (e) { return false; }
}
function pinNeeded() {
  if (sessionStorage.getItem('kc_unlocked') === '1') return false;
  return !!lsGet(LS.pin);
}
function showPinScreen(isSetup) {
  $('pin-sub').textContent = isSetup
    ? 'Naya 6-digit Web PIN set karo (ye browser lock rahega)'
    : '6-digit Web PIN dalo';
  $('pin-input').value = '';
  hideErr('pin-error');
  $('pin-reset').classList.toggle('hidden', isSetup);
  $('pin-go').textContent = isSetup ? 'Set PIN' : 'Unlock';
  $('pin-go').onclick = async function () {
    var pin = $('pin-input').value.trim();
    if (!/^\d{6}$/.test(pin)) {
      showErr('pin-error', '6-digit PIN dalo (sirf numbers)');
      return;
    }
    if (isSetup) {
      lsSet(LS.pin, await pinVerifier(pin));
      sessionStorage.setItem('kc_unlocked', '1');
      // continue the post-login flow (restore check / main)
      if (S.uid && !lsGet(LS.backupDone)) showRestoreScreen();
      else enterMain();
    } else {
      if (await pinCheck(pin)) {
        sessionStorage.setItem('kc_unlocked', '1');
        routeAfterUnlock();
      } else {
        showErr('pin-error', 'Galat PIN');
      }
    }
  };
  showScreen('screen-pin');
  setTimeout(function () { $('pin-input').focus(); }, 50);
}
$('pin-input') && $('pin-input').addEventListener('keydown', function (e) {
  if (e.key === 'Enter') $('pin-go').click();
});
$('pin-reset').onclick = function () {
  // PIN bhool gaye: full logout, dobara key login.
  doLogout(true);
};

/* ============================== key login ============================== */
function validateKeyInput() {
  hideErr('key-error');
  var key = $('key-input').value.trim();
  var r = KCrypto.validateKey(key); // includes clock-rollback guard (localStorage)
  if (!r.ok) {
    showErr('key-error', KCrypto.WRONG_KEY_MSG);
    return;
  }
  lsSet(LS.keyOk, '1');
  lsSet(LS.keyIssue, String(r.issueMillis));
  var days = KCrypto.keyDaysLeft(key);
  $('key-days').textContent = days >= 0 ? ('Key valid: ' + days + ' din baaki') : '';
  // key OK -> username step
  showUsernameScreen();
}
$('key-go').onclick = validateKeyInput;
$('key-input').addEventListener('keydown', function (e) {
  if (e.key === 'Enter') validateKeyInput();
});

/* ============================== firebase ============================== */
function initFirebase() {
  firebase.initializeApp(KALKI_FIREBASE_CONFIG);
  auth = firebase.auth();
  db = firebase.firestore();
}
async function ensureAnonAuth() {
  if (auth.currentUser) return auth.currentUser;
  var cred = await auth.signInAnonymously();
  return cred.user;
}

/* ============================== username + password ============================== */
var pendingUsername = null, pendingUid = null, pendingIsNew = false, pendingLinkedUid = null;

function showUsernameScreen() {
  $('username-input').value = '';
  hideErr('username-error');
  $('username-title').textContent = 'Username';
  $('username-sub').textContent = 'Apna KalkiChat username likho';
  showScreen('screen-username');
  setTimeout(function () { $('username-input').focus(); }, 50);
}
$('username-back').onclick = function () { showScreen('screen-key'); };

async function usernameContinue() {
  hideErr('username-error');
  var name = $('username-input').value.trim();
  if (!/^[a-zA-Z0-9_]{3,20}$/.test(name)) {
    showErr('username-error', '3-20 letters, numbers ya _');
    return;
  }
  $('username-go').disabled = true;
  try {
    await ensureAnonAuth();
    var lower = name.toLowerCase();
    var claim = await db.collection('usernames').doc(lower).get();
    pendingUsername = name; pendingIsNew = !claim.exists;
    pendingLinkedUid = null; pendingUid = null;
    if (claim.exists) {
      var ownerUid = claim.data().uid;
      // anti-impersonation: claim must agree with the user doc
      var userDoc = await db.collection('users').doc(ownerUid).get();
      if (!userDoc.exists || (userDoc.data().usernameLower || '') !== lower) {
        showErr('username-error', 'Username claim mismatch — phone se check karo.');
        return;
      }
      if (ownerUid === auth.currentUser.uid) {
        // same browser, same anon uid (returning session)
        pendingUid = ownerUid; pendingIsNew = false;
      } else {
        // username belongs to another uid (usually the phone) -> linked login
        pendingLinkedUid = ownerUid;
      }
      showPasswordScreen(false);
    } else {
      showPasswordScreen(true);
    }
  } catch (e) {
    showErr('username-error', 'Network error, dobara try karo.');
  } finally {
    $('username-go').disabled = false;
  }
}
$('username-go').onclick = usernameContinue;
$('username-input').addEventListener('keydown', function (e) {
  if (e.key === 'Enter') usernameContinue();
});

function showPasswordScreen(isSetup) {
  $('pw-title').textContent = isSetup ? 'Password set karo' : 'Password dalo';
  $('pw-sub').textContent = isSetup
    ? 'Min 6 characters. Ye password har naye browser me lagega.'
    : pendingUsername + ' ke liye password dalo';
  $('pw-input').value = ''; $('pw-input2').value = '';
  $('pw-input2').classList.toggle('hidden', !isSetup);
  // forget-password only makes sense for an existing account
  $('pw-forget').classList.toggle('hidden', !!isSetup);
  hideErr('pw-error');
  $('pw-go').onclick = isSetup ? passwordSetup : passwordVerify;
  showScreen('screen-password');
  setTimeout(function () { $('pw-input').focus(); }, 50);
}

/* Forget password (self-service): old password + new password + confirm. */
$('pw-forget').onclick = function () {
  if (pendingIsNew) {
    showErr('pw-error', 'Pehle account banao, phir reset karna');
    return;
  }
  $('forget-user-label').textContent = (pendingUsername || '') + ' ka password reset karo';
  $('forget-old').value = ''; $('forget-new').value = ''; $('forget-new2').value = '';
  hideErr('forget-error');
  $('modal-forget').classList.remove('hidden');
  setTimeout(function () { $('forget-old').focus(); }, 50);
};
$('forget-cancel').onclick = function () {
  $('modal-forget').classList.add('hidden');
};
$('forget-go').onclick = async function () {
  hideErr('forget-error');
  var oldPw = $('forget-old').value;
  var np1 = $('forget-new').value, np2 = $('forget-new2').value;
  if (np1.length < 6) { showErr('forget-error', 'Naya password min 6 characters'); return; }
  if (np1 !== np2) { showErr('forget-error', 'Naya password match nahi ho raha'); return; }
  $('forget-go').disabled = true;
  try {
    // same target as passwordVerify: the identity doc holding the pwd
    var targetUid = pendingLinkedUid || pendingUid;
    var userDoc = (await db.collection('users').doc(targetUid).get()).data();
    if (!userDoc) { showErr('forget-error', 'User nahi mila'); return; }
    var ok = await verifyPwd(oldPw, userDoc.pwd || null);
    if (!ok) { showErr('forget-error', 'Purana password galat hai'); return; }
    await db.collection('users').doc(targetUid).update({ pwd: await makePwdVerifier(np1) });
    $('modal-forget').classList.add('hidden');
    toast('Password badal gaya, ab login karo');
  } catch (e) {
    showErr('forget-error', 'Network error, dobara try karo');
  } finally {
    $('forget-go').disabled = false;
  }
};
$('pw-back').onclick = function () { showUsernameScreen(); };
$('pw-input').addEventListener('keydown', function (e) {
  if (e.key === 'Enter') $('pw-go').click();
});
$('pw-input2').addEventListener('keydown', function (e) {
  if (e.key === 'Enter') $('pw-go').click();
});

async function makePwdVerifier(password) {
  var salt = KCrypto.getRandom(16);
  var hash = await KCrypto.pbkdf2(KCrypto.te.encode(password), salt, 100000, 32);
  return { saltB64: KCrypto.bytesToB64(salt),
           hashB64: KCrypto.bytesToB64(hash), iter: 100000 };
}
async function verifyPwd(password, pwdMap) {
  if (!pwdMap) return true; // legacy user, no password yet
  try {
    var salt = KCrypto.b64ToBytes(pwdMap.saltB64);
    var want = KCrypto.b64ToBytes(pwdMap.hashB64);
    var iter = parseInt(pwdMap.iter || '100000', 10) || 100000;
    var got = await KCrypto.pbkdf2(KCrypto.te.encode(password), salt, iter, 32);
    if (got.length !== want.length) return false;
    var diff = 0;
    for (var i = 0; i < got.length; i++) diff |= got[i] ^ want[i];
    return diff === 0;
  } catch (e) { return false; }
}

/* New username registration: key -> username -> set password -> done. */
async function passwordSetup() {
  hideErr('pw-error');
  var p1 = $('pw-input').value, p2 = $('pw-input2').value;
  if (p1.length < 6) { showErr('pw-error', 'Min 6 characters'); return; }
  if (p1 !== p2) { showErr('pw-error', 'Dono password same hone chahiye'); return; }
  $('pw-go').disabled = true;
  try {
    var user = await ensureAnonAuth();
    var uid = user.uid;
    var lower = pendingUsername.toLowerCase();
    // generate my HPKE keypair
    var priv = KCrypto.getRandom(32);
    var pub = KCrypto.x25519(priv, KCrypto.BASE9);
    var pubB64 = KCrypto.bytesToB64(KCrypto.serializeHpkePublicKeyset(pub, randKeyId()));
    var verifier = await makePwdVerifier(p1);
    var now = Date.now();
    var userDoc = {
      username: pendingUsername, usernameLower: lower,
      hpkePublicKey: pubB64, pwd: verifier,
      createdAt: now, isWeb: true,
    };
    await db.runTransaction(async function (t) {
      var claimRef = db.collection('usernames').doc(lower);
      var claim = await t.get(claimRef);
      if (claim.exists) throw new Error('taken');
      t.set(claimRef, { uid: uid });
      t.set(db.collection('users').doc(uid), userDoc);
    });
    // save session
    S.uid = uid; S.authUid = uid; S.username = pendingUsername; S.usernameLower = lower;
    S.priv32 = priv; S.pubB64 = pubB64; S.linkedUid = null;
    lsSet(LS.priv, KCrypto.bytesToB64(priv));
    persistSession();
    afterAuth(true);
  } catch (e) {
    showErr('pw-error', e && e.message === 'taken'
      ? 'Username taken, koi aur try karo.' : 'Network error, dobara try karo.');
  } finally {
    $('pw-go').disabled = false;
  }
}

/* Returning login: key -> username -> password verify. */
async function passwordVerify() {
  hideErr('pw-error');
  var pw = $('pw-input').value;
  if (!pw) { showErr('pw-error', 'Password dalo'); return; }
  $('pw-go').disabled = true;
  try {
    var user = await ensureAnonAuth();
    var uid = user.uid;
    // resolve which user doc holds the password
    var targetUid = pendingLinkedUid || pendingUid;
    var userDoc = (await db.collection('users').doc(targetUid).get()).data();
    if (!userDoc) { showErr('pw-error', 'User nahi mila'); return; }
    var ok = await verifyPwd(pw, userDoc.pwd || null);
    if (!ok) { showErr('pw-error', 'Galat password'); return; }
    // load (or generate) my web keypair
    var savedPriv = lsGet(LS.priv);
    var priv, pubB64;
    if (savedPriv && pendingUid && !pendingIsNew) {
      priv = KCrypto.b64ToBytes(savedPriv);
    } else {
      priv = KCrypto.getRandom(32);
      lsSet(LS.priv, KCrypto.bytesToB64(priv));
    }
    var pub = KCrypto.x25519(priv, KCrypto.BASE9);
    pubB64 = KCrypto.bytesToB64(KCrypto.serializeHpkePublicKeyset(pub, randKeyId()));
    // upsert my per-device session doc keyed by ANONYMOUS uid (never carries
    // username/usernameLower for linked logins — kills duplicate identities).
    // Primary login keeps the old behavior (username + pwd verifier on the doc).
    var lower = pendingUsername.toLowerCase();
    var now = Date.now();
    var doc = { linkedTo: pendingLinkedUid || null,
                hpkePublicKey: pubB64, isWeb: true, createdAt: now };
    if (!pendingLinkedUid) {
      doc.username = pendingUsername; doc.usernameLower = lower;
      if (!userDoc.pwd) doc.pwd = await makePwdVerifier(pw); // legacy migration
    }
    await db.collection('users').doc(uid).set(doc, { merge: true });
    if (pendingLinkedUid) {
      // keep the MAIN identity doc pointing at this session's active key so
      // new chats encrypt with a key this device can open
      await db.collection('users').doc(pendingLinkedUid)
        .set({ hpkePublicKey: pubB64 }, { merge: true });
    }
    S.authUid = uid;
    if (pendingLinkedUid) { S.uid = pendingLinkedUid; } else { S.uid = uid; }
    S.username = pendingUsername; S.usernameLower = lower;
    S.priv32 = priv; S.pubB64 = pubB64;
    S.linkedUid = pendingLinkedUid;
    persistSession();
    afterAuth(false);
  } catch (e) {
    showErr('pw-error', 'Network error, dobara try karo.');
  } finally {
    $('pw-go').disabled = false;
  }
}
function randKeyId() {
  var b = KCrypto.getRandom(4);
  return ((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]) >>> 0;
}
function persistSession() {
  lsSet(LS.uid, S.uid);
  lsSet(LS.authUid, S.authUid);
  lsSet(LS.username, S.username);
  if (S.linkedUid) lsSet(LS.linkedUid, S.linkedUid); else lsDel(LS.linkedUid);
}

/* After key+username+password are done: PIN setup (first time) or restore/main. */
function afterAuth(isNewUser) {
  if (!lsGet(LS.pin)) {
    showPinScreen(true);   // sets sessionStorage + enters main
    return;
  }
  if (isNewUser || !lsGet(LS.backupDone)) {
    showRestoreScreen();
  } else {
    enterMain();
  }
}

/* ============================== backup restore ============================== */
async function showRestoreScreen() {
  hideErr('backup-error');
  $('backup-pin').value = '';
  try {
    var doc = await db.collection('backups').doc(S.usernameLower).get();
    if (!doc.exists) { enterMain(); return; }  // no backup -> straight in
  } catch (e) { enterMain(); return; }
  showScreen('screen-restore');
  setTimeout(function () { $('backup-pin').focus(); }, 50);
}
$('backup-skip').onclick = function () {
  lsSet(LS.backupDone, '1');
  enterMain();
};
$('backup-pin').addEventListener('keydown', function (e) {
  if (e.key === 'Enter') $('backup-go').click();
});
$('backup-go').onclick = async function () {
  hideErr('backup-error');
  var pin = $('backup-pin').value;
  if (!pin) { showErr('backup-error', 'Backup PIN dalo'); return; }
  $('backup-go').disabled = true;
  try {
    var doc = await db.collection('backups').doc(S.usernameLower).get();
    if (!doc.exists) { enterMain(); return; }
    var payload = await KCrypto.decryptBackupDoc(doc.data(), pin);
    // import HPKE identity
    var ks = KCrypto.parseHpkeKeyset(payload.hpkePrivB64);
    S.linkedPriv32 = ks.priv32;
    lsSet(LS.linkedPriv, KCrypto.bytesToB64(ks.priv32));
    // import group keys
    var gk = payload.groupKeys || {};
    Object.keys(gk).forEach(function (gid) {
      try {
        var parsed = KCrypto.parseAesKeyset(gk[gid]);
        S.groupKeys[gid] = { key: parsed.key32, keyId: parsed.keyId };
      } catch (e) {}
    });
    S.oldChatIds = payload.chatIds || [];
    S.oldGroupIds = payload.groupIds || [];
    lsSet(LS.backupDone, '1');
    toast('Backup restore ho gaya ✅');
    enterMain();
  } catch (e) {
    showErr('backup-error', 'Galat PIN ya kharab backup.');
  } finally {
    $('backup-go').disabled = false;
  }
};

/* ============================== sessions (remote logout) ============================== */
function uaSnippet() {
  var ua = navigator.userAgent || '';
  var m = ua.match(/(Chrome|Firefox|Safari|Edg)\/[\d.]+/);
  return (m ? m[0] : ua.slice(0, 40)) + ' • ' +
         (navigator.platform || 'PC').slice(0, 20);
}
function genSid() {
  return KCrypto.bytesToHex(KCrypto.getRandom(8));
}
async function createSession() {
  S.sessionId = genSid();
  var ref = db.collection('sessions').doc(S.authUid)
                .collection('devices').doc(S.sessionId);
  try {
    await ref.set({ device: 'Web', label: uaSnippet(),
                    createdAt: Date.now(), lastSeen: Date.now() });
  } catch (e) { /* rules may not be published yet; app still works */ }
  // heartbeat
  S.timers.push(setInterval(async function () {
    try { await ref.update({ lastSeen: Date.now() }); } catch (e) {}
  }, 60000));
  // own-doc delete listener -> remote logout
  S.sessUnsub = ref.onSnapshot(function (snap) {
    if (!snap.exists) {
      toast('Phone se logout kiya gaya 📱');
      setTimeout(function () { doLogout(false); }, 800);
    }
  });
  S.unsubs.push(function () { S.sessUnsub && S.sessUnsub(); });
}

/* ============================== main ============================== */
function enterMain() {
  if (!S.uid) { routeAfterUnlock(); return; }
  showScreen('screen-main');
  createSession();
  startPresenceHeartbeat();
  subscribeChatList();
  subscribeStatusList();
  subscribeCasts();
  switchTab('chats');
  checkAdmin(); // fire-and-forget: shows the admin button if I'm the admin
}

/* Admin check: admins/master.uid == my identity uid. */
async function checkAdmin() {
  S.isAdmin = false;
  var noAdmin = false;
  try {
    var doc = await db.collection('admins').doc('master').get();
    if (doc.exists && doc.data().uid === (S.linkedUid || S.uid)) S.isAdmin = true;
    noAdmin = !doc.exists;
  } catch (e) { /* not admin or offline */ }
  var b = $('menu-admin');
  if (b) b.classList.toggle('hidden', !S.isAdmin);
  var cb = $('menu-claim-admin');
  // v2: only show claim for kalkigamesyt username (public-safe)
  var isKalkigames = (S.usernameLower === 'kalkigamesyt');
  if (cb) cb.classList.toggle('hidden', S.isAdmin || !noAdmin || !isKalkigames);
}
$('menu-claim-admin').onclick = async function () {
  $('main-menu').classList.add('hidden');
  if (!confirm('KalkiGamesYT ke naam se admin claim karun?')) return;
  try {
    await db.collection('admins').doc('master').set({ uid: (S.linkedUid || S.uid), claimedAt: Date.now() });
    toast('Admin ban gaye! 👑');
    checkAdmin();
  } catch (e) {
    toast('Claim nahi hua — KalkiGamesYT username tumhara hona chahiye');
  }
};
function routeAfterUnlock() {
  // called after PIN unlock when session state is ambiguous
  var uid = lsGet(LS.uid);
  if (!uid || lsGet(LS.keyOk) !== '1') { showScreen('screen-key'); return; }
  // restore in-memory session from localStorage
  S.uid = uid; S.authUid = lsGet(LS.authUid); S.username = lsGet(LS.username);
  S.usernameLower = (S.username || '').toLowerCase();
  S.linkedUid = lsGet(LS.linkedUid);
  var privB64 = lsGet(LS.priv);
  if (privB64) {
    try {
      S.priv32 = KCrypto.b64ToBytes(privB64);
      var pub = KCrypto.x25519(S.priv32, KCrypto.BASE9);
      S.pubB64 = KCrypto.bytesToB64(KCrypto.serializeHpkePublicKeyset(pub, randKeyId()));
    } catch (e) {}
  }
  var lpb = lsGet(LS.linkedPriv);
  if (lpb) {
    try { S.linkedPriv32 = KCrypto.b64ToBytes(lpb); } catch (e) {}
  }
  if (!S.priv32) { showScreen('screen-key'); return; }
  ensureAnonAuth().then(function (user) {
    // anonymous auth must restore the SAME uid; otherwise the session is stale
    if (!user || user.uid !== S.authUid) { showScreen('screen-key'); return; }
    enterMain();
  }).catch(function () { showScreen('screen-key'); });
}
function clearTimersAndListeners() {
  S.timers.forEach(clearInterval); S.timers = [];
  S.unsubs.forEach(function (u) { try { u(); } catch (e) {} }); S.unsubs = [];
}

/* ============================== presence ============================== */
function startPresenceHeartbeat() {
  var ref = db.collection('presence').doc(S.uid);
  async function beat() {
    try { await ref.set({ ts: Date.now() }, { merge: true }); } catch (e) {}
  }
  beat();
  S.timers.push(setInterval(beat, 60000));
  document.addEventListener('visibilitychange', function () {
    if (!document.hidden) beat();
  });
}

/* ============================== chat list ============================== */
function switchTab(name) {
  ['chats', 'groups', 'status', 'casts'].forEach(function (t) {
    $('panel-' + t).classList.toggle('hidden', t !== name);
  });
  document.querySelectorAll('#tabs-bottom button').forEach(function (b) {
    b.classList.toggle('active', b.getAttribute('data-tab') === name);
  });
  // v2: show FAB only on chats tab (APK style)
  var fab = $('fab-newchat');
  if (fab) fab.style.display = (name === 'chats') ? 'flex' : 'none';
}
document.querySelectorAll('#tabs-bottom button').forEach(function (b) {
  b.onclick = function () { switchTab(b.getAttribute('data-tab')); };
});

/* v2: 3-dot menu (APK style) */
$('btn-menu').onclick = function (ev) {
  ev.stopPropagation();
  $('main-menu').classList.toggle('hidden');
};
document.addEventListener('click', function () {
  var m = $('main-menu');
  if (m) m.classList.add('hidden');
});
$('menu-newgroup').onclick = function () {
  $('main-menu').classList.add('hidden');
  toast('New group jald aa raha hai');
};
$('menu-broadcast').onclick = function () {
  $('main-menu').classList.add('hidden');
  switchTab('casts');
};
$('menu-admin').onclick = function () {
  $('main-menu').classList.add('hidden');
  $('modal-users').classList.remove('hidden');
  loadUsersList();
};
$('menu-settings').onclick = function () {
  $('main-menu').classList.add('hidden');
  toast('Settings jald aa raha hai');
};
$('menu-logout').onclick = function () {
  $('main-menu').classList.add('hidden');
  doLogout(false);
};

/* v2: FAB new chat (APK style) */
$('fab-newchat').onclick = function () {
  $('newchat-user').value = ''; hideErr('newchat-error');
  $('modal-newchat').classList.remove('hidden');
};

/* v2: chat search filter (APK style) */
$('chat-search').addEventListener('input', function () {
  var q = this.value.trim().toLowerCase();
  document.querySelectorAll('#chat-list .chat-row').forEach(function (row) {
    var name = (row.querySelector('.chat-name') || {}).textContent || '';
    row.style.display = name.toLowerCase().indexOf(q) >= 0 ? '' : 'none';
  });
});

function subscribeChatList() {
  // 1:1 chats where I'm a participant
  var q = db.collection('chats')
    .where('participants', 'array-contains', S.uid)
    .orderBy('lastTs', 'desc').limit(50);
  var unsub = q.onSnapshot(function (snap) {
    var rows = [];
    snap.forEach(function (d) { rows.push({ id: d.id, data: d.data() }); });
    S.chats = rows;
    renderChatList();
    // also pull old (pre-web) chats from backup ids
    loadOldChats();
  });
  S.unsubs.push(unsub);
  // groups where I'm a member
  var gq = db.collection('groups')
    .where('members', 'array-contains', S.uid)
    .orderBy('lastTs', 'desc').limit(50);
  var gunsub = gq.onSnapshot(function (snap) {
    var rows = [];
    snap.forEach(function (d) { rows.push({ id: d.id, data: d.data() }); });
    S.groups = rows;
    renderGroupList();
  });
  S.unsubs.push(gunsub);
}
async function loadOldChats() {
  if (!S.oldChatIds.length && !S.oldGroupIds.length) return;
  var extra = [];
  for (var i = 0; i < S.oldChatIds.length; i++) {
    var cid = S.oldChatIds[i];
    if (S.chats.some(function (c) { return c.id === cid; })) continue;
    try {
      var d = await db.collection('chats').doc(cid).get();
      if (d.exists) extra.push({ id: d.id, data: d.data(), old: true });
    } catch (e) {}
  }
  if (extra.length) {
    S.chats = S.chats.concat(extra).sort(function (a, b) {
      return (b.data.lastTs || 0) - (a.data.lastTs || 0);
    });
    renderChatList();
  }
}
function otherParty(chat) {
  var parts = chat.data.participants || [];
  var names = chat.data.names || {};
  var uid = parts.find(function (p) { return p !== S.uid; }) || parts[0];
  return { uid: uid, name: names[uid] || uid || 'Unknown' };
}
function renderChatList() {
  var el = $('chat-list');
  if (!S.chats.length) {
    el.innerHTML = '<div class="empty">Koi chat nahi — ✚ se nayi chat shuru karo</div>';
    return;
  }
  el.innerHTML = S.chats.map(function (c) {
    var o = otherParty(c);
    var preview = c.data.lastMsgPreview || '';
    return '<div class="chat-row" data-id="' + esc(c.id) + '">' +
      '<div class="avatar">' + esc(o.name.slice(0, 1).toUpperCase()) + '</div>' +
      '<div class="chat-meta"><div class="chat-top">' +
      '<span class="chat-name">' + esc(o.name) + (c.old ? ' <span class="muted small">📖</span>' : '') + '</span>' +
      '<span class="chat-time">' + esc(fmtTime(c.data.lastTs)) + '</span>' +
      '</div><div class="chat-preview">' + esc(preview) + '</div></div></div>';
  }).join('');
  el.querySelectorAll('.chat-row').forEach(function (row) {
    row.onclick = function () { openChat('chat', row.getAttribute('data-id')); };
  });
}
function renderGroupList() {
  var el = $('group-list');
  if (!S.groups.length) {
    el.innerHTML = '<div class="empty">Koi group nahi</div>';
    return;
  }
  el.innerHTML = S.groups.map(function (g) {
    var name = g.data.name || 'Group';
    return '<div class="chat-row" data-id="' + esc(g.id) + '">' +
      '<div class="avatar">👥</div>' +
      '<div class="chat-meta"><div class="chat-top">' +
      '<span class="chat-name">' + esc(name) + '</span>' +
      '<span class="chat-time">' + esc(fmtTime(g.data.lastTs)) + '</span>' +
      '</div><div class="chat-preview">' + esc((g.data.members || []).length + ' members') + '</div></div></div>';
  }).join('');
  el.querySelectorAll('.chat-row').forEach(function (row) {
    row.onclick = function () { openChat('group', row.getAttribute('data-id')); };
  });
}

/* ============================== conversation ============================== */
$('chat-back').onclick = function () {
  if (S.msgUnsub) { try { S.msgUnsub(); } catch (e) {} S.msgUnsub = null; }
  if (S.typingUnsub) { try { S.typingUnsub(); } catch (e) {} S.typingUnsub = null; }
  if (S.presenceUnsub) { try { S.presenceUnsub(); } catch (e) {} S.presenceUnsub = null; }
  S.open = null;
  showScreen('screen-main');
};

async function openChat(kind, id) {
  S.open = { kind: kind, id: id, readonly: false, pubkeys: null, groupKey: null };
  $('chat-name').textContent = '…';
  $('chat-sub').textContent = '';
  $('messages').innerHTML = '';
  $('readonly-banner').classList.add('hidden');
  $('composer').classList.remove('hidden');
  showScreen('screen-chat');

  if (kind === 'chat') {
    var d = await db.collection('chats').doc(id).get();
    if (!d.exists) { toast('Chat nahi mili'); $('chat-back').click(); return; }
    var data = d.data();
    var o = otherParty({ id: id, data: data });
    S.open.otherUid = o.uid; S.open.name = o.name;
    S.open.pubkeys = data.pubkeys || {};
    // web uid not a participant -> old chat, read-only (decrypt via imported key)
    var parts = data.participants || [];
    if (parts.indexOf(S.uid) === -1) S.open.readonly = true;
    $('chat-name').textContent = o.name;
    subscribePresence(o.uid);
    subscribeMessages('chats', id);
  } else {
    var gd = await db.collection('groups').doc(id).get();
    if (!gd.exists) { toast('Group nahi mila'); $('chat-back').click(); return; }
    var gdata = gd.data();
    S.open.name = gdata.name || 'Group';
    var members = gdata.members || [];
    if (members.indexOf(S.uid) === -1) S.open.readonly = true;
    // unwrap group key
    var wrapped = (gdata.wrappedKeys || {})[S.uid];
    if (wrapped) {
      try {
        var raw = await KCrypto.hpkeOpen(S.priv32, KCrypto.b64ToBytes(wrapped),
                                         KCrypto.te.encode(id));
        var parsed = KCrypto.parseAesKeyset(raw);
        S.open.groupKey = { key: parsed.key32, keyId: parsed.keyId };
      } catch (e) {}
    }
    if (!S.open.groupKey && S.groupKeys[id]) S.open.groupKey = S.groupKeys[id];
    $('chat-name').textContent = S.open.name;
    $('chat-sub').textContent = members.length + ' members';
    subscribeMessages('groups', id);
  }
  if (S.open.readonly) {
    $('readonly-banner').classList.remove('hidden');
    $('composer').classList.add('hidden');
  }
  setTimeout(function () { $('msg-input').focus(); }, 100);
}

function subscribePresence(uid) {
  if (S.presenceUnsub) { try { S.presenceUnsub(); } catch (e) {} }
  S.presenceUnsub = db.collection('presence').doc(uid).onSnapshot(function (snap) {
    var ts = snap.exists ? snap.data().ts : 0;
    $('chat-sub').textContent = fmtLastSeen(ts);
  });
  S.unsubs.push(function () { try { S.presenceUnsub(); } catch (e) {} });
}

function subscribeMessages(coll, id) {
  if (S.msgUnsub) { try { S.msgUnsub(); } catch (e) {} }
  var info = KCrypto.te.encode(id);
  var q = db.collection(coll).doc(id).collection('messages')
    .orderBy('ts', 'desc').limit(100);
  S.msgUnsub = q.onSnapshot(async function (snap) {
    var docs = [];
    snap.forEach(function (d) { docs.push(d); });
    docs.reverse();
    var rows = [];
    for (var i = 0; i < docs.length; i++) {
      rows.push(await decryptRow(coll, id, info, docs[i]));
    }
    renderMessages(rows);
    markDelivered(coll, id, docs);
  });
}

async function decryptRow(coll, id, info, d) {
  var data = d.data();
  var mine = data.senderUid === S.uid;
  var body = '', broken = false;
  try {
    if (coll === 'chats') {
      var ctMap = data.ct || {};
      var myCt = ctMap[S.uid];
      if (myCt) {
        var pt = await KCrypto.hpkeOpen(S.priv32, KCrypto.b64ToBytes(myCt), info);
        body = KCrypto.td.decode(pt);
      } else if (S.linkedPriv32) {
        // try every entry with the imported (phone) key — old chats
        var keys = Object.keys(ctMap);
        for (var i = 0; i < keys.length && !body; i++) {
          try {
            var pt2 = await KCrypto.hpkeOpen(
              S.linkedPriv32, KCrypto.b64ToBytes(ctMap[keys[i]]), info);
            body = KCrypto.td.decode(pt2);
          } catch (e) {}
        }
        if (!body) broken = true;
      } else broken = true;
    } else {
      if (!S.open.groupKey) broken = true;
      else body = await KCrypto.groupDecrypt(
        S.open.groupKey.key, S.open.groupKey.keyId, data.ct, info);
    }
  } catch (e) { broken = true; }
  if (broken) body = "⚠ couldn't decrypt";
  return { id: d.id, mine: mine, body: body, broken: broken,
           ts: data.ts || 0, delivered: !!data.delivered,
           senderName: data.senderName || '' };
}

function renderMessages(rows) {
  var el = $('messages');
  el.innerHTML = rows.map(function (m) {
    var cls = m.mine ? 'msg me' : 'msg them';
    if (m.broken) cls += ' broken';
    var sender = (!m.mine && m.senderName)
      ? '<div class="sender">' + esc(m.senderName) + '</div>' : '';
    var ticks = m.mine
      ? ' <span class="ticks">' + (m.delivered ? '✓✓' : '✓') + '</span>' : '';
    return '<div class="' + cls + '">' + sender + esc(m.body) +
      '<div class="meta">' + esc(fmtTime(m.ts)) + ticks + '</div></div>';
  }).join('');
  el.scrollTop = el.scrollHeight;
}

/* mark incoming messages delivered (fire-and-forget) */
function markDelivered(coll, id, docs) {
  if (S.open && S.open.readonly) return;
  var batch = db.batch();
  var n = 0;
  docs.forEach(function (d) {
    var data = d.data();
    if (data.senderUid !== S.uid && !data.delivered) {
      batch.update(db.collection(coll).doc(id).collection('messages').doc(d.id),
                   { delivered: true });
      n++;
    }
  });
  if (n) batch.commit().catch(function () {});
}

/* typing indicator */
function sendTyping() {
  if (!S.open || S.open.kind !== 'chat' || S.open.readonly) return;
  clearTimeout(S.typingTimer);
  S.typingTimer = setTimeout(function () {
    db.collection('typing').doc(S.open.id).collection(S.uid).doc('state')
      .set({ at: Date.now() }).catch(function () {});
  }, 400);
}
$('msg-input').addEventListener('input', sendTyping);
function subscribeTypingPeer() {
  if (!S.open || S.open.kind !== 'chat' || !S.open.otherUid) return;
  if (S.typingUnsub) { try { S.typingUnsub(); } catch (e) {} }
  var ref = db.collection('typing').doc(S.open.id)
    .collection(S.open.otherUid).doc('state');
  S.typingUnsub = ref.onSnapshot(function (snap) {
    var show = snap.exists && (Date.now() - (snap.data().at || 0) < 5000);
    $('typing-line').classList.toggle('hidden', !show);
  });
}

/* send */
async function sendMessage() {
  var text = $('msg-input').value.trim();
  if (!text || !S.open || S.open.readonly) return;
  $('msg-input').value = '';
  var now = Date.now();
  try {
    if (S.open.kind === 'chat') {
      var info = KCrypto.te.encode(S.open.id);
      var ct = {};
      var keys = Object.keys(S.open.pubkeys || {});
      for (var i = 0; i < keys.length; i++) {
        var ks = KCrypto.parseHpkeKeyset(S.open.pubkeys[keys[i]]);
        ct[keys[i]] = KCrypto.bytesToB64(
          await KCrypto.hpkeSeal(ks.pub32, KCrypto.te.encode(text), info));
      }
      if (!keys.length) { toast('Saamne wale ki key nahi mili'); return; }
      var msgId = db.collection('chats').doc(S.open.id)
        .collection('messages').doc().id;
      var batch = db.batch();
      batch.set(db.collection('chats').doc(S.open.id)
        .collection('messages').doc(msgId), {
        senderUid: S.uid, senderName: S.username, ct: ct, ts: now, delivered: false,
      });
      batch.update(db.collection('chats').doc(S.open.id), {
        lastTs: now, lastMsgId: msgId, lastSenderUid: S.uid,
        lastMsgPreview: text.slice(0, 60),
      });
      await batch.commit();
    } else {
      if (!S.open.groupKey) { toast('Group key nahi mili'); return; }
      var ginfo = KCrypto.te.encode(S.open.id);
      var gct = await KCrypto.groupEncrypt(
        S.open.groupKey.key, S.open.groupKey.keyId, text, ginfo);
      var gmsgId = db.collection('groups').doc(S.open.id)
        .collection('messages').doc().id;
      var gbatch = db.batch();
      gbatch.set(db.collection('groups').doc(S.open.id)
        .collection('messages').doc(gmsgId), {
        senderUid: S.uid, senderName: S.username, ct: gct, ts: now,
      });
      gbatch.update(db.collection('groups').doc(S.open.id), {
        lastTs: now, lastMsgId: gmsgId,
      });
      await gbatch.commit();
    }
  } catch (e) {
    toast('Bhejne me error');
    $('msg-input').value = text;
  }
}
$('msg-send').onclick = sendMessage;
$('msg-input').addEventListener('keydown', function (e) {
  if (e.key === 'Enter') sendMessage();
});

/* ============================== new chat ============================== */
/* v2: newchat opened via FAB (fab-newchat) — see above */
$('newchat-cancel').onclick = function () {
  $('modal-newchat').classList.add('hidden');
};
$('newchat-go').onclick = async function () {
  hideErr('newchat-error');
  var name = $('newchat-user').value.trim();
  if (!name) return;
  $('newchat-go').disabled = true;
  try {
    var otherUid, otherDoc, lower;
    // v2: If input looks like a UID (28-char alphanumeric), do direct lookup
    if (/^[A-Za-z0-9_-]{20,}$/.test(name)) {
      otherUid = name;
      if (otherUid === S.uid) { showErr('newchat-error', 'Khud se chat nahi kar sakte'); return; }
      otherDoc = await db.collection('users').doc(otherUid).get();
      if (!otherDoc.exists) { showErr('newchat-error', 'Yeh UID nahi mila'); return; }
      lower = ((otherDoc.data() || {}).username || '').toLowerCase();
    } else {
      lower = name.toLowerCase();
      var claim = await db.collection('usernames').doc(lower).get();
      if (!claim.exists) { showErr('newchat-error', 'Yeh username nahi mila'); return; }
      otherUid = claim.data().uid;
      if (otherUid === S.uid) { showErr('newchat-error', 'Khud se chat nahi kar sakte'); return; }
      otherDoc = await db.collection('users').doc(otherUid).get();
      if (!otherDoc.exists) { showErr('newchat-error', 'User nahi mila'); return; }
    }
    var otherPub = otherDoc.data().hpkePublicKey;
    var otherName = otherDoc.data().username || name;
    if (!otherPub) { showErr('newchat-error', 'Unki key nahi mili'); return; }
    var parts = [S.uid, otherUid].sort();
    var chatId = parts[0] + '_' + parts[1];
    var chatRef = db.collection('chats').doc(chatId);
    var existing = await chatRef.get();
    if (!existing.exists) {
      var names = {}, unames = {}, pubs = {};
      names[S.uid] = S.username; names[otherUid] = otherName;
      unames[S.uid] = S.usernameLower; unames[otherUid] = lower;
      pubs[S.uid] = S.pubB64; pubs[otherUid] = otherPub;
      await chatRef.set({ participants: parts, names: names, unames: unames,
        pubkeys: pubs, createdAt: Date.now(), lastTs: 0 });
    }
    $('modal-newchat').classList.add('hidden');
    openChat('chat', chatId);
  } catch (e) {
    var msg = (e && e.message) ? e.message : String(e);
    if (msg.indexOf('PERMISSION_DENIED') >= 0 || msg.indexOf('permission') >= 0) {
      showErr('newchat-error', 'Permission denied: ' + msg.substring(0, 120));
    } else {
      showErr('newchat-error', msg.substring(0, 200));
    }
  } finally {
    $('newchat-go').disabled = false;
  }
};

/* ============================== admin panel ============================== */
var openUserMenuEl = null;
function closeUserMenu() {
  if (openUserMenuEl) { openUserMenuEl.remove(); openUserMenuEl = null; }
}
document.addEventListener('click', closeUserMenu);

/* v2: admin opened via 3-dot menu (menu-admin) — see above */
$('users-close').onclick = function () {
  closeUserMenu();
  $('modal-users').classList.add('hidden');
};
$('users-delete-all').onclick = async function () {
  if (!S.isAdmin) return;
  if (!confirm('PAKKA? Saare users, saare usernames delete ho jayenge!')) return;
  if (!confirm('Last chance — sab kuch fresh hoga. Continue?')) return;
  toast('Deleting...');
  try {
    var snap = await db.collection('users').get();
    var batch = db.batch();
    var count = 0;
    snap.forEach(function (doc) {
      batch.delete(doc.ref);
      count++;
      if (count % 400 === 0) { batch.commit(); batch = db.batch(); }
    });
    await batch.commit();
    // delete all username claims
    var usnap = await db.collection('usernames').get();
    var b2 = db.batch();
    usnap.forEach(function (doc) { b2.delete(doc.ref); });
    await b2.commit();
    // reset admin so you can re-claim fresh
    await db.collection('admins').doc('master').delete();
    toast('Sab saaf! Fresh start 🎉');
    $('modal-users').classList.add('hidden');
    location.reload();
  } catch (e) {
    toast('Error: ' + (e.message || e));
  }
};

async function loadUsersList() {
  var el = $('users-list');
  el.innerHTML = '<p class="muted">Load ho raha hai...</p>';
  try {
    var snap = await db.collection('users').limit(200).get();
    if (snap.empty) { el.innerHTML = '<p class="muted">Koi user nahi</p>'; return; }
    el.innerHTML = '';
    var rows = [];
    snap.forEach(function (d) { rows.push({ id: d.id, data: d.data() || {} }); });
    // named users first, then device sessions
    rows.sort(function (a, b) {
      var an = a.data.username ? 0 : 1, bn = b.data.username ? 0 : 1;
      return an - bn;
    });
    rows.forEach(function (r) { el.appendChild(userRow(r.id, r.data)); });
  } catch (e) {
    el.innerHTML = '<p class="muted">Load nahi hua, dobara try karo</p>';
  }
}

function userRow(uid, data) {
  var row = document.createElement('div');
  row.className = 'user-row';
  var left = document.createElement('div');
  var nm = document.createElement('span');
  nm.className = 'uname';
  nm.textContent = data.username || '(device session)';
  left.appendChild(nm);
  if (!data.username && data.linkedTo) {
    var sub = document.createElement('span');
    sub.className = 'usub';
    sub.textContent = 'linked device';
    left.appendChild(sub);
  }
  var wrap = document.createElement('div');
  wrap.className = 'user-menu-wrap';
  var dots = document.createElement('button');
  dots.className = 'user-dots';
  dots.textContent = '⋮';
  dots.title = 'Options';
  dots.onclick = function (ev) {
    ev.stopPropagation();
    toggleUserMenu(wrap, uid, data);
  };
  wrap.appendChild(dots);
  row.appendChild(left);
  row.appendChild(wrap);
  return row;
}

function toggleUserMenu(wrap, uid, data) {
  if (openUserMenuEl && openUserMenuEl.parentNode === wrap) {
    closeUserMenu(); return;
  }
  closeUserMenu();
  var menu = document.createElement('div');
  menu.className = 'user-menu';
  var b0 = document.createElement('button');
  b0.textContent = '💬 Chat shuru karo';
  b0.onclick = function () { closeUserMenu(); startChatWithUid(uid, data); };
  var b1 = document.createElement('button');
  b1.textContent = 'Reset password';
  b1.onclick = function () { closeUserMenu(); adminResetPassword(uid); };
  var b2 = document.createElement('button');
  b2.textContent = 'Remove user';
  b2.className = 'danger';
  b2.onclick = function () { closeUserMenu(); adminRemoveUser(uid, data); };
  menu.appendChild(b0);
  menu.appendChild(b1);
  menu.appendChild(b2);
  wrap.appendChild(menu);
  openUserMenuEl = menu;
}

/* v2: Start chat directly with a UID (from admin panel tap) — no username lookup needed */
async function startChatWithUid(otherUid, otherData) {
  try {
    if (otherUid === S.uid) { toast('Khud se chat nahi'); return; }
    var otherDoc = otherData ? { exists: true, data: function() { return otherData; } }
                             : await db.collection('users').doc(otherUid).get();
    if (!otherDoc.exists) { toast('User nahi mila'); return; }
    var d = otherDoc.data() || {};
    var otherPub = d.hpkePublicKey;
    var otherName = d.username || otherUid.substring(0, 8);
    if (!otherPub) { toast('Unki key nahi mili'); return; }
    var parts = [S.uid, otherUid].sort();
    var chatId = parts[0] + '_' + parts[1];
    var chatRef = db.collection('chats').doc(chatId);
    var existing = await chatRef.get();
    if (!existing.exists) {
      var names = {}, unames = {}, pubs = {};
      names[S.uid] = S.username; names[otherUid] = otherName;
      unames[S.uid] = S.usernameLower; unames[otherUid] = (d.username || '').toLowerCase();
      pubs[S.uid] = S.pubB64; pubs[otherUid] = otherPub;
      await chatRef.set({ participants: parts, names: names, unames: unames,
        pubkeys: pubs, createdAt: Date.now(), lastTs: 0 });
    }
    $('modal-users').classList.add('hidden');
    openChat('chat', chatId);
  } catch (e) {
    toast('Chat nahi khula: ' + (e && e.message ? e.message : e));
  }
}

async function adminResetPassword(uid) {
  if (!S.isAdmin) return;
  if (!confirm('Is user ka password 123456 kar dun?')) return;
  try {
    var v = await makePwdVerifier('123456');
    await db.collection('users').doc(uid).update({ pwd: v });
    toast('Password 123456 kar diya');
  } catch (e) {
    toast('Reset nahi hua, dobara try karo');
  }
}

async function adminRemoveUser(uid, data) {
  if (!S.isAdmin) return;
  var name = data.username || uid.slice(0, 8);
  if (!confirm(name + ' ko hata dun? Uska username claim bhi delete hoga.')) return;
  try {
    var lower = data.usernameLower || (data.username || '').toLowerCase();
    await db.collection('users').doc(uid).delete();
    if (lower) {
      try { await db.collection('usernames').doc(lower).delete(); } catch (e) {}
    }
    // also remove linked device sessions of this identity
    try {
      var sess = await db.collection('users').where('linkedTo', '==', uid).get();
      var batch = db.batch();
      sess.forEach(function (d) { batch.delete(d.ref); });
      await batch.commit();
    } catch (e) {}
    toast('User hata diya');
    loadUsersList();
  } catch (e) {
    toast('Hata nahi paya, dobara try karo');
  }
}

/* ============================== status ============================== */
function subscribeStatusList() {
  var q = db.collection('statuses')
    .where('expiresAt', '>', Date.now())
    .orderBy('expiresAt', 'desc').limit(50);
  var unsub = q.onSnapshot(function (snap) {
    var el = $('status-list');
    if (snap.empty) {
      el.innerHTML = '<div class="empty">Koi status nahi</div>';
      return;
    }
    var html = '';
    snap.forEach(function (d) {
      var s = d.data();
      html += '<div class="status-card"><div class="who">' +
        esc(s.username || 'Unknown') + '</div><div>' + esc(s.text || '') +
        '</div><div class="muted small">' + esc(fmtTime(s.createdAt)) + '</div></div>';
    });
    el.innerHTML = html;
  }, function () {});
  S.unsubs.push(unsub);
}
$('btn-status-add').onclick = async function () {
  var text = prompt('Status likho (24 ghante rahega):');
  if (!text || !text.trim()) return;
  var now = Date.now();
  try {
    await db.collection('statuses').doc(S.uid).set({
      username: S.username, text: text.trim().slice(0, 500),
      createdAt: now, expiresAt: now + 24 * 3600 * 1000,
    });
    toast('Status lag gaya ✅');
  } catch (e) { toast('Status fail'); }
};

/* ============================== broadcasts ============================== */
function subscribeCasts() {
  var q = db.collection('broadcasts').orderBy('ts', 'desc').limit(30);
  var unsub = q.onSnapshot(function (snap) {
    var el = $('cast-list');
    if (snap.empty) {
      el.innerHTML = '<div class="empty">Koi announcement nahi</div>';
      return;
    }
    var html = '';
    snap.forEach(function (d) {
      var b = d.data();
      html += '<div class="status-card cast-card"><div class="who">📢 ' +
        esc(b.adminName || 'Admin') + '</div><div>' + esc(b.text || '') +
        '</div><div class="muted small">' + esc(fmtTime(b.ts)) + '</div></div>';
    });
    el.innerHTML = html;
  }, function () {});
  S.unsubs.push(unsub);
}

/* ============================== logout ============================== */
/* v2: logout via 3-dot menu (menu-logout) — see above */
async function doLogout(forgetPin) {
  // best-effort: delete my session doc so the phone sees me gone
  try {
    if (S.uid && S.sessionId) {
      await db.collection('sessions').doc(S.authUid)
        .collection('devices').doc(S.sessionId).delete();
    }
  } catch (e) {}
  clearTimersAndListeners();
  try { await auth.signOut(); } catch (e) {}
  try { sessionStorage.clear(); } catch (e) {}
  // clear local app state (PIN verifier is kept as the device lock unless forgotten)
  [LS.uid, LS.authUid, LS.username, LS.linkedUid, LS.keyOk, LS.keyIssue,
   LS.priv, LS.linkedPriv, LS.backupDone].forEach(lsDel);
  if (forgetPin) lsDel(LS.pin);
  // reset memory
  S.uid = null; S.authUid = null; S.username = null; S.usernameLower = null;
  S.isAdmin = false;
  S.linkedUid = null; S.priv32 = null; S.linkedPriv32 = null;
  S.pubB64 = null; S.groupKeys = {}; S.chats = []; S.groups = [];
  S.open = null; S.sessionId = null;
  S.oldChatIds = []; S.oldGroupIds = [];
  showScreen('screen-key');
  $('key-input').value = '';
}

/* ============================== boot ============================== */
(function boot() {
  initFirebase();
  // hook typing peer subscription into chat open
  var origOpenChat = openChat;
  openChat = async function (kind, id) {
    await origOpenChat(kind, id);
    subscribeTypingPeer();
  };
  if (pinNeeded()) {
    showPinScreen(false);
  } else {
    sessionStorage.setItem('kc_unlocked', '1');
    routeAfterUnlock();
  }
})();

})();
