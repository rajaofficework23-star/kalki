/* KalkiChat Web — crypto core (plain script, no modules; works from file:// and https).
 * Exposes window.KCrypto (also module.exports for Node testing).
 *
 * Implements, from source-reading of the Android app:
 *  - Key validation (KeyValidator.java): <password>-<24 HEX>, XOR-hidden issue
 *    timestamp, 30-day validity, clock-rollback guard (localStorage).
 *  - Tink HPKE (DHKEM_X25519_HKDF_SHA256 / HKDF_SHA256 / AES_256_GCM, NO_PREFIX)
 *    exactly per RFC 9180 base mode, matching Tink's Java implementation:
 *    ciphertext = enc(32B) || AES-GCM(key, base_nonce, aad="", pt).
 *  - Tink binary keyset protobuf parse/serialize (HpkePrivateKey/HpkePublicKey/AesGcmKey).
 *  - Group AES-256-GCM with Tink's 5-byte output prefix (0x01 || key_id).
 *  - v6 backup decrypt: PBKDF2-HMAC-SHA256 100k + AES-256-GCM, magic "KCBK1".
 */
(function (global) {
'use strict';

var te = new TextEncoder();
var td = new TextDecoder();

function concat() {
  var total = 0, i, a = arguments;
  for (i = 0; i < a.length; i++) total += a[i].length;
  var out = new Uint8Array(total), o = 0;
  for (i = 0; i < a.length; i++) { out.set(a[i], o); o += a[i].length; }
  return out;
}
function b64ToBytes(s) {
  var bin = atob(s.replace(/-/g, '+').replace(/_/g, '/'));
  var out = new Uint8Array(bin.length);
  for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function bytesToB64(b) {
  var s = '', i;
  for (i = 0; i < b.length; i += 0x8000) {
    s += String.fromCharCode.apply(null, b.subarray(i, i + 0x8000));
  }
  return btoa(s);
}
function hexToBytes(h) {
  var out = new Uint8Array(h.length / 2), i;
  for (i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
}
function bytesToHex(b) {
  var s = '', i;
  for (i = 0; i < b.length; i++) s += ('0' + b[i].toString(16)).slice(-2);
  return s.toUpperCase();
}
function leToBigInt(b) {
  var r = 0n;
  for (var i = b.length - 1; i >= 0; i--) r = (r << 8n) | BigInt(b[i]);
  return r;
}
function bigIntToLe(n, len) {
  var out = new Uint8Array(len);
  for (var i = 0; i < len; i++) { out[i] = Number(n & 0xffn); n >>= 8n; }
  return out;
}
function i2osp(n, len) {
  var out = new Uint8Array(len);
  for (var i = len - 1; i >= 0; i--) { out[i] = n & 0xff; n >>>= 8; }
  return out;
}
function getRandom(n) {
  var b = new Uint8Array(n);
  (global.crypto || {}).getRandomValues
    ? global.crypto.getRandomValues(b)
    : require('crypto').randomFillSync(b);
  return b;
}
function subtle() {
  if (global.crypto && global.crypto.subtle) return global.crypto.subtle;
  return require('crypto').webcrypto.subtle;
}

/* ---------------- X25519 (RFC 7748, Montgomery ladder, BigInt) ---------------- */
var P25519 = (1n << 255n) - 19n;
var A24_25519 = 121665n;
var BASE9 = new Uint8Array(32); BASE9[0] = 9;

function modP(a) { a %= P25519; return a < 0 ? a + P25519 : a; }
function modPow(base, exp) {
  var r = 1n, b = modP(base);
  while (exp > 0n) { if (exp & 1n) r = modP(r * b); b = modP(b * b); exp >>= 1n; }
  return r;
}
function x25519Clamp(k) {
  var t = new Uint8Array(k);
  t[0] &= 248; t[31] &= 127; t[31] |= 64;
  return t;
}
function x25519(priv, pub) {
  var k = leToBigInt(x25519Clamp(priv));
  var x1 = modP(leToBigInt(pub));
  var x2 = 1n, z2 = 0n, x3 = x1, z3 = 1n, swap = 0, t, kt;
  for (t = 254; t >= 0; t--) {
    kt = Number((k >> BigInt(t)) & 1n);
    swap ^= kt;
    if (swap) { var tx = x2; x2 = x3; x3 = tx; var tz = z2; z2 = z3; z3 = tz; }
    swap = kt;
    var A = modP(x2 + z2), AA = modP(A * A);
    var B = modP(x2 - z2), BB = modP(B * B);
    var E = modP(AA - BB);
    var C = modP(x3 + z3), D = modP(x3 - z3);
    var DA = modP(D * A), CB = modP(C * B);
    var dapcb = modP(DA + CB), damcb = modP(DA - CB);
    var x5 = modP(dapcb * dapcb);
    var z5 = modP(x1 * modP(damcb * damcb));
    var x4 = modP(AA * BB);
    var z4 = modP(E * modP(AA + A24_25519 * E));
    x2 = x4; z2 = z4; x3 = x5; z3 = z5;
  }
  return bigIntToLe(modP(x2 * modPow(z2, P25519 - 2n)), 32);
}

/* ---------------- HKDF / HPKE (RFC 9180 base mode, Tink-compatible) ---------------- */
var HPKE_V1 = te.encode('HPKE-v1');
/* Full HPKE suite id (key schedule): "HPKE" || kem || kdf || aead */
var SUITE_ID = concat(te.encode('HPKE'), new Uint8Array([0x00, 0x20, 0x00, 0x01, 0x00, 0x02]));
/* KEM-only suite id (DHKEM ExtractAndExpand): "KEM" || kem_id  (RFC 9180 s4.1) */
var KEM_SUITE_ID = concat(te.encode('KEM'), new Uint8Array([0x00, 0x20]));
var ZEROS32 = new Uint8Array(32);

async function hmacSha256(keyBytes, data) {
  var k = await subtle().importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await subtle().sign('HMAC', k, data));
}
/* RFC 5869 Extract (NOT WebCrypto HKDF-deriveBits, which always appends Expand) */
async function labeledExtract(salt, label, ikm, suiteId) {
  var s = (!salt || salt.length === 0) ? ZEROS32 : salt;
  var sid = suiteId || SUITE_ID;
  return hmacSha256(s, concat(HPKE_V1, sid, te.encode(label), ikm));
}
/* RFC 5869 Expand, manual HMAC loop (WebCrypto cannot do expand-only) */
async function labeledExpand(prk, label, info, L, suiteId) {
  var sid = suiteId || SUITE_ID;
  var labeledInfo = concat(i2osp(L, 2), HPKE_V1, sid, te.encode(label), info);
  var n = Math.ceil(L / 32), t = new Uint8Array(0), ok = new Uint8Array(0);
  for (var i = 1; i <= n; i++) {
    t = await hmacSha256(prk, concat(t, labeledInfo, new Uint8Array([i])));
    ok = concat(ok, t);
  }
  return ok.slice(0, L);
}
async function hpkeKeySchedule(dh, info, enc, pkR) {
  // Matches Tink's HpkeContext.createContext EXACTLY (tink-java v1.18.0 source).
  // NOTE: Tink deviates from RFC 9180 here: its key_schedule_context does NOT
  // include kem_context (the KEM already bound enc||pkR into shared_secret via
  // ExtractAndExpand). keyScheduleContext = mode || psk_id_hash || info_hash.
  var kemContext = concat(enc, pkR);
  var eaePrk = await labeledExtract(null, 'eae_prk', dh, KEM_SUITE_ID);
  var sharedSecret = await labeledExpand(eaePrk, 'shared_secret', kemContext, 32, KEM_SUITE_ID);
  var pskIdHash = await labeledExtract(null, 'psk_id_hash', new Uint8Array(0));
  var infoHash = await labeledExtract(null, 'info_hash', info);
  var ksCtx = concat(new Uint8Array([0x00]), pskIdHash, infoHash);
  var secret = await labeledExtract(sharedSecret, 'secret', new Uint8Array(0));
  var key = await labeledExpand(secret, 'key', ksCtx, 32);
  var baseNonce = await labeledExpand(secret, 'base_nonce', ksCtx, 12);
  return { key: key, baseNonce: baseNonce };
}
async function aesGcmEncryptRaw(key, iv, aad, pt) {
  var k = await subtle().importKey('raw', key, { name: 'AES-GCM' }, false, ['encrypt']);
  var ct = await subtle().encrypt({ name: 'AES-GCM', iv: iv, additionalData: aad }, k, pt);
  return new Uint8Array(ct);
}
async function aesGcmDecryptRaw(key, iv, aad, data) {
  var k = await subtle().importKey('raw', key, { name: 'AES-GCM' }, false, ['decrypt']);
  var pt = await subtle().decrypt({ name: 'AES-GCM', iv: iv, additionalData: aad }, k, data);
  return new Uint8Array(pt);
}

/** HPKE seal for Tink NO_PREFIX keys. Returns enc(32) || ct. info = chatId/groupId UTF-8. */
async function hpkeSeal(recipientPub32, plaintext, info) {
  var eph = getRandom(32);
  var enc = x25519(eph, BASE9);
  var shared = x25519(eph, recipientPub32);
  var ks = await hpkeKeySchedule(shared, info, enc, recipientPub32);
  var ct = await aesGcmEncryptRaw(ks.key, ks.baseNonce, new Uint8Array(0), plaintext);
  return concat(enc, ct);
}
/** HPKE open. priv32 = our X25519 private key. data = enc || ct. */
async function hpkeOpen(priv32, data, info) {
  var enc = data.slice(0, 32), ct = data.slice(32);
  var pkR = x25519(priv32, BASE9);
  var shared = x25519(priv32, enc);
  var ks = await hpkeKeySchedule(shared, info, enc, pkR);
  return aesGcmDecryptRaw(ks.key, ks.baseNonce, new Uint8Array(0), ct);
}

/* ---------------- minimal protobuf codec (Tink binary keysets) ---------------- */
function pbReadVarint(u8, pos) {
  var r = 0, shift = 0, b;
  do { b = u8[pos++]; r |= (b & 0x7f) << shift; shift += 7; } while (b & 0x80);
  return { value: r, pos: pos };
}
/* returns [{field, wire, data(Uint8Array)|value(number)}] */
function pbFields(u8) {
  var out = [], pos = 0;
  while (pos < u8.length) {
    var tag = pbReadVarint(u8, pos); pos = tag.pos;
    var field = tag.value >>> 3, wire = tag.value & 7, f = { field: field, wire: wire };
    if (wire === 0) { var v = pbReadVarint(u8, pos); f.value = v.value; pos = v.pos; }
    else if (wire === 2) {
      var l = pbReadVarint(u8, pos); pos = l.pos;
      f.data = u8.slice(pos, pos + l.value); pos += l.value;
    } else throw new Error('unsupported wire ' + wire);
    out.push(f);
  }
  return out;
}
function pbGet(fields, n) {
  for (var i = 0; i < fields.length; i++) if (fields[i].field === n) return fields[i];
  return null;
}
function pbVarint(n) {
  var out = [];
  do { var b = n & 0x7f; n >>>= 7; out.push(n ? b | 0x80 : b); } while (n);
  return new Uint8Array(out);
}
function pbLen(field, bytes) { return concat(pbVarint((field << 3) | 2), pbVarint(bytes.length), bytes); }
function pbInt(field, n) { return concat(pbVarint(field << 3), pbVarint(n)); }

/* Parse a base64 Tink keyset -> {keyId, priv32?, pub32?} (HPKE).
 * Handles both HpkePrivateKey (field 2 = nested public key, field 3 = private key)
 * and HpkePublicKey (field 3 = public key) keysets, distinguished by type_url. */
function parseHpkeKeyset(b64) {
  var ks = pbFields(b64ToBytes(b64));
  var keyF = pbGet(ks, 2);
  if (!keyF) throw new Error('no key in keyset');
  var key = pbFields(keyF.data);
  var keyId = pbGet(key, 3).value;
  var kd = pbFields(pbGet(key, 1).data);
  var typeUrl = td.decode(pbGet(kd, 1).data);
  var val = pbFields(pbGet(kd, 2).data);
  var out = { keyId: keyId >>> 0 };
  if (typeUrl.indexOf('HpkePrivateKey') !== -1) {
    var pubF = pbGet(val, 2);
    if (pubF) out.pub32 = pbGet(pbFields(pubF.data), 3).data;
    var privF = pbGet(val, 3);
    if (privF) out.priv32 = privF.data;
  } else {
    // HpkePublicKey: field 3 IS the public key
    var pubOnly = pbGet(val, 3);
    if (pubOnly) out.pub32 = pubOnly.data;
  }
  if (!out.pub32 && out.priv32) out.pub32 = x25519(out.priv32, BASE9);
  if (!out.pub32) throw new Error('no public key in keyset');
  return out;
}
/* Parse a base64 Tink AES-GCM keyset -> {keyId, key32} */
function parseAesKeyset(b64) {
  var ks = pbFields(b64ToBytes(b64));
  var key = pbFields(pbGet(ks, 2).data);
  var keyId = pbGet(key, 3).value;
  var kd = pbFields(pbGet(key, 1).data);
  var aes = pbFields(pbGet(kd, 2).data);
  return { keyId: keyId >>> 0, key32: pbGet(aes, 2).data };
}
/* Serialize a Tink public HPKE keyset (for users/{uid}.hpkePublicKey) */
/* HpkeParams for (X25519, HKDF-SHA256, AES-256-GCM): kem=1, kdf=1, aead=2.
 * (Tink's enums use small values, NOT the HPKE wire ids. Verified vs real Tink.) */
var HPKE_PARAMS_B = hexToBytes('080110011802');
function serializeHpkePublicKeyset(pub32, keyId) {
  var pubKey = concat(pbInt(1, 0), pbLen(2, HPKE_PARAMS_B), pbLen(3, pub32));
  var kd = concat(pbLen(1, te.encode('type.googleapis.com/google.crypto.tink.HpkePublicKey')),
                  pbLen(2, pubKey), pbInt(3, 2)); // ASYMMETRIC_PUBLIC
  var key = concat(pbLen(1, kd), pbInt(2, 1), pbInt(3, keyId), pbInt(4, 3)); // ENABLED, RAW
  return concat(pbInt(1, keyId), pbLen(2, key));
}
/* Serialize a Tink AES-GCM keyset (for wrapping group keys, phone-compatible) */
function serializeAesKeyset(keyId, key32) {
  var aes = concat(pbInt(1, 0), pbLen(2, key32)); // AesGcmKey{version:0, key_value}
  var kd = concat(pbLen(1, te.encode('type.googleapis.com/google.crypto.tink.AesGcmKey')),
                  pbLen(2, aes), pbInt(3, 0)); // SYMMETRIC
  var key = concat(pbLen(1, kd), pbInt(2, 1), pbInt(3, keyId), pbInt(4, 1)); // ENABLED, TINK
  return concat(pbInt(1, keyId), pbLen(2, key));
}
/* Tink 5-byte output prefix for TINK keys: 0x01 || key_id big-endian */
function tinkPrefix(keyId) {
  return concat(new Uint8Array([0x01]), i2osp(keyId, 4));
}

/* Group message decrypt: ct = prefix(5) || iv(12) || ct||tag, aad = groupId bytes */
async function groupDecrypt(key32, keyId, ctB64, aad) {
  var raw = b64ToBytes(ctB64);
  if (raw.length < 5 + 12 + 16 || raw[0] !== 0x01) throw new Error('bad group ct');
  var iv = raw.slice(5, 17), data = raw.slice(17);
  var pt = await aesGcmDecryptRaw(key32, iv, aad, data);
  return td.decode(pt);
}
/* Group message encrypt (phone-compatible wire format) */
async function groupEncrypt(key32, keyId, plaintext, aad) {
  var iv = getRandom(12);
  var ct = await aesGcmEncryptRaw(key32, iv, aad, te.encode(plaintext));
  return bytesToB64(concat(tinkPrefix(keyId), iv, ct));
}

/* ---------------- PBKDF2 (backup PIN) ---------------- */
async function pbkdf2(pw, salt, iters, len) {
  var pwBytes = (typeof pw === 'string') ? te.encode(pw) : pw;
  var km = await subtle().importKey('raw', pwBytes, 'PBKDF2', false, ['deriveBits']);
  var bits = await subtle().deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: salt, iterations: iters },
    km, (len || 32) * 8);
  return new Uint8Array(bits);
}

/* ---------------- key validation (JS port of KeyValidator.java) ---------------- */
var SECRET_OBF = [0x9B, 0x31, 0x1A, 0x7C, 0x72, 0x00, 0xDA, 0x63,
                  0x87, 0xF0, 0x40, 0x41, 0x0C, 0xE2, 0x2D, 0xDD];
var KEY_PASSWORD = 'kalki';
var VALIDITY_MS = 30 * 24 * 3600 * 1000;
var WRONG_KEY_MSG = 'wrong key please contact admin on telegram. For more details Dm :- @KaIkiGamesYT';

function deobfSecret() {
  return SECRET_OBF.map(function (b) { return b ^ 0x5A; });
}
function keyIssueMillis(key) {
  try {
    key = String(key).trim();
    var dash = key.lastIndexOf('-');
    if (dash <= 0) return -1;
    var pw = key.slice(0, dash), hex = key.slice(dash + 1);
    if (pw !== KEY_PASSWORD || hex.length !== 24 || !/^[0-9a-fA-F]{24}$/.test(hex)) return -1;
    var ct = hexToBytes(hex), s = deobfSecret(), pt = new Uint8Array(12), i;
    for (i = 0; i < 12; i++) pt[i] = ct[i] ^ s[i % 16];
    var ms = 0;
    for (i = 0; i < 8; i++) ms = ms * 256 + pt[i];
    return ms;
  } catch (e) { return -1; }
}
function getStore() {
  try { return global.localStorage; } catch (e) { return null; }
}
function validateKey(key) {
  var issue = keyIssueMillis(key);
  if (issue <= 0) return { ok: false };
  var now = Date.now();
  if (issue > now || now - issue > VALIDITY_MS) return { ok: false };
  var st = getStore(), lastSeen = 0;
  if (st) {
    lastSeen = parseInt(st.getItem('kc_last_seen') || '0', 10) || 0;
    if (now < lastSeen) return { ok: false }; // clock rolled back
    st.setItem('kc_last_seen', String(Math.max(lastSeen, now)));
  }
  return { ok: true, issueMillis: issue };
}
function keyDaysLeft(key) {
  var issue = keyIssueMillis(key);
  if (issue <= 0) return -1;
  return Math.floor((VALIDITY_MS - (Date.now() - issue)) / (24 * 3600 * 1000));
}

/* ---------------- backup decrypt (v6 format) ---------------- */
async function decryptBackupDoc(doc, pin) {
  // doc = {saltB64, ivB64, blobB64}
  var salt = b64ToBytes(doc.saltB64), iv = b64ToBytes(doc.ivB64), ct = b64ToBytes(doc.blobB64);
  var key = await pbkdf2(pin, salt, 100000);
  var pt;
  try { pt = await aesGcmDecryptRaw(key, iv, new Uint8Array(0), ct); }
  catch (e) { throw new Error('wrong_pin'); }
  var payload = JSON.parse(td.decode(pt));
  if (payload.magic !== 'KCBK1') throw new Error('wrong_pin');
  return payload;
}

var KCrypto = {
  concat: concat, b64ToBytes: b64ToBytes, bytesToB64: bytesToB64,
  hexToBytes: hexToBytes, bytesToHex: bytesToHex,
  x25519: x25519, BASE9: BASE9, x25519Clamp: x25519Clamp,
  hpkeSeal: hpkeSeal, hpkeOpen: hpkeOpen,
  parseHpkeKeyset: parseHpkeKeyset, parseAesKeyset: parseAesKeyset,
  serializeHpkePublicKeyset: serializeHpkePublicKeyset, serializeAesKeyset: serializeAesKeyset,
  tinkPrefix: tinkPrefix, groupDecrypt: groupDecrypt, groupEncrypt: groupEncrypt,
  aesGcmEncryptRaw: aesGcmEncryptRaw, aesGcmDecryptRaw: aesGcmDecryptRaw,
  pbkdf2: pbkdf2, getRandom: getRandom,
  _labeledExtract: labeledExtract, _labeledExpand: labeledExpand,
  _KEM_SUITE_ID: KEM_SUITE_ID, _SUITE_ID: SUITE_ID,
  validateKey: validateKey, keyIssueMillis: keyIssueMillis, keyDaysLeft: keyDaysLeft,
  WRONG_KEY_MSG: WRONG_KEY_MSG, KEY_PASSWORD: KEY_PASSWORD,
  decryptBackupDoc: decryptBackupDoc,
  te: te, td: td
};
global.KCrypto = KCrypto;
if (typeof module !== 'undefined' && module.exports) module.exports = KCrypto;
})(typeof window !== 'undefined' ? window : globalThis);
