'use strict';
/* 55-MAKTAB SARDORLARI — server qismi (Vercel Serverless Function + Upstash Redis) */
const crypto = require('crypto');

const KV_URL = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
const KV_TOKEN = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;

const OWNER_U = '55_aqwer_122a';
const OWNER_SALT = '782754b582b3c2f6308ca31d99ce7021';
const OWNER_HASH = '0b83cfc32406214319e37c6207cf5f636e21090bd1940473538dd6d3896fe101';
const TOKEN_TTL = 12 * 3600 * 1000;

const hasOwn = (o, k) => Object.prototype.hasOwnProperty.call(o || {}, k);
const secret = () => process.env.AUTH_SECRET || crypto.createHash('sha256').update('m55|' + KV_TOKEN).digest();

async function kv(...cmd) {
  const r = await fetch(KV_URL, {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + KV_TOKEN, 'Content-Type': 'application/json' },
    body: JSON.stringify(cmd)
  });
  const j = await r.json();
  if (j.error) throw new Error(j.error);
  return j.result;
}

function sign(p) {
  const body = Buffer.from(JSON.stringify(p)).toString('base64url');
  const mac = crypto.createHmac('sha256', secret()).update(body).digest('base64url');
  return body + '.' + mac;
}
function verify(t) {
  if (typeof t !== 'string') return null;
  const parts = t.split('.');
  if (parts.length !== 2) return null;
  const exp = crypto.createHmac('sha256', secret()).update(parts[0]).digest('base64url');
  const a = Buffer.from(parts[1]), b = Buffer.from(exp);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  let p;
  try { p = JSON.parse(Buffer.from(parts[0], 'base64url').toString()); } catch (e) { return null; }
  if (!p || !p.exp || p.exp < Date.now()) return null;
  return p;
}
const pbk = (pw, saltHex) => crypto.pbkdf2Sync(String(pw), Buffer.from(String(saltHex || ''), 'hex'), 150000, 32, 'sha256').toString('hex');
const eq = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };

async function getDoc(p) { const v = await kv('GET', 'm55:d:' + p); return v ? JSON.parse(v) : null; }
async function setDoc(p, data) { await kv('SET', 'm55:d:' + p, JSON.stringify(data)); await kv('INCR', 'm55:ver'); }
async function getCol(c) {
  const keys = await kv('KEYS', 'm55:d:' + c + '/*');
  if (!keys || !keys.length) return [];
  const vals = await kv('MGET', ...keys);
  return keys.map((k, i) => ({ id: k.slice(('m55:d:' + c + '/').length), data: vals[i] ? JSON.parse(vals[i]) : null })).filter(x => x.data);
}

const okDocRead = (p, tok) => p === 'ws/meta' || /^att\/[^\/]{1,80}$/.test(p) || (p === 'ws/cred' && tok.o);

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') return res.status(405).json({ ok: false, err: 'method' });
  if (!KV_URL || !KV_TOKEN) return res.status(500).json({ ok: false, err: 'nodb' });
  let b = req.body;
  if (typeof b === 'string') { try { b = JSON.parse(b); } catch (e) { b = {}; } }
  b = b || {};
  try {
    switch (b.a) {
      case 'login': {
        const u = String(b.u || '').trim().toLowerCase().slice(0, 60);
        const p = String(b.p || '').slice(0, 200);
        const ip = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() || 'x';
        const rk = 'm55:rl:' + ip;
        const n = await kv('INCR', rk);
        if (n === 1) await kv('EXPIRE', rk, 900);
        if (n > 20) return res.status(429).json({ ok: false, err: 'rate' });
        if (u === OWNER_U) {
          if (eq(pbk(p, OWNER_SALT), OWNER_HASH)) {
            await kv('DEL', rk);
            return res.json({ ok: true, owner: true, token: sign({ u: 'owner', o: 1, m: 0, exp: Date.now() + TOKEN_TTL }) });
          }
          return res.status(401).json({ ok: false, err: 'bad' });
        }
        const cred = (await getDoc('ws/cred')) || {};
        const c = /^[a-z0-9._-]{3,30}$/.test(u) && hasOwn(cred.users, u) ? cred.users[u] : null;
        const h = pbk(p, c ? c.salt : '00'.repeat(16));
        if (!c || !eq(h, c.hash)) return res.status(401).json({ ok: false, err: 'bad' });
        const meta = await getDoc('ws/meta');
        if (c.active === false || (meta && meta.blocked && meta.blocked[u])) return res.status(403).json({ ok: false, err: 'blocked' });
        await kv('DEL', rk);
        return res.json({ ok: true, owner: false, must: !!c.must, token: sign({ u, o: 0, m: c.must ? 1 : 0, exp: Date.now() + TOKEN_TTL }) });
      }
      case 'changepw': {
        const tok = verify(b.t);
        if (!tok || tok.o) return res.status(401).json({ ok: false, err: 'auth' });
        const np = String(b.np || '');
        if (np.length < 8 || np.length > 200) return res.status(400).json({ ok: false, err: 'short' });
        const cred = (await getDoc('ws/cred')) || { users: {} };
        if (!hasOwn(cred.users, tok.u)) return res.status(403).json({ ok: false, err: 'bad' });
        const salt = crypto.randomBytes(16).toString('hex');
        cred.users[tok.u] = Object.assign({}, cred.users[tok.u], { salt, hash: pbk(np, salt), must: false });
        await setDoc('ws/cred', cred);
        return res.json({ ok: true, token: sign({ u: tok.u, o: 0, m: 0, exp: Date.now() + TOKEN_TTL }) });
      }
      case 'poll': {
        const tok = verify(b.t);
        if (!tok || tok.m) return res.status(401).json({ ok: false, err: 'auth' });
        const ver = String((await kv('GET', 'm55:ver')) || '0');
        if (String(b.v) === ver) return res.json({ ok: true, same: true, v: ver });
        const items = Array.isArray(b.items) ? b.items.slice(0, 10) : [];
        const out = [];
        for (const it of items) {
          if (it && it.k === 'd' && typeof it.p === 'string' && okDocRead(it.p, tok)) {
            const d = await getDoc(it.p);
            out.push({ exists: d !== null, data: d });
          } else if (it && it.k === 'c' && it.c === 'att') {
            out.push({ docs: await getCol('att') });
          } else out.push({ exists: false, denied: true });
        }
        return res.json({ ok: true, v: ver, res: out });
      }
      case 'set': {
        const tok = verify(b.t);
        if (!tok || tok.m) return res.status(401).json({ ok: false, err: 'auth' });
        const p = String(b.p || '');
        const data = b.data;
        if (!data || typeof data !== 'object' || Array.isArray(data)) return res.status(400).json({ ok: false, err: 'data' });
        if (JSON.stringify(data).length > 900000) return res.status(413).json({ ok: false, err: 'big' });
        if (p === 'ws/cred') {
          if (!tok.o) return res.status(403).json({ ok: false, err: 'forbidden' });
        } else if (p === 'ws/meta') {
          if (!tok.o) {
            const cur = (await getDoc('ws/meta')) || {};
            for (const k of ['roles', 'blocked', 'perm']) { if (hasOwn(cur, k)) data[k] = cur[k]; else delete data[k]; }
          }
        } else if (!/^att\/[^\/]{1,80}$/.test(p)) {
          return res.status(403).json({ ok: false, err: 'forbidden' });
        }
        await setDoc(p, data);
        return res.json({ ok: true });
      }
      default:
        return res.status(400).json({ ok: false, err: 'action' });
    }
  } catch (e) {
    return res.status(500).json({ ok: false, err: 'server', msg: String((e && e.message) || e) });
  }
};
