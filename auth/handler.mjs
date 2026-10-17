// auth: the panel's small sign-in service — GitHub's OAuth web flow for the lab's GitHub App, done where the App's client
// secret can live (a Cloudflare Worker: worker.mjs; or your own server behind TLS: node.mjs), and nothing more. It keeps no
// store: a sign-in rides in two signed values — a random k in an HttpOnly cookie of this origin alone, and the `state`
// GitHub carries back (where it returns, k's keyed hash, when) — and the tokens are handed to the panel once, after the # of
// its address (never in a query: the # reaches no server, no log, no Referer). The panel then talks to GitHub itself with the person's own user token: what it may
// see and do is what GitHub gives that person through the App installed on the lab's repositories — this service adds no
// power and holds no token. Runs as it is on Node 22, in a browser and on Workers: fetch, Request, Response, URL,
// crypto.subtle, TextEncoder (and btoa/atob) only.
//   GET /health                          → { ok, clientId, origins, panels, version } (CORS to the panel's origins)
//   GET /login?return=<panel>&select=1&login=<name>   → 302 to GitHub (k in the cookie, the state in the URL; both signed)
//   GET /callback?code&state             → 302 to <panel>#bdslab-auth=<base64url(JSON tokens)> (or #bdslab-auth-error=<word>)
//   POST /refresh {refresh_token}        → the renewed tokens (from the panel's origins only)
//   POST /logout {access_token}          → 204 (the token revoked on GitHub; from the panel's origins only)
// and the sign-in of AI clients to the lab's API (api.mjs: MCP at /mcp, plain HTTP at /api) — an OAuth 2.1 authorization
// server as MCP asks for one, stateless like the rest: a client registered dynamically is a signed value (its redirect
// addresses in it), the code and the tokens are sealed values (AES-GCM, a key made from STATE_SECRET) that hold the
// person's GitHub tokens, and the person signs in through the same GitHub App sign-in — after saying yes, on this service's
// own page, to that client by name and the address it returns to (one GitHub client id serving every client: MCP's rule
// against the confused deputy). The person's power is still GitHub's alone: the API acts with their user token.
//   GET /.well-known/oauth-protected-resource[/mcp], GET /.well-known/oauth-authorization-server   → the metadata
//   POST /register {redirect_uris, client_name, token_endpoint_auth_method}  → 201 { client_id, … } (RFC 7591)
//   GET /authorize?response_type=code&client_id&redirect_uri&state&code_challenge(S256)  → the consent page
//   POST /authorize (the page's form: its signed request and a CSRF value bound to a cookie) → 302 to GitHub
//   GET /callback (the state says MCP)    → 302 to <redirect_uri>?code=<sealed>&state&iss
//   POST /token grant_type=authorization_code (PKCE) | refresh_token | device_code  → { access_token, refresh_token, expires_in }
// and, for an AI with no browser of its own (a CLI, a script, a chat in a sandbox), the device sign-in (RFC 8628) — the one
// part that needs a short-lived store (store: a Durable Object on Cloudflare, memory on node.mjs; none: not offered):
//   POST /device/code {client_name}       → { device_code, user_code, verification_uri(_complete), interval, client_id }
//   GET /device?code=XXXX-XXXX → the consent page (the code to compare) → POST /device → GitHub → /callback → 「つながりました」
//   POST /token grant_type=urn:ietf:params:oauth:grant-type:device_code → authorization_pending … then the tokens, once
// and the end of it, for any AI client: POST /revoke token=<access or refresh token> (RFC 7009) → 200, the GitHub token gone
export const VERSION = '4';
/** what only the real GitHub can confirm (kept in this one place; the tests use a fake GitHub) */
export const GITHUB = {
  // (GitHub's OAuth web flow takes PKCE: code_challenge S256 at /authorize, code_verifier at /access_token — 要実測)
  pkce: true,
  // (prompt=select_account: GitHub shows its account picker, for a second account in one browser — 要実測)
  selectAccount: 'select_account',
  authorize: '/login/oauth/authorize',
  token: '/login/oauth/access_token',
  revoke: (clientId) => `/applications/${encodeURIComponent(clientId)}/token`,
  apiVersion: '2022-11-28',
};
const COOKIE = '__Host-bdslab_state', TTL = 600_000, UA = `bds-lab-auth/${VERSION}`;
const LOGIN = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/, TOKEN = /^[\x21-\x7e]{1,2048}$/;
/** on every answer: nothing cached, no Referer, no sniffing, nothing framed or loaded */
export const HEADERS = { 'cache-control': 'no-store', 'referrer-policy': 'no-referrer', 'x-content-type-options': 'nosniff', 'content-security-policy': "default-src 'none'; frame-ancestors 'none'" };
const enc = new TextEncoder(), dec = new TextDecoder();
const b64url = (bytes) => { const b = new Uint8Array(bytes); let s = ''; for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode(...b.subarray(i, i + 0x8000)); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); };
const unb64url = (s) => Uint8Array.from(atob(String(s).replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (String(s).length % 4)) % 4)), (c) => c.charCodeAt(0));
const reply = (status, body, extra = {}) => new Response(body === null ? null : JSON.stringify(body), { status, headers: { ...HEADERS, ...(body === null ? {} : { 'content-type': 'application/json; charset=utf-8' }), ...extra } });

// (a path written escaped — a dot, a slash, a backslash — may be read as another place by the server behind it)
const ESCAPED = /%(2e|2f|5c)/i;
/** a panel as written in PANEL_ORIGINS → { origin, path, href }, or null (pure): https, or http on this machine only. The path
 *  is the head of the panel's addresses, ending in / (GitHub Pages: /<repository>/ — the owner's other repositories share
 *  the origin); none: the whole origin (a domain of the panel's own) */
function panelOf(s) {
  let u; try { u = new URL(s); } catch { return null; }
  const local = /^(localhost|127\.0\.0\.1|\[::1\])$/.test(u.hostname);
  if (!(u.protocol === 'https:' || (u.protocol === 'http:' && local)) || u.search || u.hash || u.username || u.password || ESCAPED.test(u.pathname)) return null;
  const path = u.pathname.endsWith('/') ? u.pathname : `${u.pathname}/`;
  return { origin: u.origin, path, href: `${u.origin}${path}` };
}
/** env → the service's settings (pure): what is missing is named (never a value) */
export function config(env = {}) {
  const base = (v, d) => String(v ?? '').trim().replace(/\/+$/, '') || d;
  const panels = [...new Map(String(env.PANEL_ORIGINS ?? '').split(',').map((s) => s.trim()).filter(Boolean).map(panelOf).filter(Boolean).map((p) => [p.href, p])).values()];
  // (origins: for CORS — a browser's Origin header carries no path; panels: where a sign-in may return)
  const origins = [...new Set(panels.map((p) => p.origin))];
  const c = { clientId: String(env.GITHUB_CLIENT_ID ?? '').trim(), secret: String(env.GITHUB_CLIENT_SECRET ?? '').trim(), stateSecret: String(env.STATE_SECRET ?? ''), origins, panels, web: base(env.GITHUB_WEB, 'https://github.com'), api: base(env.GITHUB_API, 'https://api.github.com') };
  c.missing = [!c.clientId && 'GITHUB_CLIENT_ID', !c.secret && 'GITHUB_CLIENT_SECRET', c.stateSecret.length < 32 && 'STATE_SECRET', !origins.length && 'PANEL_ORIGINS'].filter(Boolean);
  // (the lab the API acts on — auth-deploy.yml sets it; without it the sign-in still works, the API says it has no lab)
  const lab = String(env.LAB_SLUG ?? '').trim();
  c.lab = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})\/[A-Za-z0-9._-]{1,100}$/.test(lab) ? lab : null;
  return c;
}

const SEALED = { code: 'bdsl_cd.', access: 'bdsl_at.', refresh: 'bdsl_rt.' };
/** sealed values for MCP's sign-in (pure but for crypto.subtle): seal(kind, object) → 'bdsl_<kind>.<base64url(iv ‖ AES-GCM)>'
 *  with a key made from STATE_SECRET by HKDF; open(kind, text) → the object, or null — a value sealed for one kind (a code)
 *  never opens as another (an access token): the kind is the cipher's associated data and inside it too */
export function tokenBox(stateSecret) {
  const subtle = () => globalThis.crypto.subtle;
  let keyP = null;
  const key = () => (keyP ??= (async () => {
    const base = await subtle().importKey('raw', enc.encode(String(stateSecret ?? '')), 'HKDF', false, ['deriveKey']);
    return subtle().deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: enc.encode('bds-lab'), info: enc.encode('bds-lab mcp sealed v1') }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  })());
  return {
    async seal(kind, obj) {
      if (!SEALED[kind]) throw new Error('kind');
      const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
      const ct = new Uint8Array(await subtle().encrypt({ name: 'AES-GCM', iv, additionalData: enc.encode(kind) }, await key(), enc.encode(JSON.stringify({ ...obj, kind }))));
      const all = new Uint8Array(12 + ct.length); all.set(iv, 0); all.set(ct, 12);
      return `${SEALED[kind]}${b64url(all)}`;
    },
    async open(kind, text) {
      const t = String(text ?? '');
      if (!SEALED[kind] || !t.startsWith(SEALED[kind]) || t.length > 8192 || String(stateSecret ?? '').length < 32) return null;
      try {
        const all = unb64url(t.slice(SEALED[kind].length));
        if (all.length < 29) return null;
        const pt = await subtle().decrypt({ name: 'AES-GCM', iv: all.subarray(0, 12), additionalData: enc.encode(kind) }, await key(), all.subarray(12));
        const j = JSON.parse(dec.decode(pt));
        return j && typeof j === 'object' && j.kind === kind ? j : null;
      } catch { return null; }
    },
  };
}
/** a redirect address an AI client may register (pure): https; http on this machine only (a CLI's loopback); or a native
 *  app's own scheme — never one a browser runs, reads or hands to another program */
export function redirectOk(s) {
  if (typeof s !== 'string' || !s || s.length > 500) return false;
  let u; try { u = new URL(s); } catch { return false; }
  if (u.hash || u.username || u.password) return false;
  if (u.protocol === 'https:') return Boolean(u.hostname);
  if (u.protocol === 'http:') return /^(localhost|127\.0\.0\.1|\[::1\])$/.test(u.hostname);
  return /^[a-z][a-z0-9+.-]{1,40}:$/.test(u.protocol) && !/^(javascript|data|file|blob|about|vbscript|ws|wss|ftp|mailto|tel|sms|chrome|chrome-extension|intent|filesystem|view-source|jar|content|res|resource|ms-[a-z0-9-]+):$/.test(u.protocol);
}
const esc = (x) => String(x ?? '').replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch]);
/** the device sign-in's short-lived store in memory (node.mjs, the tests): { get, put(key, value, ttlMs), take } — each value
 *  a copy, gone after its time; take reads and deletes at once */
export function memoryStore({ now = () => Date.now() } = {}) {
  const m = new Map();
  const live = (k) => { const x = m.get(k); if (!x) return null; if (!(x.exp > now())) { m.delete(k); return null; } return x.v; };
  return {
    async get(k) { const v = live(k); return v === null ? null : structuredClone(v); },
    async put(k, v, ttl) { m.set(k, { v: structuredClone(v), exp: now() + Math.min(Math.max(Number(ttl) || 0, 1000), 3_600_000) }); if (m.size > 5000) for (const [kk, x] of m) if (!(x.exp > now())) m.delete(kk); },
    async take(k) { const v = live(k); m.delete(k); return v; },
  };
}
/** the device sign-in's user code: 8 of 20 consonants that are hard to confuse (RFC 8628's example), shown XXXX-XXXX */
const UC = 'BCDFGHJKLMNPQRSTVWXZ';
function userCode() {
  let out = '';
  while (out.length < 8) for (const b of globalThis.crypto.getRandomValues(new Uint8Array(16))) if (b < 240 && out.length < 8) out += UC[b % 20];
  return out;
}
const DEVICE_TTL = 600_000, DEVICE_EVERY = 5;
/** an address with these added to its query (pure): its own query kept, empty values left out */
export function withQuery(addr, params) {
  const u = new URL(addr);
  for (const [k, v] of Object.entries(params ?? {})) if (v !== undefined && v !== null && v !== '') u.searchParams.append(k, String(v));
  return u.href;
}
/** GitHub's token answer → the tokens the panel is handed, or null (pure): only these five fields, each checked */
export function tokensOf(j) {
  const num = (v) => { const n = typeof v === 'string' && /^\d{1,9}$/.test(v) ? Number(v) : v; return typeof n === 'number' && Number.isFinite(n) && n > 0 && n < 1e9 ? Math.floor(n) : null; };
  if (!j || typeof j !== 'object' || !TOKEN.test(String(j.access_token ?? '')) || (j.token_type !== undefined && !/^bearer$/i.test(String(j.token_type)))) return null;
  return { access_token: j.access_token, expires_in: num(j.expires_in), refresh_token: TOKEN.test(String(j.refresh_token ?? '')) ? j.refresh_token : null, refresh_token_expires_in: num(j.refresh_token_expires_in), token_type: 'bearer' };
}

/** env → async (Request) → Response. fetchImpl reaches GitHub (a fake in tests); now is the clock (tests move it) */
export function handler(env, { fetchImpl = (...a) => globalThis.fetch(...a), now = () => Date.now(), store = null } = {}) {
  const c = config(env ?? {}), subtle = () => globalThis.crypto.subtle;
  let keyP = null;
  const key = () => (keyP ??= subtle().importKey('raw', enc.encode(c.stateSecret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']));
  // (one key, each use its own label: a state's signature is never a PKCE verifier, k's hash never the cookie's signature)
  const mac = async (label, data) => subtle().sign('HMAC', await key(), enc.encode(`${label}\n${data}`));
  const macOk = async (label, data, sig) => { try { return await subtle().verify('HMAC', await key(), unb64url(sig), enc.encode(`${label}\n${data}`)); } catch { return false; } };
  // (the PKCE verifier is written nowhere — not in the state GitHub's address carries, not in the cookie: it is made again
  //  from the cookie's k with the secret. k never leaves this browser and this service, so whoever saw the callback's
  //  address — its code and state — can neither make the cookie nor the verifier: the code stays theirs who began)
  const verifierOf = async (k) => b64url(await mac('pkce', k));
  const cookie = (v, age) => `${COOKIE}=${v}; Max-Age=${age}; Path=/; Secure; HttpOnly; SameSite=Lax`;
  const cookieOf = (req) => { for (const part of String(req.headers.get('cookie') ?? '').split(';')) { const i = part.indexOf('='); if (i > 0 && part.slice(0, i).trim() === COOKIE) return part.slice(i + 1).trim(); } return null; };
  /** the address a sign-in returns to → the same, cleaned, or null: under one of PANEL_ORIGINS (its origin, and its path's
   *  head: /bds-lab/ is not /bds-lab-evil/), no user:password, no escaped dot or slash in the path, no handoff in it */
  const returnOf = (s) => {
    if (typeof s !== 'string' || !s || s.length > 1500) return null;
    let u; try { u = new URL(s); } catch { return null; }
    if (u.username || u.password || ESCAPED.test(u.pathname) || /bdslab-auth/.test(u.hash)) return null;
    if (!c.panels.some((p) => p.origin === u.origin && u.pathname.startsWith(p.path))) return null;
    return `${u.origin}${u.pathname}${u.search}${u.hash}`;
  };
  // (the panel's own # is kept: its route — a run Discord linked to — and the nonce it left to know its own sign-in)
  const handTo = (back, part) => { const i = back.indexOf('#'), frag = i < 0 ? '' : back.slice(i + 1); return `${i < 0 ? back : back.slice(0, i)}#${frag ? `${frag}&` : ''}${part}`; };
  /** a sign-in begun → { state, cookie, k }: k (16 random bytes) goes in the cookie alone, signed (k.sig); the state GitHub's
   *  address carries has where it returns (r), k's keyed hash (h: k cannot be had from it) and when (t), signed */
  async function begin(r, m = null, d = null) {
    const k = b64url(globalThis.crypto.getRandomValues(new Uint8Array(16)));
    // (m: an AI client's request — where it returns, its state and PKCE challenge, its id's hash — for MCP's sign-in; d: the
    // device sign-in's key in the store)
    const payload = b64url(enc.encode(JSON.stringify({ r, h: b64url(await mac('bind', k)), t: now(), ...(m ? { m } : {}), ...(d ? { d } : {}) })));
    return { state: `${payload}.${b64url(await mac('state', payload))}`, cookie: `${k}.${b64url(await mac('cookie', k))}`, k };
  }
  async function openState(state) {
    const m = /^([A-Za-z0-9_-]{1,6000})\.([A-Za-z0-9_-]{43})$/.exec(String(state ?? ''));
    if (!m || !(await macOk('state', m[1], m[2]))) return null;
    try {
      const s = JSON.parse(dec.decode(unb64url(m[1])));
      const mcpOk = s?.m === undefined || (s.m && typeof s.m === 'object' && redirectOk(s.m.ru) && typeof s.m.cc === 'string' && typeof s.m.ch === 'string');
      const devOk = s?.d === undefined || /^[A-Za-z0-9_-]{43}$/.test(String(s.d));
      return typeof s?.r === 'string' && /^[A-Za-z0-9_-]{43}$/.test(String(s.h)) && Number.isFinite(s.t) && mcpOk && devOk ? s : null;
    } catch { return null; }
  }
  /** the cookie's value → its k, or null when this service did not sign it */
  async function openCookie(v) {
    const m = /^([A-Za-z0-9_-]{22})\.([A-Za-z0-9_-]{43})$/.exec(String(v ?? ''));
    return m && (await macOk('cookie', m[1], m[2])) ? m[1] : null;
  }
  /** a code or a refresh token traded at GitHub → { ok, tokens } / { ok: false, error } (GitHub's own words are not passed on) */
  async function exchange(params) {
    let r, j;
    try {
      r = await fetchImpl(`${c.web}${GITHUB.token}`, { method: 'POST', headers: { accept: 'application/json', 'content-type': 'application/x-www-form-urlencoded', 'user-agent': UA }, body: new URLSearchParams({ client_id: c.clientId, client_secret: c.secret, ...params }).toString() });
      j = await r.json();
    } catch { return { ok: false, error: 'github' }; }
    const tokens = r.ok && !j?.error ? tokensOf(j) : null;
    return tokens ? { ok: true, tokens } : { ok: false, error: 'exchange' };
  }
  const readJson = async (req, max = 4096) => {
    if (Number(req.headers.get('content-length') ?? 0) > max) return null;
    const t = await req.text().catch(() => '');
    try { const j = t.length <= max ? JSON.parse(t) : null; return j && typeof j === 'object' && !Array.isArray(j) ? j : null; } catch { return null; }
  };

  async function login(url) {
    const back = returnOf(url.searchParams.get('return'));
    if (!back) return reply(400, { error: 'return' });
    const { state, cookie: kept, k } = await begin(back);
    const q = new URLSearchParams({ client_id: c.clientId, redirect_uri: `${url.origin}/callback`, state });
    if (GITHUB.pkce) { q.set('code_challenge', b64url(await subtle().digest('SHA-256', enc.encode(await verifierOf(k))))); q.set('code_challenge_method', 'S256'); }
    if (/^(1|true)$/.test(url.searchParams.get('select') ?? '')) q.set('prompt', GITHUB.selectAccount);
    const who = url.searchParams.get('login');
    if (who && LOGIN.test(who)) q.set('login', who);
    return reply(302, null, { location: `${c.web}${GITHUB.authorize}?${q}`, 'set-cookie': cookie(kept, TTL / 1000) });
  }
  async function callback(url, req) {
    const clear = { 'set-cookie': cookie('', 0) }, state = url.searchParams.get('state') ?? '', s = await openState(state);
    // (a state this service did not sign: no address to trust — nothing is followed)
    if (!s) return reply(400, { error: 'state' }, clear);
    if (s.m) return mcpCallback(url, req, s);
    if (s.d) return deviceCallback(url, req, s);
    const back = returnOf(s.r);
    if (!back) return reply(400, { error: 'return' }, clear);
    const go = (part) => reply(302, null, { ...clear, location: handTo(back, part) });
    // (the cookie set when this browser began, its k matching the state's h: a callback address made elsewhere and sent to
    //  someone signs nobody in. A cookie this service did not sign was made outside a browser — the state's own value, say,
    //  copied from a callback address seen on the way: 400, nothing followed)
    const raw = cookieOf(req);
    if (!raw) return go('bdslab-auth-error=cookie');
    const k = await openCookie(raw);
    if (!k) return reply(400, { error: 'cookie' }, clear);
    if (!(await macOk('bind', k, s.h))) return go('bdslab-auth-error=cookie');
    const age = now() - s.t;
    if (!(age <= TTL && age >= -60_000)) return go('bdslab-auth-error=expired');
    const err = url.searchParams.get('error');
    if (err) return go(`bdslab-auth-error=${err === 'access_denied' ? 'denied' : 'github'}`);
    const code = url.searchParams.get('code') ?? '';
    if (!/^[\x21-\x7e]{1,512}$/.test(code)) return go('bdslab-auth-error=code');
    const t = await exchange({ code, redirect_uri: `${url.origin}/callback`, ...(GITHUB.pkce ? { code_verifier: await verifierOf(k) } : {}) });
    if (!t.ok) return go(`bdslab-auth-error=${t.error}`);
    return go(`bdslab-auth=${b64url(enc.encode(JSON.stringify(t.tokens)))}`);
  }
  async function refresh(body, cors) {
    const rt = body?.refresh_token;
    if (typeof rt !== 'string' || !TOKEN.test(rt)) return reply(400, { error: 'body' }, cors);
    const t = await exchange({ grant_type: 'refresh_token', refresh_token: rt });
    if (t.ok) return reply(200, t.tokens, cors);
    return t.error === 'github' ? reply(502, { error: 'github' }, cors) : reply(401, { error: 'refresh' }, cors);
  }
  /** a GitHub user token revoked on GitHub (the App's client id and secret) → true when it is gone (404 / 422: GitHub knows no
   *  such token any more — gone already, which is what was asked), false when GitHub could not be asked */
  async function revokeGh(at) {
    try {
      const r = await fetchImpl(`${c.api}${GITHUB.revoke(c.clientId)}`, { method: 'DELETE', headers: { accept: 'application/vnd.github+json', authorization: `Basic ${btoa(`${c.clientId}:${c.secret}`)}`, 'content-type': 'application/json', 'x-github-api-version': GITHUB.apiVersion, 'user-agent': UA }, body: JSON.stringify({ access_token: at }) });
      await r.text().catch(() => '');
      return r.ok || r.status === 404 || r.status === 422;
    } catch { return false; }
  }
  async function logout(body, cors) {
    const at = body?.access_token;
    if (typeof at !== 'string' || !TOKEN.test(at)) return reply(400, { error: 'body' }, cors);
    return (await revokeGh(at)) ? reply(204, null, cors) : reply(502, { error: 'github' }, cors);
  }

  // ---- MCP's sign-in: AI clients to the lab's API (api.mjs) ----
  const box = tokenBox(c.stateSecret);
  const OPEN = { 'access-control-allow-origin': '*', 'access-control-allow-headers': 'authorization, content-type, mcp-protocol-version', 'access-control-allow-methods': 'GET, POST, OPTIONS', 'access-control-max-age': '600' };
  const sha = async (text) => b64url(await subtle().digest('SHA-256', enc.encode(String(text))));
  const CONSENT = '__Host-bdslab_consent';
  const consentCookie = (v, age) => `${CONSENT}=${v}; Max-Age=${age}; Path=/; Secure; HttpOnly; SameSite=Strict`;
  const consentOf = (req) => { for (const part of String(req.headers.get('cookie') ?? '').split(';')) { const i = part.indexOf('='); if (i > 0 && part.slice(0, i).trim() === CONSENT) return part.slice(i + 1).trim(); } return null; };
  const DEVICE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code';
  const asMeta = (o) => ({ issuer: o, authorization_endpoint: `${o}/authorize`, token_endpoint: `${o}/token`, registration_endpoint: `${o}/register`, ...(store ? { device_authorization_endpoint: `${o}/device/code` } : {}), response_types_supported: ['code'], grant_types_supported: ['authorization_code', 'refresh_token', ...(store ? [DEVICE_GRANT] : [])], code_challenge_methods_supported: ['S256'], token_endpoint_auth_methods_supported: ['none', 'client_secret_post', 'client_secret_basic'], revocation_endpoint: `${o}/revoke`, revocation_endpoint_auth_methods_supported: ['none', 'client_secret_post', 'client_secret_basic'], scopes_supported: ['lab'], service_documentation: c.panels[0]?.href ?? o });
  const prMeta = (o) => ({ resource: `${o}/mcp`, authorization_servers: [o], scopes_supported: ['lab'], bearer_methods_supported: ['header'], resource_name: `bds-lab${c.lab ? `（${c.lab}）` : ''}`, resource_documentation: c.panels[0]?.href ?? o });
  /** a page of this service's own (the consent; or why not): text escaped, a style of its own nonce, forms only where they go */
  function page(status, title, body, { formTo = [], cookies = [] } = {}) {
    const nonce = b64url(globalThis.crypto.getRandomValues(new Uint8Array(12)));
    const headers = new Headers({ ...HEADERS, 'content-type': 'text/html; charset=utf-8', 'content-security-policy': `default-src 'none'; style-src 'nonce-${nonce}'; form-action 'self' ${formTo.join(' ')}; frame-ancestors 'none'; base-uri 'none'` });
    for (const k of cookies) headers.append('set-cookie', k);
    const css = 'body{font:16px/1.6 system-ui,sans-serif;margin:0;background:#f6f7f9;color:#111}main{max-width:34rem;margin:2rem auto;padding:1.5rem;background:#fff;border-radius:12px;box-shadow:0 1px 4px #0002}h1{font-size:1.3rem;margin-top:0}.who{font-weight:700}.host{font-family:ui-monospace,monospace;background:#eef;padding:.1rem .3rem;border-radius:4px;word-break:break-all}.row{display:flex;gap:.75rem;flex-wrap:wrap;margin-top:1.25rem}button,a.btn{font:inherit;padding:.6rem 1.1rem;border-radius:8px;border:1px solid #888;background:#fff;color:#111;text-decoration:none;cursor:pointer}button.go{background:#2f6fde;border-color:#2f6fde;color:#fff}.muted{color:#555;font-size:.92rem}@media (prefers-color-scheme:dark){body{background:#111;color:#eee}main{background:#1c1c1f}.host{background:#2a2a40}button,a.btn{background:#222;color:#eee}.muted{color:#aaa}}';
    return new Response(`<!doctype html><html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="referrer" content="no-referrer"><title>${esc(title)}</title><style nonce="${nonce}">${css}</style></head><body><main><h1>${esc(title)}</h1>${body}</main></body></html>`, { status, headers });
  }
  const stop = (status, why) => page(status, 'つなげません', `<p>${esc(why)}</p><p class="muted">AI のアプリで、もう一度つなぎ直してください。</p>`);
  /** a client as it registered (its signed value) → { id, uris, name, method }, or null */
  async function openClient(id) {
    const m = /^bdsc1\.([A-Za-z0-9_-]{1,6000})\.([A-Za-z0-9_-]{43})$/.exec(String(id ?? ''));
    if (!m || !(await macOk('client', m[1], m[2]))) return null;
    try {
      const j = JSON.parse(dec.decode(unb64url(m[1])));
      // (a device client — minted by /device/code — has no address to return to: it can only use the device grant and refresh)
      if (j?.d === 1 && Array.isArray(j.u) && !j.u.length) return { id: String(id), uris: [], name: String(j.n ?? ''), method: 'none', device: true };
      return Array.isArray(j?.u) && j.u.length && j.u.every(redirectOk) ? { id: String(id), uris: j.u, name: String(j.n ?? ''), method: String(j.a ?? 'none') } : null;
    } catch { return null; }
  }
  async function register(req) {
    const j = await readJson(req, 8192), bad = (d) => reply(400, { error: 'invalid_client_metadata', error_description: d }, OPEN);
    if (!j) return bad('a JSON object');
    const uris = j.redirect_uris;
    if (!Array.isArray(uris) || !uris.length || uris.length > 10 || !uris.every(redirectOk)) return reply(400, { error: 'invalid_redirect_uri', error_description: 'redirect_uris: 1-10 of https, http on localhost, or a native app scheme' }, OPEN);
    const method = j.token_endpoint_auth_method ?? 'none';
    if (!['none', 'client_secret_post', 'client_secret_basic'].includes(method)) return bad('token_endpoint_auth_method: none, client_secret_post or client_secret_basic');
    if (j.grant_types !== undefined && !(Array.isArray(j.grant_types) && j.grant_types.every((g) => g === 'authorization_code' || g === 'refresh_token'))) return bad('grant_types: authorization_code, refresh_token');
    if (j.response_types !== undefined && !(Array.isArray(j.response_types) && j.response_types.every((r) => r === 'code'))) return bad('response_types: code');
    const name = String(j.client_name ?? '').replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, 80) || 'AI のアプリ', at = Math.floor(now() / 1000);
    const payload = b64url(enc.encode(JSON.stringify({ u: uris, n: name, a: method, t: at })));
    const id = `bdsc1.${payload}.${b64url(await mac('client', payload))}`;
    const out = { client_id: id, client_id_issued_at: at, client_name: name, redirect_uris: uris, token_endpoint_auth_method: method, grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'] };
    if (method !== 'none') Object.assign(out, { client_secret: b64url(await mac('client-secret', id)), client_secret_expires_at: 0 });
    return reply(201, out, OPEN);
  }
  /** GET /authorize: the request checked, then this service's own page asks the person — the client by name, where it
   *  returns, what it may do — before anything goes to GitHub */
  async function authorizeAsk(url) {
    const q = url.searchParams, client = await openClient(q.get('client_id'));
    if (!client) return stop(400, 'この AI のアプリの登録（client_id）が正しくありません。');
    const ru = q.get('redirect_uri') ?? (client.uris.length === 1 ? client.uris[0] : null);
    if (!ru || !client.uris.includes(ru)) return stop(400, '戻る先（redirect_uri）が、この AI のアプリの登録にありません。');
    const st = q.get('state') ?? '';
    const back = (params) => reply(302, null, { location: withQuery(ru, { ...params, ...(st.length <= 1000 ? { state: st } : {}) }) });
    if (st.length > 1000) return back({ error: 'invalid_request', error_description: 'state is too long' });
    if (q.get('response_type') !== 'code') return back({ error: 'unsupported_response_type' });
    const cc = q.get('code_challenge') ?? '';
    if (!/^[A-Za-z0-9_-]{43,128}$/.test(cc) || q.get('code_challenge_method') !== 'S256') return back({ error: 'invalid_request', error_description: 'PKCE with S256 is required' });
    const res = q.get('resource');
    if (res && res.replace(/\/+$/, '') !== `${url.origin}/mcp` && res.replace(/\/+$/, '') !== url.origin) return back({ error: 'invalid_target' });
    const sc = String(q.get('scope') ?? 'lab').slice(0, 200), nonce = b64url(globalThis.crypto.getRandomValues(new Uint8Array(16)));
    const payload = b64url(enc.encode(JSON.stringify({ ci: client.id, ru, st, cc, sc, t: now() })));
    const signed = `${payload}.${b64url(await mac('consent-req', payload))}`, csrf = b64url(await mac('consent', `${nonce}\n${payload}`));
    const to = new URL(ru), shown = to.protocol === 'https:' || to.protocol === 'http:' ? to.host : to.protocol.replace(/:$/, '');
    // (the form's way on: here, GitHub, and the client — a browser checks a form's redirects against form-action too)
    const formTo = [c.web, /^https?:$/.test(to.protocol) ? to.origin : to.protocol].map((x) => String(x).replace(/[;'\s]/g, ''));
    const cancel = withQuery(ru, { error: 'access_denied', ...(st ? { state: st } : {}) });
    return page(200, 'AI にラボの操作を許しますか', `<p><span class="who">「${esc(client.name)}」</span>が、あなたの GitHub のアカウントで <b>${esc(c.lab ?? 'このラボ')}</b> を操作する許可を求めています。</p>
<p>許すと、その AI はあなたと同じ権限で、ワークフローを始め、実行のログを読み、ファイルを直し、秘密や変数を登録できます（ラボの役割の決まり・確認・監査ログはパネルと同じ。.github/ は変えられません）。</p>
<p class="muted">許したあとの戻り先: <span class="host">${esc(shown)}</span>　知らないアプリなら「やめる」を押してください。</p>
<form method="post" action="/authorize"><input type="hidden" name="req" value="${esc(signed)}"><input type="hidden" name="csrf" value="${esc(csrf)}">
<div class="row"><button class="go" type="submit">許可して GitHub へ</button><a class="btn" href="${esc(cancel)}">やめる</a></div></form>`, { formTo, cookies: [consentCookie(nonce, TTL / 1000)] });
  }
  /** POST /authorize: the page's own form (its cookie, its CSRF value, its signed request, fresh) → the GitHub sign-in begun as
   *  /login does, the client's request riding in the state */
  async function authorizeYes(req, url) {
    const site = req.headers.get('sec-fetch-site');
    if (site && site !== 'same-origin') return stop(403, 'このページの外から送られました。');
    if (Number(req.headers.get('content-length') ?? 0) > 16384) return stop(413, '送られたものが大きすぎます。');
    const p = new URLSearchParams((await req.text().catch(() => '')).slice(0, 16384)), nonce = consentOf(req);
    const m = /^([A-Za-z0-9_-]{1,8000})\.([A-Za-z0-9_-]{43})$/.exec(p.get('req') ?? '');
    if (!nonce || !m || !(await macOk('consent', `${nonce}\n${m[1]}`, p.get('csrf') ?? '')) || !(await macOk('consent-req', m[1], m[2]))) return stop(403, '許可の画面が古いか、ほかの画面から送られました。');
    let r; try { r = JSON.parse(dec.decode(unb64url(m[1]))); } catch { return stop(400, '許可の中身が読めません。'); }
    const age = now() - Number(r.t);
    if (!(age <= TTL && age >= -60_000)) return stop(400, '許可の画面が古くなりました（10 分）。');
    const client = await openClient(r.ci);
    if (!client || !client.uris.includes(r.ru)) return stop(400, 'この AI のアプリの登録が変わりました。');
    const { state, cookie: kept, k } = await begin('', { ru: r.ru, st: String(r.st ?? ''), cc: String(r.cc), ch: await sha(client.id), sc: String(r.sc ?? 'lab') });
    const q = new URLSearchParams({ client_id: c.clientId, redirect_uri: `${url.origin}/callback`, state });
    if (GITHUB.pkce) { q.set('code_challenge', b64url(await subtle().digest('SHA-256', enc.encode(await verifierOf(k))))); q.set('code_challenge_method', 'S256'); }
    const headers = new Headers({ ...HEADERS, location: `${c.web}${GITHUB.authorize}?${q}` });
    headers.append('set-cookie', cookie(kept, TTL / 1000));
    headers.append('set-cookie', consentCookie('', 0));
    return new Response(null, { status: 302, headers });
  }
  /** GitHub back to /callback for an AI client: the same browser (the cookie's k), in time, GitHub's code traded — then a
   *  short-lived code of this service's own, sealed with the person's tokens, to the client's own address */
  async function mcpCallback(url, req, s) {
    const m = s.m, clear = cookie('', 0);
    const back = (params) => reply(302, null, { 'set-cookie': clear, location: withQuery(m.ru, { ...params, ...(m.st ? { state: m.st } : {}), iss: url.origin }) });
    const raw = cookieOf(req);
    if (!raw) return back({ error: 'access_denied', error_description: 'cookie' });
    const k = await openCookie(raw);
    if (!k) return reply(400, { error: 'cookie' }, { 'set-cookie': clear });
    if (!(await macOk('bind', k, s.h))) return back({ error: 'access_denied', error_description: 'cookie' });
    const age = now() - s.t;
    if (!(age <= TTL && age >= -60_000)) return back({ error: 'access_denied', error_description: 'expired' });
    if (url.searchParams.get('error')) return back({ error: 'access_denied' });
    const code = url.searchParams.get('code') ?? '';
    if (!/^[\x21-\x7e]{1,512}$/.test(code)) return back({ error: 'server_error', error_description: 'code' });
    const t = await exchange({ code, redirect_uri: `${url.origin}/callback`, ...(GITHUB.pkce ? { code_verifier: await verifierOf(k) } : {}) });
    if (!t.ok) return back({ error: 'server_error', error_description: t.error });
    return back({ code: await box.seal('code', { gh: t.tokens, cc: m.cc, ch: m.ch, ru: m.ru, sc: m.sc, exp: now() + 120_000 }) });
  }
  async function issue(gh, chash, scope, url) {
    const life = gh.expires_in ?? 30 * 86400;
    const out = { access_token: await box.seal('access', { gh: gh.access_token, exp: now() + life * 1000, aud: `${url.origin}/mcp`, ch: chash }), token_type: 'Bearer', expires_in: life, scope: scope || 'lab' };
    if (gh.refresh_token) out.refresh_token = await box.seal('refresh', { gh: gh.refresh_token, ch: chash, sc: scope || 'lab', exp: now() + (gh.refresh_token_expires_in ?? 180 * 86400) * 1000 });
    return reply(200, out, { ...OPEN, pragma: 'no-cache' });
  }
  /** a form's or a JSON object's fields as strings (OAuth's endpoints take either), null when it is neither */
  async function params(req) {
    if (Number(req.headers.get('content-length') ?? 0) > 16384) return null;
    const text = (await req.text().catch(() => '')).slice(0, 16384), ct = req.headers.get('content-type') ?? '';
    if (!/json/i.test(ct)) return Object.fromEntries(new URLSearchParams(text));
    try { const j = JSON.parse(text); return j && typeof j === 'object' && !Array.isArray(j) ? Object.fromEntries(Object.entries(j).map(([k, v]) => [k, String(v)])) : null; } catch { return null; }
  }
  /** the client a request to /token or /revoke names (client_id in the form, or HTTP Basic), its secret checked when it has
   *  one → { client } | { none: true } (named no client) | { bad: true } */
  async function clientOf(req, p) {
    let cid = p.client_id, secret = p.client_secret;
    const basic = /^Basic\s+([A-Za-z0-9+/=]{1,8000})$/i.exec(req.headers.get('authorization') ?? '');
    if (basic) { try { const [a, b = ''] = atob(basic[1]).split(':'); cid = decodeURIComponent(a); secret = decodeURIComponent(b); } catch { return { bad: true }; } }
    if (cid === undefined) return { none: true };
    const client = await openClient(cid);
    if (!client || (client.method !== 'none' && !(await macOk('client-secret', client.id, String(secret ?? ''))))) return { bad: true };
    return { client };
  }
  async function token(req, url) {
    const bad = (error, status = 400) => reply(status, { error }, OPEN);
    const p = await params(req);
    if (!p) return bad('invalid_request');
    const { client } = await clientOf(req, p);
    if (!client) return bad('invalid_client', 401);
    const chash = await sha(client.id);
    if (p.grant_type === 'authorization_code') {
      const code = await box.open('code', p.code);
      if (!code || !(code.exp > now()) || code.ch !== chash || (p.redirect_uri !== undefined && p.redirect_uri !== code.ru)) return bad('invalid_grant');
      const v = String(p.code_verifier ?? '');
      if (!/^[A-Za-z0-9._~-]{43,128}$/.test(v) || (await sha(v)) !== code.cc) return bad('invalid_grant');
      return issue(code.gh, chash, code.sc, url);
    }
    if (p.grant_type === 'refresh_token') {
      const r = await box.open('refresh', p.refresh_token);
      if (!r || r.ch !== chash || !(r.exp > now())) return bad('invalid_grant');
      const t = await exchange({ grant_type: 'refresh_token', refresh_token: r.gh });
      if (!t.ok) return t.error === 'github' ? bad('temporarily_unavailable', 503) : bad('invalid_grant');
      return issue(t.tokens, chash, r.sc, url);
    }
    if (p.grant_type === DEVICE_GRANT && store) {
      const key = `d:${await sha(String(p.device_code ?? ''))}`, rec = await store.get(key);
      if (!rec) return bad('expired_token');
      if (rec.ch !== chash) return bad('invalid_grant');
      if (rec.st === 'wait') return bad('authorization_pending');
      const got = await store.take(key);
      if (!got || got.st === 'no') return bad(got ? 'access_denied' : 'expired_token');
      const sealed = got.st === 'ok' ? await box.open('code', got.gh) : null;
      return sealed ? issue(sealed.gh, chash, sealed.sc, url) : bad('expired_token');
    }
    return bad('unsupported_grant_type');
  }
  /** POST /revoke (RFC 7009): this service's access or refresh token → its GitHub token revoked on GitHub (a refresh token is
   *  traded once and the new access token revoked: the pair keeps no live token on GitHub — revoke the access token too).
   *  200 whatever the token was (nothing told to one who tries tokens); a token named with a client it was not issued to:
   *  refused; GitHub not reachable: 503, to be tried again */
  async function revoke(req) {
    const p = await params(req);
    if (!p || !p.token) return reply(400, { error: 'invalid_request' }, OPEN);
    const who = await clientOf(req, p);
    if (who.bad) return reply(401, { error: 'invalid_client' }, OPEN);
    const kind = p.token.startsWith(SEALED.refresh) ? 'refresh' : p.token.startsWith(SEALED.access) ? 'access' : null;
    const t = kind ? await box.open(kind, p.token) : null;
    if (!t || !(t.exp > now())) return reply(200, {}, OPEN);
    if (who.client && t.ch !== (await sha(who.client.id))) return reply(400, { error: 'unauthorized_client' }, OPEN);
    let at = kind === 'access' ? t.gh : null;
    if (kind === 'refresh') { const x = await exchange({ grant_type: 'refresh_token', refresh_token: t.gh }); if (x.ok) at = x.tokens.access_token; else if (x.error === 'github') return reply(503, { error: 'temporarily_unavailable' }, OPEN); }
    if (at && !(await revokeGh(at))) return reply(503, { error: 'temporarily_unavailable' }, OPEN);
    return reply(200, {}, OPEN);
  }
  // ---- the device sign-in (RFC 8628) ----
  const cleanName = (x) => String(x ?? '').replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, 80);
  async function deviceCode(req, url) {
    if (!store) return reply(400, { error: 'unsupported_grant_type', error_description: 'this service keeps no store: the device sign-in is off' }, OPEN);
    const p = await params(req);
    if (!p) return reply(400, { error: 'invalid_request' }, OPEN);
    let client = null;
    if (p.client_id) { client = await openClient(p.client_id); if (!client) return reply(401, { error: 'invalid_client' }, OPEN); }
    const name = cleanName(p.client_name) || client?.name || 'AI のアプリ';
    if (!client) {
      const payload = b64url(enc.encode(JSON.stringify({ u: [], n: name, a: 'none', d: 1, t: Math.floor(now() / 1000) })));
      client = { id: `bdsc1.${payload}.${b64url(await mac('client', payload))}`, name };
    }
    const dc = b64url(globalThis.crypto.getRandomValues(new Uint8Array(32))), uc = userCode(), dk = await sha(dc);
    await store.put(`d:${dk}`, { st: 'wait', ch: await sha(client.id), n: name, uc, sc: 'lab' }, DEVICE_TTL);
    await store.put(`u:${uc}`, dk, DEVICE_TTL);
    const shown = `${uc.slice(0, 4)}-${uc.slice(4)}`;
    return reply(200, { device_code: dc, user_code: shown, verification_uri: `${url.origin}/device`, verification_uri_complete: `${url.origin}/device?code=${shown}`, expires_in: DEVICE_TTL / 1000, interval: DEVICE_EVERY, client_id: client.id }, OPEN);
  }
  const ucOf = (x) => { const u = String(x ?? '').toUpperCase().replace(/[^A-Z]/g, ''); return u.length === 8 && [...u].every((ch) => UC.includes(ch)) ? u : null; };
  /** GET /device: the code (typed, or in the link) → this service's own page: the AI by name, the code to compare with the AI's,
   *  what it may do — and the two buttons; no code: a box to type it in */
  async function deviceAsk(url) {
    if (!store) return stop(400, 'このサービスでは、コードでつなぐ方法は使えません。');
    const raw = url.searchParams.get('code');
    if (!raw) return page(200, 'AI をつなぐ', '<p>AI の画面に出ているコード（XXXX-XXXX）を入れてください。</p><form method="get" action="/device"><p><input name="code" autocomplete="off" autocapitalize="characters" placeholder="XXXX-XXXX" maxlength="12" required></p><div class="row"><button class="go" type="submit">つぎへ</button></div></form>');
    const uc = ucOf(raw), dk = uc ? await store.get(`u:${uc}`) : null, rec = dk ? await store.get(`d:${dk}`) : null;
    if (!rec || rec.st !== 'wait') return stop(400, 'このコードは使えません（10 分で切れます。使ったコードも使えません）。AI に、もう一度つなぐように頼んでください。');
    const nonce = b64url(globalThis.crypto.getRandomValues(new Uint8Array(16)));
    const payload = b64url(enc.encode(JSON.stringify({ dk, t: now() })));
    const signed = `${payload}.${b64url(await mac('device-req', payload))}`, csrf = b64url(await mac('consent', `${nonce}\n${payload}`)), shown = `${uc.slice(0, 4)}-${uc.slice(4)}`;
    const hidden = `<input type="hidden" name="req" value="${esc(signed)}"><input type="hidden" name="csrf" value="${esc(csrf)}">`;
    return page(200, 'AI にラボの操作を許しますか', `<p><span class="who">「${esc(rec.n)}」</span>が、あなたの GitHub のアカウントで <b>${esc(c.lab ?? 'このラボ')}</b> を操作する許可を求めています。</p>
<p>コード: <span class="host">${esc(shown)}</span>　AI の画面のコードと同じか確かめてください。</p>
<p>許すと、その AI はあなたと同じ権限で、ワークフローを始め、実行のログを読み、ファイルを直し、秘密や変数を登録できます（ラボの役割の決まり・確認・監査ログはパネルと同じ。.github/ は変えられません）。</p>
<p class="muted">あなた自身が AI に「つないで」と頼んで、この画面を開いたときだけ許可してください。ほかの人から送られてきたリンクなら「やめる」を。</p>
<form method="post" action="/device">${hidden}<div class="row"><button class="go" type="submit">許可して GitHub へ</button></div></form>
<form method="post" action="/device">${hidden}<input type="hidden" name="deny" value="1"><div class="row"><button type="submit">やめる</button></div></form>`, { formTo: [String(c.web).replace(/[;'\s]/g, '')], cookies: [consentCookie(nonce, TTL / 1000)] });
  }
  /** POST /device: the page's own form (cookie, CSRF value, signed and fresh) → said no: kept so the AI hears it; else the
   *  GitHub sign-in begun, the device's key riding in the state */
  async function deviceYes(req, url) {
    if (!store) return stop(400, 'このサービスでは、コードでつなぐ方法は使えません。');
    const site = req.headers.get('sec-fetch-site');
    if (site && site !== 'same-origin') return stop(403, 'このページの外から送られました。');
    if (Number(req.headers.get('content-length') ?? 0) > 16384) return stop(413, '送られたものが大きすぎます。');
    const p = new URLSearchParams((await req.text().catch(() => '')).slice(0, 16384)), nonce = consentOf(req);
    const m = /^([A-Za-z0-9_-]{1,2000})\.([A-Za-z0-9_-]{43})$/.exec(p.get('req') ?? '');
    if (!nonce || !m || !(await macOk('consent', `${nonce}\n${m[1]}`, p.get('csrf') ?? '')) || !(await macOk('device-req', m[1], m[2]))) return stop(403, '許可の画面が古いか、ほかの画面から送られました。');
    let r; try { r = JSON.parse(dec.decode(unb64url(m[1]))); } catch { return stop(400, '許可の中身が読めません。'); }
    const age = now() - Number(r.t);
    if (!(age <= TTL && age >= -60_000) || !/^[A-Za-z0-9_-]{43}$/.test(String(r.dk))) return stop(400, '許可の画面が古くなりました（10 分）。');
    const rec = await store.get(`d:${r.dk}`);
    if (!rec || rec.st !== 'wait') return stop(400, 'このコードはもう使えません。AI に、もう一度つなぐように頼んでください。');
    if (p.get('deny')) {
      await store.put(`d:${r.dk}`, { ...rec, st: 'no' }, DEVICE_TTL);
      return page(200, 'やめました', '<p>AI はつながりません。この画面は閉じてかまいません。</p>', { cookies: [consentCookie('', 0)] });
    }
    const { state, cookie: kept, k } = await begin('', null, r.dk);
    const q = new URLSearchParams({ client_id: c.clientId, redirect_uri: `${url.origin}/callback`, state });
    if (GITHUB.pkce) { q.set('code_challenge', b64url(await subtle().digest('SHA-256', enc.encode(await verifierOf(k))))); q.set('code_challenge_method', 'S256'); }
    const headers = new Headers({ ...HEADERS, location: `${c.web}${GITHUB.authorize}?${q}` });
    headers.append('set-cookie', cookie(kept, TTL / 1000));
    headers.append('set-cookie', consentCookie('', 0));
    return new Response(null, { status: 302, headers });
  }
  /** GitHub back to /callback for the device sign-in: the same browser, in time, GitHub's code traded — the tokens sealed into
   *  the store for the AI's next ask, and the person told to go back to it */
  async function deviceCallback(url, req, s) {
    const clear = cookie('', 0), say = (status, title, body) => page(status, title, body, { cookies: [clear] });
    const raw = cookieOf(req), k = raw ? await openCookie(raw) : null;
    if (!k || !(await macOk('bind', k, s.h))) return say(400, 'つなげません', '<p>この画面は、許可の画面を開いたのと同じブラウザで開いてください。</p>');
    const age = now() - s.t;
    if (!(age <= TTL && age >= -60_000)) return say(400, 'つなげません', '<p>時間がたちすぎました（10 分）。AI に、もう一度つなぐように頼んでください。</p>');
    const rec = store ? await store.get(`d:${s.d}`) : null;
    if (!rec || rec.st !== 'wait') return say(400, 'つなげません', '<p>このコードはもう使えません。AI に、もう一度つなぐように頼んでください。</p>');
    if (url.searchParams.get('error')) { await store.put(`d:${s.d}`, { ...rec, st: 'no' }, DEVICE_TTL); return say(200, 'やめました', '<p>GitHub で取りやめました。AI はつながりません。</p>'); }
    const code = url.searchParams.get('code') ?? '';
    const t = /^[\x21-\x7e]{1,512}$/.test(code) ? await exchange({ code, redirect_uri: `${url.origin}/callback`, ...(GITHUB.pkce ? { code_verifier: await verifierOf(k) } : {}) }) : { ok: false };
    if (!t.ok) return say(502, 'つなげません', '<p>GitHub からトークンを受け取れませんでした。少しして、AI にもう一度つなぐように頼んでください。</p>');
    await store.put(`d:${s.d}`, { ...rec, st: 'ok', gh: await box.seal('code', { gh: t.tokens, ch: rec.ch, sc: rec.sc, exp: now() + DEVICE_TTL }) }, DEVICE_TTL);
    return say(200, '✅ AI がつながりました', `<p><span class="who">「${esc(rec.n)}」</span>が ${esc(c.lab ?? 'このラボ')} を操作できるようになりました（あなたの GitHub のアカウントで。ラボの役割の決まり・確認・監査ログのとおりに）。</p><p>この画面は閉じて、AI の画面に戻ってください。</p><p class="muted">やめさせるには: GitHub の Settings → Applications → Authorized GitHub Apps で、このラボの App を取り消します。</p>`);
  }
  const MCP_ROUTES = { '/.well-known/oauth-authorization-server': 'GET', '/.well-known/oauth-protected-resource': 'GET', '/.well-known/oauth-protected-resource/mcp': 'GET', '/register': 'POST', '/authorize': 'GET POST', '/token': 'POST', '/revoke': 'POST', '/device/code': 'POST', '/device': 'GET POST' };
  async function mcpRoute(req, url, path) {
    if (req.method === 'OPTIONS') return path === '/authorize' || path === '/device' ? reply(405, { error: 'method' }) : reply(204, null, OPEN);
    if (!MCP_ROUTES[path].split(' ').includes(req.method)) return reply(405, { error: 'method' }, { ...OPEN, allow: MCP_ROUTES[path].replace(' ', ', ') });
    if (path === '/.well-known/oauth-authorization-server') return reply(200, asMeta(url.origin), OPEN);
    if (path.startsWith('/.well-known/oauth-protected-resource')) return reply(200, prMeta(url.origin), OPEN);
    if (c.missing.length) return path === '/authorize' || path === '/device' ? stop(503, 'サインインのサービスの設定が足りません（パネルの「準備」）。') : reply(503, { error: 'temporarily_unavailable' }, OPEN);
    if (path === '/register') return register(req);
    if (path === '/token') return token(req, url);
    if (path === '/revoke') return revoke(req);
    if (path === '/device/code') return deviceCode(req, url);
    if (path === '/device') return req.method === 'GET' ? deviceAsk(url) : deviceYes(req, url);
    return req.method === 'GET' ? authorizeAsk(url) : authorizeYes(req, url);
  }

  const ROUTES = { '/health': 'GET', '/login': 'GET', '/callback': 'GET', '/refresh': 'POST', '/logout': 'POST' };
  async function route(req) {
    const url = new URL(req.url), path = url.pathname, want = ROUTES[path];
    if (MCP_ROUTES[path]) return mcpRoute(req, url, path);
    if (!want) return reply(404, { error: 'not_found' });
    // (CORS for the panel's own origins alone; a browser says where a call comes from — anything else is not the panel)
    const origin = req.headers.get('origin'), allowed = origin !== null && c.origins.includes(origin);
    const cors = allowed ? { 'access-control-allow-origin': origin, vary: 'Origin' } : { vary: 'Origin' };
    if (req.method === 'OPTIONS') {
      return allowed && path !== '/login' && path !== '/callback' ? reply(204, null, { ...cors, 'access-control-allow-methods': 'GET, POST', 'access-control-allow-headers': 'content-type', 'access-control-max-age': '600' }) : reply(403, { error: 'origin' }, { vary: 'Origin' });
    }
    if (req.method !== want) return reply(405, { error: 'method' }, { allow: `${want}, OPTIONS` });
    if (path === '/health') return reply(c.missing.length ? 503 : 200, { ok: !c.missing.length, clientId: c.clientId || null, origins: c.origins, panels: c.panels.map((p) => p.href), version: VERSION, lab: c.lab, device: Boolean(store), ...(c.missing.length ? { missing: c.missing } : {}) }, cors);
    if (c.missing.length) return reply(500, { error: 'config' }, cors);
    if (path === '/login') return login(url);
    if (path === '/callback') return callback(url, req);
    if (!allowed) return reply(403, { error: 'origin' }, { vary: 'Origin' });
    const body = await readJson(req);
    return path === '/refresh' ? refresh(body, cors) : logout(body, cors);
  }
  return async (request) => { try { return await route(request); } catch { return reply(500, { error: 'internal' }); } };
}
