// the sign-in service and the lab's API for AI in Cloudflare's own runtime (workerd, through `wrangler dev --local`): the
// Worker as auth-deploy.yml puts it in place — auth/worker.mjs bundled with panel/lib, its Durable Object, the platform's
// fetch, WebCrypto and timers — against a fake GitHub on this machine. /health, the discovery pages, the tools (a secret
// sealed with the platform's X25519 so GitHub opens it, a log fetched over its redirect without the token, the units by one
// GraphQL query, a file written in UTF-8, a workflow started and its run found, MCP), its own https /health answered inside
// (no network: a Worker cannot fetch its own workers.dev address), and the device sign-in through the Durable Object.
// Nothing leaves this machine. auth-deploy.yml runs it before it puts the service in place.
// WRANGLER: the command to run wrangler (e.g. "npx --yes wrangler@4.148.0"; default: a wrangler in node_modules — with
// none, skipped and said).
// node tests/api-workerd.mjs
import fs from 'node:fs';
import os from 'node:os';
import net from 'node:net';
import http from 'node:http';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { fakeCheck } from '../panel/lib/ghrules.mjs';

const TOP = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SEAL = await import(pathToFileURL(path.join(TOP, 'panel/lib/seal.mjs')).href);
const local = [path.join(TOP, 'node_modules/.bin/wrangler'), path.join(TOP, 'auth/node_modules/.bin/wrangler')].find((f) => fs.existsSync(f));
const WRANGLER = process.env.WRANGLER?.trim() ? process.env.WRANGLER.trim().split(/\s+/) : local ? [local] : null;
if (!WRANGLER) { console.log('skip: wrangler がありません（WRANGLER="npx --yes wrangler@4.148.0" node tests/api-workerd.mjs）'); process.exit(0); }

let pass = 0, fail = 0;
const t = async (name, fn) => { try { await fn(); pass++; console.log(`ok   ${name}`); } catch (e) { fail++; console.log(`FAIL ${name}\n     ${e.stack?.split('\n').slice(0, 3).join('\n     ') ?? e.message}`); } };
const ok = (c, m) => { if (!c) throw new Error(m); };
const b64url = (b) => Buffer.from(b).toString('base64url');
const sha256 = (s) => b64url(crypto.createHash('sha256').update(s).digest());
const freePort = () => new Promise((r) => { const s = net.createServer().listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => r(p)); }); });

// ---- a fake GitHub: its web sign-in, its API for the lab o/lab (public: no audit log), the log storage, the panel's config ----
const CLIENT_ID = 'Iv23liFAKECLIENT', CLIENT_SECRET = 'fake-client-secret-0123456789abcdef', STATE_SECRET = 'fake-state-secret-0123456789abcdef-0123456789';
const SELF = 'https://bds-lab-auth.test', OWNER = 'ghp_fake_owner_token_0123456789abcd';
const sk = crypto.randomBytes(32), pk = SEAL.x25519Public(sk);
const G = { tokens: { [OWNER]: 'o' }, codes: new Map(), refreshes: new Set(), files: new Map(), secrets: new Map(), dispatched: [], blobAuth: [], revoked: [], agents: new Set(), n: 0 };
const put = (p, text) => G.files.set(p, { bytes: Buffer.from(text), sha: crypto.createHash('sha1').update(`${p}\n${text}\n${Math.random()}`).digest('hex') });
put('bds/addons/coins/bp/manifest.json', JSON.stringify({ format_version: 2, header: { name: 'Coins', version: [1, 2, 0] }, modules: [] }));
put('bds/addons/coins/tests.txt', '## one\nsay hi\n~ hi\n## two\nsay yo\n~ yo\n');
put('bds/addons/coins/TASK.md', '# コインのアドオン\n');
const WFS = ['verify.yml', 'unit.yml', 'pages.yml', 'auth-deploy.yml'].map((f, i) => ({ id: 10 + i, name: f.replace('.yml', ''), path: `.github/workflows/${f}`, state: 'active' }));
const runOf = (id, file, conclusion, event = 'push') => ({ id, name: file.replace('.yml', ''), path: `.github/workflows/${file}`, event, status: conclusion ? 'completed' : 'queued', conclusion, head_branch: 'main', head_sha: 'abcdef1234567', run_number: id, run_attempt: 1, actor: { login: 'o' }, triggering_actor: { login: 'o' }, created_at: '2026-10-17T00:00:00Z', html_url: `https://github.com/o/lab/actions/runs/${id}` });
const fake = http.createServer(async (req, res) => {
  const body = await new Promise((r) => { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', () => r(b)); });
  const u = new URL(req.url, 'http://fake'), p = u.pathname, m = req.method;
  let jb = null; try { jb = body ? JSON.parse(body) : null; } catch { /* a form */ }
  const send = (status, j, headers = {}) => { res.writeHead(status, { 'content-type': 'application/json', ...headers }); res.end(j === null || j === undefined ? '' : typeof j === 'string' ? j : JSON.stringify(j)); };
  if (p === '/web/login/oauth/authorize') {
    const q = u.searchParams, back = new URL(q.get('redirect_uri')), c = `code${crypto.randomBytes(6).toString('hex')}`;
    G.codes.set(c, q.get('code_challenge'));
    back.search = new URLSearchParams({ code: c, state: q.get('state') });
    return send(302, null, { location: back.href });
  }
  if (p === '/web/login/oauth/access_token') {
    const q = new URLSearchParams(body), ch = G.codes.get(q.get('code'));
    G.codes.delete(q.get('code'));
    if (q.get('client_id') !== CLIENT_ID || q.get('client_secret') !== CLIENT_SECRET) return send(200, { error: 'incorrect_client_credentials' });
    if (q.get('grant_type') === 'refresh_token') { if (!G.refreshes.delete(q.get('refresh_token'))) return send(200, { error: 'bad_refresh_token' }); }
    else if (!ch || ch !== sha256(q.get('code_verifier') ?? '')) return send(200, { error: 'bad_verification_code' });
    G.n++; const tk = `ghu_AccessToken${G.n}xxxxxxxxxxxxxxxxxx`, rt = `ghr_RefreshToken${G.n}xxxxxxxxxxxxxxx`; G.tokens[tk] = 'o'; G.refreshes.add(rt);
    return send(200, { access_token: tk, expires_in: 28800, refresh_token: rt, refresh_token_expires_in: 15811200, token_type: 'bearer', scope: '' });
  }
  if (p.startsWith('/blob/')) { G.blobAuth.push(req.headers.authorization ?? null); return send(200, '2026-10-17T00:00:01.1234567Z setting up\n2026-10-17T00:00:02.0000000Z \x1b[31mError: boom\x1b[0m\n2026-10-17T00:00:03.0000000Z after\n'); }
  if (p === '/pages/lab/config.json') return send(200, { authUrl: SELF, appSlug: 'lab-o', appClientId: CLIENT_ID });
  if (!p.startsWith('/api/')) return send(404, { message: 'Not Found' });
  if (m === 'DELETE' && p === `/api/applications/${CLIENT_ID}/token`) {
    if (req.headers.authorization !== `Basic ${Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64')}`) return send(401, { message: 'Requires authentication' });
    const had = Boolean(G.tokens[jb?.access_token]); delete G.tokens[jb?.access_token]; G.revoked.push(jb?.access_token);
    return send(had ? 204 : 404, had ? null : { message: 'Not Found' });
  }
  const who = G.tokens[String(req.headers.authorization ?? '').replace(/^Bearer /, '')];
  if (!who) return send(401, { message: 'Bad credentials' });
  G.agents.add(String(req.headers['user-agent'] ?? ''));
  if (!req.headers['user-agent']) return send(403, { message: 'Request forbidden by administrative rules. Please make sure your request has a User-Agent header' });
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(m) && p !== '/api/graphql') { const bad = fakeCheck(m, p.slice(4) + u.search, jb); if (bad) return send(422, { message: bad.message }); }
  const a = p.slice(4), r = a.replace(/^\/repos\/o\/lab/, '');
  let x;
  if (a === '/user') return send(200, { login: who, id: 1, type: 'User' });
  if (a === '/graphql') {
    const data = {};
    for (const [, k, e] of String(jb?.query ?? '').matchAll(/(\w+):\s*object\(expression:\s*"([^"]+)"\)/g)) { const f = G.files.get(e.split(':').slice(1).join(':')); data[k] = f ? { text: f.bytes.toString(), isBinary: false } : null; }
    return send(200, { data: { repository: data } });
  }
  if (a === '/repos/o/lab') return send(200, { id: 1, full_name: 'o/lab', name: 'lab', owner: { login: 'o', type: 'User', id: 1 }, private: false, visibility: 'public', default_branch: 'main', html_url: 'https://github.com/o/lab', permissions: { admin: true, maintain: true, push: true, triage: true, pull: true } });
  if ((x = /^\/contents\/(.+)$/.exec(r))) {
    const fp = decodeURIComponent(x[1]), f = G.files.get(fp);
    if (m === 'GET') return f ? send(200, { type: 'file', name: fp.split('/').pop(), path: fp, sha: f.sha, size: f.bytes.length, encoding: 'base64', content: f.bytes.toString('base64') }) : send(404, { message: 'Not Found' });
    if (m === 'PUT') { if (f && jb.sha !== f.sha) return send(409, { message: `${fp} does not match ${jb.sha}` }); put(fp, Buffer.from(jb.content, 'base64').toString()); return send(f ? 200 : 201, { content: { path: fp, sha: G.files.get(fp).sha }, commit: { sha: 'abc1234def', html_url: 'https://github.com/o/lab/commit/abc1234def' } }); }
  }
  if (r === '/git/trees/main') {
    const tree = new Map();
    for (const k of G.files.keys()) { const ps = k.split('/'); for (let i = 1; i < ps.length; i++) tree.set(ps.slice(0, i).join('/'), 'tree'); tree.set(k, 'blob'); }
    return send(200, { sha: 'tree', truncated: false, tree: [...tree].map(([path, type]) => ({ path, type, mode: type === 'tree' ? '040000' : '100644' })) });
  }
  if (/^\/actions\/(workflows\/[\w.-]+\/)?runs$/.test(r)) {
    const wf = /workflows\/([\w.-]+)\//.exec(r)?.[1];
    const runs = [runOf(100, 'verify.yml', 'failure'), ...G.dispatched.map((d, i) => runOf(300 + i, d.file, null, 'workflow_dispatch'))].filter((x) => !wf || x.path.endsWith(`/${wf}`)).reverse();
    return send(200, { total_count: runs.length, workflow_runs: runs });
  }
  if (r === '/actions/runs/100/jobs') return send(200, { jobs: [{ id: 1001, name: 'test coins', status: 'completed', conclusion: 'failure', steps: [] }] });
  if (r === '/actions/jobs/1001/logs') return send(302, null, { location: `http://127.0.0.1:${fake.address().port}/blob/log-1001?sig=abc` });
  if ((x = /^\/actions\/workflows\/([\w.-]+)\/dispatches$/.exec(r)) && m === 'POST') { G.dispatched.push({ file: x[1], ...jb }); return send(204, null); }
  if (r === '/actions/workflows') return send(200, { total_count: WFS.length, workflows: WFS });
  if (r === '/actions/secrets/public-key') return send(200, { key_id: 'K1', key: SEAL.toB64(pk) });
  if (r === '/actions/secrets') return send(200, { total_count: G.secrets.size, secrets: [...G.secrets.keys()].map((name) => ({ name, created_at: '2026-10-01T00:00:00Z', updated_at: '2026-10-01T00:00:00Z' })) });
  if ((x = /^\/actions\/secrets\/(\w+)$/.exec(r)) && m === 'PUT') { const had = G.secrets.has(x[1]); G.secrets.set(x[1], jb.encrypted_value); return send(had ? 204 : 201, null); }
  if (r === '/actions/variables') return send(200, { total_count: 0, variables: [] });
  if (/^\/actions\/variables\/\w+$/.test(r)) return send(404, { message: 'Not Found' });
  if (r === '/pages') return send(200, { build_type: 'workflow', html_url: 'http://fake/pages/lab/' });
  if (r === '/releases' || r.startsWith('/issues')) return send(200, []);
  if (a === '/user/installations') return send(200, { total_count: 0, installations: [] });
  if (a === '/apps/lab-o') return send(200, { slug: 'lab-o', permissions: {} });
  return send(404, { message: `Not Found: ${m} ${a}` });
});
await new Promise((r) => fake.listen(0, '127.0.0.1', r));
const F = `http://127.0.0.1:${fake.address().port}`;

// ---- the Worker's files as wrangler sees them in auth/ (copied: wrangler leaves its state there), in workerd ----
const W = fs.mkdtempSync(path.join(os.tmpdir(), 'bds-lab-workerd-'));
fs.cpSync(path.join(TOP, 'auth'), path.join(W, 'auth'), { recursive: true, filter: (s) => !/[\\/](node_modules|\.wrangler)([\\/]|$)/.test(s) });
fs.cpSync(path.join(TOP, 'panel/lib'), path.join(W, 'panel/lib'), { recursive: true });
fs.writeFileSync(path.join(W, 'auth/.dev.vars'), `GITHUB_CLIENT_SECRET=${CLIENT_SECRET}\nSTATE_SECRET=${STATE_SECRET}\n`);
const [port, inspector] = [await freePort(), await freePort()], B = `http://127.0.0.1:${port}`, here = (u) => String(u).replace(SELF, B);
const vars = { GITHUB_CLIENT_ID: CLIENT_ID, PANEL_ORIGINS: `${F}/pages/lab/`, LAB_SLUG: 'o/lab', GITHUB_API: `${F}/api`, GITHUB_WEB: `${F}/web` };
// (--local-upstream: the Worker sees its requests at https://bds-lab-auth.test, as on Cloudflare — an https origin of its own)
const wr = spawn(WRANGLER[0], [...WRANGLER.slice(1), 'dev', '--local', '--ip', '127.0.0.1', '--port', String(port), '--inspector-port', String(inspector), '--local-upstream', new URL(SELF).host, '--upstream-protocol', 'https', '--persist-to', path.join(W, 'state'), '--show-interactive-dev-session=false', ...Object.entries(vars).flatMap(([k, v]) => ['--var', `${k}:${v}`])],
  { cwd: path.join(W, 'auth'), detached: true, env: { ...process.env, WRANGLER_SEND_METRICS: 'false', CI: '1', NO_COLOR: '1', FORCE_COLOR: '0' } });
let out = '';
wr.stdout.on('data', (d) => { out += d; }); wr.stderr.on('data', (d) => { out += d; });
const kill = (sig) => { try { process.kill(-wr.pid, sig); } catch { /* gone */ } };
// (wrangler and its workerd, the whole group: asked to stop, then made to)
const stop = async () => { if (wr.exitCode !== null || wr.signalCode !== null) return; const gone = new Promise((r) => wr.once('exit', r)); kill('SIGTERM'); if (await Promise.race([gone.then(() => true), new Promise((r) => setTimeout(r, 5000, false))])) return; kill('SIGKILL'); await gone; };
process.on('exit', () => kill('SIGKILL'));
let up = false;
for (let i = 0; i < 240 && !up && wr.exitCode === null; i++) { await new Promise((r) => setTimeout(r, 500)); try { up = (await fetch(`${B}/health`)).status > 0; } catch { /* not yet */ } }
if (!up) { console.log(`FAIL wrangler dev did not start\n${out.slice(-3000)}`); await stop(); fake.close(); fs.rmSync(W, { recursive: true, force: true }); process.exit(1); }

const OWN = { authorization: `Bearer ${OWNER}` };
const call = async (tool, args = {}, h = OWN) => { const r = await fetch(`${B}/api/${tool}`, { method: 'POST', headers: { ...h, 'content-type': 'application/json' }, body: JSON.stringify(args) }); return { status: r.status, j: await r.json().catch(() => null) }; };
const show = (x) => JSON.stringify(x).slice(0, 600);

await t('/health: the lab, the App, the device sign-in on (the Durable Object bound)', async () => {
  const h = await (await fetch(`${B}/health`)).json();
  ok(h.ok === true && h.clientId === CLIENT_ID && h.lab === 'o/lab' && h.device === true, show(h));
});
await t('the discovery: /api lists every tool, /, /openapi.json, /llms.txt, the MCP and OAuth metadata at the https origin', async () => {
  const d = await (await fetch(`${B}/api`)).json();
  ok(d.tools.length === 34 && d.mcp === `${SELF}/mcp`, show(d));
  for (const p of ['/', '/openapi.json', '/llms.txt', '/.well-known/oauth-protected-resource/mcp', '/.well-known/oauth-authorization-server']) { const r = await fetch(`${B}${p}`); ok(r.status === 200, `${p}: ${r.status}`); }
  const as = await (await fetch(`${B}/.well-known/oauth-authorization-server`)).json();
  ok(as.issuer === SELF && as.device_authorization_endpoint === `${SELF}/device/code`, show(as));
});
await t('lab_status: GitHub with a User-Agent, the 「準備」 checks — the service\'s own https /health answered inside', async () => {
  const s = await call('lab_status');
  const auth = s.j?.result?.setup?.find((x) => x.key === 'auth');
  ok(s.status === 200 && s.j.result.you.login === 'o' && auth?.ok === true, show(auth ?? s.j));
  ok([...G.agents].every((x) => x.startsWith('bds-lab-api/')), [...G.agents].join(' '));
});
await t('secret_set: sealed with the platform\'s X25519 so GitHub opens it; never in the answer', async () => {
  const s = await call('secret_set', { name: 'MY_KEY', value: 'workerd-secret-value' });
  ok(s.status === 200 && !JSON.stringify(s.j).includes('workerd-secret-value'), show(s.j));
  const sealed = SEAL.fromB64(G.secrets.get('MY_KEY') ?? ''), epk = sealed.subarray(0, 32), both = new Uint8Array(64);
  both.set(epk, 0); both.set(pk, 32);
  const plain = new TextDecoder().decode(SEAL.secretbox(sealed.subarray(48), SEAL.blake2b(both, 24), SEAL.hsalsa20(SEAL.x25519(sk, epk), new Uint8Array(16))).subarray(16));
  ok(plain === 'workerd-secret-value', 'GitHub cannot open it');
});
await t('run_log: the redirect to the log\'s storage followed by hand, without the token; lines numbered, stamps and colours gone', async () => {
  const l = await (await fetch(`${B}/api/run_log?job_id=1001&grep=error&context=0`, { headers: OWN })).json();
  ok(l.ok && l.text === '2: Error: boom' && G.blobAuth.length > 0 && G.blobAuth.every((x) => x === null), show(l) + show(G.blobAuth));
});
await t('units_list: one tree and one GraphQL query', async () => {
  const u = await (await fetch(`${B}/api/units_list`, { headers: OWN })).json();
  const c = u.result?.units?.find((x) => x.name === 'coins');
  ok(u.ok && c?.version === '1.2.0' && c.tests === 2, show(u));
});
await t('file_write: UTF-8 kept; an existing file only over its sha', async () => {
  const w = await call('file_write', { path: 'bds/addons/coins/notes.md', content: 'メモ ✅\n', message: 'notes' });
  ok(w.status === 200 && G.files.get('bds/addons/coins/notes.md')?.bytes.toString() === 'メモ ✅\n', show(w.j));
  const blind = await call('file_write', { path: 'bds/addons/coins/notes.md', content: 'x\n' });
  ok(blind.status === 409, show(blind));
});
await t('workflow_run: dispatched and its new run found (the platform\'s timers)', async () => {
  const w = await call('workflow_run', { workflow: 'verify.yml' });
  ok(w.status === 200 && G.dispatched.length === 1 && w.j.result?.run?.id === 300, show(w.j));
});
await t('MCP: initialize, tools/list, tools/call', async () => {
  const rpc = async (method, params, id = 1) => (await fetch(`${B}/mcp`, { method: 'POST', headers: { ...OWN, 'content-type': 'application/json', accept: 'application/json, text/event-stream' }, body: JSON.stringify({ jsonrpc: '2.0', id, method, params }) })).json();
  const i = await rpc('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'workerd-test', version: '1' } });
  ok(i.result?.protocolVersion === '2025-06-18', show(i));
  ok((await rpc('tools/list', {}, 2)).result.tools.length === 34, 'tools/list');
  const c = await rpc('tools/call', { name: 'units_list', arguments: {} }, 3);
  ok(c.result && !c.result.isError && /coins/.test(c.result.content[0].text), show(c));
});
await t('the device sign-in through the Durable Object: a code, the page, GitHub, the tokens once, then the lab', async () => {
  const d = await (await fetch(`${B}/device/code`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 'client_name=workerd-test' })).json();
  ok(/^[A-Z]{4}-[A-Z]{4}$/.test(d.user_code ?? '') && d.verification_uri_complete === `${SELF}/device?code=${d.user_code}`, show(d));
  const poll = async () => (await fetch(`${B}/token`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:device_code', device_code: d.device_code, client_id: d.client_id }) })).json();
  ok((await poll()).error === 'authorization_pending', 'pending: the store read back');
  const ask = await fetch(here(d.verification_uri_complete)), page = await ask.text();
  const consent = /__Host-bdslab_consent=([^;]+)/.exec(ask.headers.getSetCookie().join('\n'))?.[1];
  ok(ask.status === 200 && page.includes(d.user_code) && consent, `the page: ${ask.status}`);
  const go = await fetch(`${B}/device`, { method: 'POST', redirect: 'manual', headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: `__Host-bdslab_consent=${consent}` }, body: new URLSearchParams({ req: /name="req" value="([^"]+)"/.exec(page)[1], csrf: /name="csrf" value="([^"]+)"/.exec(page)[1] }) });
  const state = /__Host-bdslab_state=([^;]+)/.exec(go.headers.getSetCookie().join('\n'))?.[1];
  ok(go.status === 302 && state && go.headers.get('location').startsWith(`${F}/web/login/oauth/authorize?`), `to GitHub: ${go.status}`);
  const back = (await fetch(go.headers.get('location'), { redirect: 'manual' })).headers.get('location');
  ok(String(back).startsWith(`${SELF}/callback?`), `back to the service's own https address: ${back}`);
  const done = await fetch(here(back), { headers: { cookie: `__Host-bdslab_state=${state}` } });
  ok(done.status === 200 && /AI がつながりました/.test(await done.text()), `the callback: ${done.status}`);
  const tk = await poll();
  ok(/^bdsl_at\./.test(tk.access_token ?? '') && /^bdsl_rt\./.test(tk.refresh_token ?? '') && !JSON.stringify(tk).includes('ghu_'), show(tk));
  ok((await poll()).error === 'expired_token', 'the tokens are handed out once');
  const s = await call('lab_status', {}, { authorization: `Bearer ${tk.access_token}` });
  ok(s.status === 200 && s.j.result.you.via === 'mcp', show(s.j));
  // the end of it (RFC 7009): GitHub's token revoked there, the API then refuses the token
  const rv = async (token) => (await fetch(`${B}/revoke`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ token, client_id: d.client_id }) })).status;
  ok((await rv(tk.access_token)) === 200 && G.revoked.length === 1 && G.revoked[0].startsWith('ghu_'), `revoked on GitHub: ${G.revoked}`);
  ok((await call('lab_status', {}, { authorization: `Bearer ${tk.access_token}` })).status === 401, 'the revoked token refused');
  ok((await rv(tk.refresh_token)) === 200 && G.revoked.length === 2, 'the refresh token: traded once, that token revoked');
});

await stop(); fake.close();
if (fail) console.log(out.slice(-3000));
fs.rmSync(W, { recursive: true, force: true });
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
