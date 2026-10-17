// the lab's API for AI (auth/api.mjs: MCP at /mcp, plain HTTP at /api) and MCP's sign-in (auth/handler.mjs) against a fake
// GitHub (its web flow and its API), with no network: discovery (401 and the metadata), dynamic registration (what redirect
// addresses may be), the consent page (the client by name, escaped; its form bound to a cookie), GitHub and back, the code
// traded with PKCE (wrong verifier, another client, too late: refused), the sealed tokens (no GitHub token anywhere), refresh;
// then every tool through MCP and through /api — the role policy (a denial, a confirmation), the audit log (via mcp), the
// protected files, a secret sealed and never shown, files written over their sha only, logs fetched without the token.
// node tests/api-offline.mjs
import http from 'node:http';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { fakeCheck } from '../panel/lib/ghrules.mjs';

const TOP = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const imp = (p) => import(pathToFileURL(path.join(TOP, p)).href);
const A = await imp('auth/handler.mjs'), API = await imp('auth/api.mjs'), SEAL = await imp('panel/lib/seal.mjs');
let pass = 0, fail = 0;
const t = async (name, fn) => { try { await fn(); pass++; console.log(`ok   ${name}`); } catch (e) { fail++; console.log(`FAIL ${name}\n     ${e.stack?.split('\n').slice(0, 3).join('\n     ') ?? e.message}`); } };
const eq = (a, b, m = '') => { if (JSON.stringify(a) !== JSON.stringify(b)) throw new Error(`${m} want ${JSON.stringify(b)} got ${JSON.stringify(a)}`); };
const ok = (c, m) => { if (!c) throw new Error(m); };
const b64url = (b) => Buffer.from(b).toString('base64url');
const sha256 = (s) => b64url(crypto.createHash('sha256').update(s).digest());

// ---- a fake GitHub: /web (the App's sign-in) and /api (the lab o/lab, private: the audit log is kept) ----
const CLIENT_ID = 'Iv23liFAKECLIENT', CLIENT_SECRET = 'fake-client-secret-0123456789abcdef', STATE_SECRET = 'fake-state-secret-0123456789abcdef-0123456789';
const AUTH = 'https://auth.test', RU = 'https://claude.test/api/mcp/auth_callback';
const TOKENS = { ghp_OwnerToken0123456789abcdefghij: 'o', ghp_WriterToken0123456789abcdefghi: 'w', ghp_ReaderToken0123456789abcdefghi: 'r' };
const sk = crypto.randomBytes(32), pk = SEAL.x25519Public(sk);
const gitSha = (s) => crypto.createHash('sha1').update(s).digest('hex');
const G = {
  codes: new Map(), refreshes: new Set(), n: 0, seen: [], blobAuth: [], graphql: 0, dispatched: [], reruns: [], secrets: new Map(), writes: [],
  files: new Map(), runs: [], jobs: {}, logs: {}, notes: {}, issues: [], labels: new Set(), users: new Set(['o', 'w', 'r', 'newbie']),
  collaborators: [{ login: 'o', permissions: { admin: true, push: true, pull: true } }, { login: 'w', permissions: { push: true, pull: true } }, { login: 'r', permissions: { pull: true } }], invitations: [],
  vars: new Map(Object.entries({ APP_ID: '5', APP_SLUG: 'lab-o', APP_CLIENT_ID: CLIENT_ID, LAB_AUTH_URL: AUTH, APP_CALLBACK_URL: `${AUTH}/callback`, LAB_HOSTS: 'x/host' })),
};
const put = (p, text) => G.files.set(p, { bytes: Buffer.isBuffer(text) ? text : Buffer.from(text), sha: gitSha(`${p}\n${Buffer.isBuffer(text) ? text.toString('base64') : text}\n${Math.random()}`) });
put('AGENTS.md', '# bds-lab\n');
put('bds/addons/coins/bp/manifest.json', JSON.stringify({ format_version: 2, header: { name: 'Coins', description: 'coins for everyone', version: [1, 2, 0] }, modules: [{ type: 'script', entry: 'scripts/main.js' }] }));
put('bds/addons/coins/TASK.md', '# コインのアドオン\n');
put('bds/addons/coins/tests.txt', '## one\nsay hi\n~ hi\n## two\nsay yo\n~ yo\n');
put('bds/addons/coins/src/main.ts', 'import { cmd } from "./kit";\nexport const x = 1;\n');
put('bds/addons/zz_old/TASK.md', '# しまったもの\n');
put('.github/workflows/unit.yml', 'name: unit\n# a unit\non:\n  workflow_dispatch:\n    inputs:\n      job: { type: choice, options: [test, go] }\njobs:\n  run:\n    runs-on: ubuntu-latest\n');
put('tex.png', Buffer.from([0x89, 0x50, 0x4e, 0x47, 0, 1, 2, 3]));
for (const s of ['APP_PRIVATE_KEY', 'APP_CLIENT_SECRET', 'AUTH_STATE_SECRET', 'CLOUDFLARE_API_TOKEN']) G.secrets.set(s, { sealed: 'x', at: '2026-10-01T00:00:00Z' });
const WFS = ['verify.yml', 'unit.yml', 'ai-make.yml', 'pages.yml', 'auth-deploy.yml'].map((f, i) => ({ id: 10 + i, name: f.replace('.yml', ''), path: `.github/workflows/${f}`, state: 'active' }));
const mkRun = (id, file, conclusion, actor = 'o', event = 'push') => ({ id, name: file.replace('.yml', ''), path: `.github/workflows/${file}`, event, status: conclusion ? 'completed' : 'in_progress', conclusion, head_branch: 'main', head_sha: 'abcdef1234567', display_title: `${file} run`, run_number: id - 90, run_attempt: 1, triggering_actor: { login: actor }, actor: { login: actor }, created_at: '2026-10-17T00:00:00Z', updated_at: '2026-10-17T00:05:00Z', html_url: `https://github.com/o/lab/actions/runs/${id}` });
G.runs.push(mkRun(100, 'verify.yml', 'failure'), mkRun(99, 'unit.yml', 'success'));
G.jobs[100] = [{ id: 1001, name: 'test coins', status: 'completed', conclusion: 'failure', started_at: 'x', completed_at: 'y', steps: [{ number: 1, name: 'checkout', status: 'completed', conclusion: 'success' }, { number: 2, name: 'tests', status: 'completed', conclusion: 'failure' }] }];
G.jobs[99] = [{ id: 991, name: 'unit', status: 'completed', conclusion: 'success', steps: [] }];
G.notes[1001] = [{ annotation_level: 'failure', title: 'tests.txt', message: 'expected "hi" but got "ho"', path: 'bds/addons/coins/tests.txt', start_line: 3 }];
G.logs[1001] = ['2026-10-17T00:00:01.1234567Z setting up', '2026-10-17T00:00:02.0000000Z \x1b[31mError: boom\x1b[0m', '2026-10-17T00:00:03.0000000Z after', ...Array.from({ length: 50 }, (_, i) => `2026-10-17T00:01:00.0000000Z line ${i}`)].join('\n') + '\n';

const userOf = (req) => { const a = String(req.headers.authorization ?? ''); const m = /^Bearer (.+)$/.exec(a); return m ? TOKENS[m[1]] ?? null : null; };
const issue = () => { G.n++; const tk = { access_token: `ghu_AccessToken${G.n}xxxxxxxxxxxxxxxxxx`, expires_in: 28800, refresh_token: `ghr_RefreshToken${G.n}xxxxxxxxxxxxxxx`, refresh_token_expires_in: 15811200, token_type: 'bearer', scope: '' }; TOKENS[tk.access_token] = 'o'; G.refreshes.add(tk.refresh_token); return tk; };
const fake = http.createServer(async (req, res) => {
  const body = await new Promise((r) => { let b = ''; req.on('data', (c) => { b += c; }); req.on('end', () => r(b)); });
  const u = new URL(req.url, 'http://fake'), p = u.pathname, m = req.method;
  G.seen.push({ m, p: `${p}${u.search}`, auth: req.headers.authorization ?? null, ua: req.headers['user-agent'] ?? null });
  const send = (status, j, headers = {}) => { res.writeHead(status, { 'content-type': 'application/json', ...headers }); res.end(j === null || j === undefined ? '' : typeof j === 'string' ? j : JSON.stringify(j)); };
  let jb = null; try { jb = body && p.startsWith('/api/') ? JSON.parse(body) : null; } catch { /* not JSON */ }
  if (p.startsWith('/api/') && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(m)) { const bad = fakeCheck(m, p.slice(4) + u.search, jb); if (bad) return send(422, { message: bad.message }); }
  // web: the App's sign-in
  if (m === 'GET' && p === '/web/login/oauth/authorize') {
    const q = u.searchParams, back = new URL(q.get('redirect_uri')), code = `code${crypto.randomBytes(6).toString('hex')}`;
    G.codes.set(code, { challenge: q.get('code_challenge'), redirect: q.get('redirect_uri') });
    back.search = new URLSearchParams({ code, state: q.get('state') }).toString();
    return send(302, null, { location: back.href });
  }
  if (m === 'POST' && p === '/web/login/oauth/access_token') {
    const q = new URLSearchParams(body);
    if (q.get('client_id') !== CLIENT_ID || q.get('client_secret') !== CLIENT_SECRET) return send(200, { error: 'incorrect_client_credentials' });
    if (q.get('grant_type') === 'refresh_token') return G.refreshes.delete(q.get('refresh_token')) ? send(200, issue()) : send(200, { error: 'bad_refresh_token' });
    const c = G.codes.get(q.get('code')); G.codes.delete(q.get('code'));
    if (!c || c.redirect !== q.get('redirect_uri') || c.challenge !== sha256(q.get('code_verifier') ?? '')) return send(200, { error: 'bad_verification_code' });
    return send(200, issue());
  }
  // the log's storage: no token may come here
  if (p.startsWith('/blob/')) { G.blobAuth.push(req.headers.authorization ?? null); return send(200, G.logs[p.split('-').pop()] ?? ''); }
  if (p === '/pages/lab/config.json') return send(200, { authUrl: AUTH, appSlug: 'lab-o', appClientId: CLIENT_ID });
  if (!p.startsWith('/api/')) return send(404, { message: 'Not Found' });
  const who = userOf(req), a = p.slice(4);
  if (!who) return send(401, { message: 'Bad credentials' });
  let x;
  if (a === '/user') return send(200, { login: who, id: who.length });
  if ((x = /^\/users\/([\w-]+)$/.exec(a))) return G.users.has(x[1]) ? send(200, { login: x[1] }) : send(404, { message: 'Not Found' });
  if (a === '/graphql' && m === 'POST') {
    G.graphql++;
    const data = {};
    for (const [, k, expr] of jb.query.matchAll(/(f\d+):object\(expression:"([^"]+)"\)/g)) { const f = G.files.get(expr.split(':').slice(1).join(':')); data[k] = f ? { text: f.bytes.toString('utf8'), isBinary: false } : null; }
    return send(200, { data: { repository: data } });
  }
  if (a === '/apps/lab-o') return send(200, { slug: 'lab-o', permissions: { administration: 'write', actions: 'write', contents: 'write', secrets: 'write', actions_variables: 'write', issues: 'write', workflows: 'write', pages: 'write', pull_requests: 'read', metadata: 'read', members: 'read' } });
  if (a === '/user/installations') return send(200, { installations: [{ id: 7, app_slug: 'lab-o' }] });
  if (a.startsWith('/user/installations/7/repositories')) return send(200, { repositories: [{ full_name: 'o/lab' }] });
  if (!a.startsWith('/repos/o/lab')) return send(404, { message: 'Not Found' });
  const r = a.slice('/repos/o/lab'.length), perm = G.collaborators.find((c) => c.login === who)?.permissions;
  if (!perm) return send(404, { message: 'Not Found' });
  const write = () => perm.push || perm.admin;
  if (r === '' && m === 'GET') return send(200, { id: 22, full_name: 'o/lab', name: 'lab', owner: { login: 'o', type: 'User', id: 1 }, visibility: 'private', private: true, default_branch: 'main', html_url: 'https://github.com/o/lab', permissions: { admin: Boolean(perm.admin), maintain: Boolean(perm.admin), push: Boolean(perm.push), triage: Boolean(perm.push), pull: true } });
  if ((x = /^\/contents\/?(.*)$/.exec(r))) {
    const fp = decodeURIComponent(x[1]);
    if (m === 'GET') {
      const f = G.files.get(fp);
      if (f) return send(200, { type: 'file', name: fp.split('/').pop(), path: fp, sha: f.sha, size: f.bytes.length, encoding: 'base64', content: f.bytes.toString('base64') });
      const kids = [...G.files.keys()].filter((k) => (fp ? k.startsWith(`${fp}/`) : true));
      if (!kids.length) return send(404, { message: 'Not Found' });
      const names = new Map(kids.map((k) => { const rest = fp ? k.slice(fp.length + 1) : k, n = rest.split('/')[0]; return [n, rest.includes('/') ? 'dir' : 'file']; }));
      return send(200, [...names].map(([n, type]) => ({ name: n, path: fp ? `${fp}/${n}` : n, type, size: type === 'file' ? G.files.get(fp ? `${fp}/${n}` : n).bytes.length : 0 })));
    }
    if (!write()) return send(403, { message: 'Resource not accessible' });
    const cur = G.files.get(fp);
    if (m === 'PUT') {
      if (cur && !jb.sha) return send(422, { message: 'Invalid request.\n\n"sha" wasn\'t supplied.' });
      if (cur && jb.sha !== cur.sha) return send(409, { message: `${fp} does not match ${jb.sha}` });
      G.writes.push(fp); put(fp, Buffer.from(jb.content, 'base64'));
      return send(cur ? 200 : 201, { content: { sha: G.files.get(fp).sha, path: fp }, commit: { sha: 'c0ffee1234567', html_url: 'https://github.com/o/lab/commit/c0ffee1' } });
    }
    if (m === 'DELETE') { if (!cur || jb.sha !== cur.sha) return send(409, { message: `${fp} does not match` }); G.files.delete(fp); G.writes.push(`-${fp}`); return send(200, { commit: { sha: 'dead1234567', html_url: 'https://github.com/o/lab/commit/dead' } }); }
  }
  if ((x = /^\/git\/trees\/main$/.exec(r))) {
    const tree = new Map();
    for (const k of G.files.keys()) { const parts = k.split('/'); for (let i = 1; i < parts.length; i++) tree.set(parts.slice(0, i).join('/'), 'tree'); tree.set(k, 'blob'); }
    return send(200, { truncated: false, tree: [...tree].map(([path, type]) => ({ path, type })) });
  }
  if ((x = /^\/actions\/runs\/(\d+)$/.exec(r))) { const run = G.runs.find((y) => String(y.id) === x[1]); return run ? send(200, run) : send(404, { message: 'Not Found' }); }
  if ((x = /^\/actions\/runs\/(\d+)\/jobs$/.exec(r))) return send(200, { jobs: G.jobs[x[1]] ?? [] });
  if ((x = /^\/actions\/runs\/(\d+)\/(rerun|rerun-failed-jobs|cancel)$/.exec(r)) && m === 'POST') { if (!write()) return send(403, { message: 'no' }); G.reruns.push(`${x[2]} ${x[1]}`); return send(201, {}); }
  if ((x = /^\/check-runs\/(\d+)\/annotations$/.exec(r))) return send(200, G.notes[x[1]] ?? []);
  if ((x = /^\/actions\/jobs\/(\d+)\/logs$/.exec(r))) return send(302, null, { location: `http://127.0.0.1:${fake.address().port}/blob/log-${x[1]}` });
  if ((x = /^\/actions\/(?:workflows\/([\w.-]+)\/)?runs$/.exec(r))) {
    let list = G.runs.filter((y) => !x[1] || y.path.endsWith(`/${x[1]}`));
    const st = u.searchParams.get('status'); if (st) list = list.filter((y) => y.status === st || y.conclusion === st);
    return send(200, { workflow_runs: list.slice(0, Number(u.searchParams.get('per_page') ?? 30)) });
  }
  if (r === '/actions/workflows') return send(200, { workflows: WFS });
  if ((x = /^\/actions\/workflows\/([\w.-]+)\/dispatches$/.exec(r)) && m === 'POST') {
    if (!write()) return send(403, { message: 'Must have admin rights to Repository.' });
    G.dispatched.push({ file: x[1], ...jb, by: who });
    G.runs.unshift(mkRun(200 + G.dispatched.length, x[1], null, who, 'workflow_dispatch'));
    return send(204, null);
  }
  if (r === '/actions/secrets/public-key') return send(200, { key_id: 'KID', key: SEAL.toB64(pk) });
  if (r === '/actions/secrets') return send(200, { secrets: [...G.secrets].map(([name, s]) => ({ name, updated_at: s.at })) });
  if ((x = /^\/actions\/secrets\/(\w+)$/.exec(r))) {
    if (!write()) return send(403, { message: 'no' });
    if (m === 'PUT') { G.secrets.set(x[1], { sealed: jb.encrypted_value, at: '2026-10-17T00:00:00Z' }); return send(201, null); }
    if (m === 'DELETE') { G.secrets.delete(x[1]); return send(204, null); }
  }
  if (r.startsWith('/actions/variables')) {
    if ((x = /^\/actions\/variables\/(\w+)$/.exec(r))) {
      if (m === 'GET') return G.vars.has(x[1]) ? send(200, { name: x[1], value: G.vars.get(x[1]) }) : send(404, { message: 'Not Found' });
      if (!write()) return send(403, { message: 'no' });
      if (m === 'PATCH') { if (!G.vars.has(x[1])) return send(404, { message: 'Not Found' }); G.vars.set(x[1], jb.value); return send(204, null); }
      if (m === 'DELETE') { G.vars.delete(x[1]); return send(204, null); }
    }
    if (m === 'POST') { G.vars.set(jb.name, jb.value); return send(201, null); }
    return send(200, { total_count: G.vars.size, variables: [...G.vars].map(([name, value]) => ({ name, value, updated_at: '2026-10-17T00:00:00Z' })) });
  }
  if (r === '/releases') return send(200, [{ tag_name: 'addon-coins', name: 'Coins 1.2.0', draft: false, prerelease: false, published_at: '2026-10-16T00:00:00Z', html_url: 'https://github.com/o/lab/releases/tag/addon-coins', assets: [{ name: 'Coins.mcaddon', size: 1234, download_count: 7, browser_download_url: 'https://github.com/o/lab/releases/download/addon-coins/Coins.mcaddon' }] }]);
  if (/^\/actions(\/runs\/\d+)?\/artifacts$/.test(r)) return send(200, { artifacts: [{ id: 5, name: 'dist', size_in_bytes: 99, expired: false, created_at: 'x', workflow_run: { id: 100 } }] });
  if (r.startsWith('/collaborators') && m === 'GET') return send(200, G.collaborators);
  if (r.startsWith('/invitations') && m === 'GET') return send(200, G.invitations.map((i) => ({ id: i.id, invitee: { login: i.login }, permissions: i.permissions, created_at: 'x' })));
  if ((x = /^\/collaborators\/([\w-]+)$/.exec(r))) {
    if (!perm.admin) return send(403, { message: 'Must have admin rights to Repository.' });
    if (m === 'PUT') { const had = G.collaborators.find((c) => c.login === x[1]); if (had) return send(204, null); G.invitations.push({ id: 60 + G.invitations.length, login: x[1], permissions: jb?.permission ?? 'write' }); return send(201, { id: 60 }); }
    if (m === 'DELETE') { G.collaborators = G.collaborators.filter((c) => c.login !== x[1]); return send(204, null); }
  }
  if ((x = /^\/invitations\/(\d+)$/.exec(r)) && m === 'DELETE') { G.invitations = G.invitations.filter((i) => String(i.id) !== x[1]); return send(204, null); }
  if (r === '/labels' && m === 'POST') { if (G.labels.has(jb.name)) return send(422, { message: 'already_exists' }); G.labels.add(jb.name); return send(201, {}); }
  if (r === '/issues' && m === 'POST') { const n = G.issues.length + 1; G.issues.push({ number: n, title: jb.title, body: jb.body, labels: (jb.labels ?? []).map((name) => ({ name })), state: 'open', comments: [], locked: false, html_url: `https://github.com/o/lab/issues/${n}` }); return send(201, { number: n, html_url: `https://github.com/o/lab/issues/${n}` }); }
  if (r === '/issues' && m === 'GET') { const lab = u.searchParams.get('labels'); return send(200, (Number(u.searchParams.get('page') ?? 1) > 1 ? [] : G.issues.filter((i) => !lab || i.labels.some((l) => l.name === lab)).map((i) => ({ ...i, comments: i.comments.length })))); }
  if ((x = /^\/issues\/(\d+)$/.exec(r))) { const i = G.issues[Number(x[1]) - 1]; if (!i) return send(404, { message: 'Not Found' }); if (m === 'PATCH') { i.state = jb.state ?? i.state; return send(200, {}); } return send(200, { ...i, comments: i.comments.length }); }
  if ((x = /^\/issues\/(\d+)\/lock$/.exec(r)) && m === 'PUT') { G.issues[Number(x[1]) - 1].locked = true; return send(204, null); }
  if ((x = /^\/issues\/(\d+)\/comments$/.exec(r))) {
    const i = G.issues[Number(x[1]) - 1];
    if (m === 'POST') { const c = { id: 900 + i.comments.length, body: jb.body, user: { login: who }, created_at: new Date().toISOString(), updated_at: null, html_url: `https://github.com/o/lab/issues/${x[1]}#c` }; c.updated_at = c.created_at; i.comments.push(c); return send(201, c); }
    return send(200, Number(u.searchParams.get('page') ?? 1) > 1 ? [] : i.comments);
  }
  if (r === '/pages') return send(200, { build_type: 'workflow', html_url: 'https://o.github.io/lab/' });
  send(404, { message: `Not Found ${m} ${a}` });
});
await new Promise((r) => fake.listen(0, '127.0.0.1', r));
const GH = `http://127.0.0.1:${fake.address().port}`;
const ENV = { GITHUB_CLIENT_ID: CLIENT_ID, GITHUB_CLIENT_SECRET: CLIENT_SECRET, STATE_SECRET, PANEL_ORIGINS: `${GH}/pages/lab/`, GITHUB_WEB: `${GH}/web`, GITHUB_API: `${GH}/api`, LAB_SLUG: 'o/lab' };
let clock = Date.parse('2026-10-17T00:00:00Z');
const auth = A.handler(ENV, { now: () => clock }), lab = API.api(ENV, { self: auth, now: () => clock, sleep: async () => {} });
const answers = [];
/** the Worker: the API first, else the sign-in service (worker.mjs) — every answer's text kept */
async function H(url, init = {}) {
  const res = (await lab(new Request(url, init))) ?? (await auth(new Request(url, init)));
  const text = res.status === 204 || res.status === 302 ? '' : await res.text();
  const a = { status: res.status, headers: res.headers, location: res.headers.get('location'), cookies: res.headers.getSetCookie(), text, json: (() => { try { return JSON.parse(text); } catch { return null; } })() };
  answers.push(a);
  return a;
}
const form = (o) => ({ method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(o).toString() });
const jsonPost = (o, headers = {}) => ({ method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(o) });
let AT = null, RT = null, CLIENT = null, nid = 0;
const rpc = async (method, params, token = AT) => H(`${AUTH}/mcp`, jsonPost({ jsonrpc: '2.0', id: ++nid, method, ...(params ? { params } : {}) }, { accept: 'application/json, text/event-stream', authorization: `Bearer ${token}` }));
/** a tool through MCP → { isError, text, meta (the JSON after the summary), raw (the second block) } */
async function tool(name, args = {}, token = AT) {
  const r = await rpc('tools/call', { name, arguments: args }, token);
  ok(r.status === 200 && r.json?.result, `${name}: ${r.status} ${r.text.slice(0, 300)}`);
  const c = r.json.result.content ?? [], first = c[0]?.text ?? '', i = first.indexOf('\n{');
  let meta = null; try { meta = i >= 0 ? JSON.parse(first.slice(i + 1)) : null; } catch { /* a summary alone */ }
  return { isError: Boolean(r.json.result.isError), text: first, meta, raw: c[1]?.text ?? null };
}

await t('discovery: /mcp without a token is 401 with the protected resource\'s metadata; its metadata and the authorization server\'s say where to sign in (S256, dynamic registration)', async () => {
  const r = await H(`${AUTH}/mcp`, jsonPost({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18' } }));
  eq(r.status, 401);
  ok(/resource_metadata="https:\/\/auth\.test\/\.well-known\/oauth-protected-resource"/.test(r.headers.get('www-authenticate')), r.headers.get('www-authenticate'));
  ok(/www-authenticate/.test(r.headers.get('access-control-expose-headers') ?? ''), 'the browser may read why');
  for (const p of ['/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/mcp']) { const m = await H(`${AUTH}${p}`); eq([m.status, m.json.resource, m.json.authorization_servers], [200, `${AUTH}/mcp`, [AUTH]], p); }
  const as = await H(`${AUTH}/.well-known/oauth-authorization-server`);
  eq([as.json.issuer, as.json.authorization_endpoint, as.json.token_endpoint, as.json.registration_endpoint, as.json.code_challenge_methods_supported], [AUTH, `${AUTH}/authorize`, `${AUTH}/token`, `${AUTH}/register`, ['S256']]);
  eq(as.headers.get('access-control-allow-origin'), '*', 'metadata for any client');
  const api = await H(`${AUTH}/api`);
  ok(api.status === 200 && api.json.lab === 'o/lab' && api.json.tools.length >= 30 && api.json.mcp === `${AUTH}/mcp`, `GET /api lists the tools without a token: ${api.text.slice(0, 200)}`);
});

await t('registration: https, http on this machine, a native app\'s scheme — not javascript:, plain http elsewhere, a browser\'s own scheme or none; a confidential client gets a secret it can be checked by', async () => {
  for (const bad of [['javascript:alert(1)'], ['http://evil.test/cb'], [], ['chrome-extension://abc/cb'], ['https://x.test/cb#frag'], ['data:text/html,hi'], ['file:///etc/passwd']]) {
    const r = await H(`${AUTH}/register`, jsonPost({ redirect_uris: bad, client_name: 'x' }));
    eq(r.status, 400, JSON.stringify(bad));
  }
  for (const good of [['http://127.0.0.1:5555/callback'], ['http://localhost:33418/'], ['cursor://anysphere.cursor-retrieval/oauth/callback']]) eq((await H(`${AUTH}/register`, jsonPost({ redirect_uris: good }))).status, 201, JSON.stringify(good));
  const conf = await H(`${AUTH}/register`, jsonPost({ redirect_uris: [RU], token_endpoint_auth_method: 'client_secret_post' }));
  ok(conf.status === 201 && conf.json.client_secret && conf.json.client_secret_expires_at === 0, conf.text);
  eq((await H(`${AUTH}/register`, jsonPost({ redirect_uris: [RU], token_endpoint_auth_method: 'private_key_jwt' }))).status, 400, 'an auth method not offered');
  const r = await H(`${AUTH}/register`, jsonPost({ redirect_uris: [RU], client_name: 'Claude <script>alert(1)</script>', token_endpoint_auth_method: 'none' }));
  ok(r.status === 201 && /^bdsc1\./.test(r.json.client_id) && !r.json.client_secret && r.json.redirect_uris[0] === RU, r.text);
  CLIENT = r.json;
});

const VERIFIER = b64url(crypto.randomBytes(32));
let CODE = null;
await t('authorize: this service\'s own consent page first (the client\'s name escaped, where it returns, the lab) — then its form, bound to a cookie, sends the person to GitHub; GitHub back to /callback: a sealed code to the client\'s address with its state and iss', async () => {
  const q = { response_type: 'code', client_id: CLIENT.client_id, redirect_uri: RU, state: 'st-123', code_challenge: sha256(VERIFIER), code_challenge_method: 'S256', scope: 'lab', resource: `${AUTH}/mcp` };
  // refused before any redirect: a client not signed, an address not registered
  eq((await H(`${AUTH}/authorize?${new URLSearchParams({ ...q, client_id: 'bdsc1.x.y' })}`)).status, 400);
  const wrongRu = await H(`${AUTH}/authorize?${new URLSearchParams({ ...q, redirect_uri: 'https://evil.test/cb' })}`);
  ok(wrongRu.status === 400 && !wrongRu.location, 'never sent to an address the client did not register');
  // refused back to the client: no PKCE, plain PKCE, another resource
  for (const [over, err] of [[{ code_challenge: '' }, 'invalid_request'], [{ code_challenge_method: 'plain' }, 'invalid_request'], [{ resource: 'https://other.test/mcp' }, 'invalid_target'], [{ response_type: 'token' }, 'unsupported_response_type']]) {
    const r = await H(`${AUTH}/authorize?${new URLSearchParams({ ...q, ...over })}`);
    const back = new URL(r.location);
    eq([r.status, `${back.origin}${back.pathname}`, back.searchParams.get('error'), back.searchParams.get('state')], [302, RU, err, 'st-123'], JSON.stringify(over));
  }
  const ask = await H(`${AUTH}/authorize?${new URLSearchParams(q)}`);
  eq(ask.status, 200);
  ok(ask.text.includes('Claude &lt;script&gt;alert(1)&lt;/script&gt;') && !ask.text.includes('<script>alert'), 'the client\'s name is text');
  ok(ask.text.includes('claude.test') && ask.text.includes('o/lab'), 'where it returns and the lab, said');
  const csp = ask.headers.get('content-security-policy');
  ok(/default-src 'none'/.test(csp) && /form-action 'self' http:\/\/127\.0\.0\.1:\d+\/web https:\/\/claude\.test/.test(csp) && /style-src 'nonce-/.test(csp) && !/script-src/.test(csp), csp);
  const nonce = /__Host-bdslab_consent=([^;]+)/.exec(ask.cookies.join('\n'))?.[1], req = /name="req" value="([^"]+)"/.exec(ask.text)?.[1], csrf = /name="csrf" value="([^"]+)"/.exec(ask.text)?.[1];
  ok(nonce && req && csrf && /SameSite=Strict/.test(ask.cookies.join('\n')) && /HttpOnly/.test(ask.cookies.join('\n')), 'a consent cookie and the form\'s values');
  const send = (body, headers = {}) => H(`${AUTH}/authorize`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers }, body: new URLSearchParams(body).toString() });
  // the form from elsewhere, without its cookie, with another CSRF value, or too old: refused
  eq((await send({ req, csrf })).status, 403, 'no consent cookie');
  eq((await send({ req, csrf: `${csrf.slice(0, -2)}AA` }, { cookie: `__Host-bdslab_consent=${nonce}` })).status, 403, 'another CSRF value');
  eq((await send({ req, csrf }, { cookie: `__Host-bdslab_consent=${nonce}`, 'sec-fetch-site': 'cross-site' })).status, 403, 'from another site');
  clock += 11 * 60_000;
  eq((await send({ req, csrf }, { cookie: `__Host-bdslab_consent=${nonce}` })).status, 400, 'older than 10 minutes');
  clock -= 11 * 60_000;
  const yes = await send({ req, csrf }, { cookie: `__Host-bdslab_consent=${nonce}`, 'sec-fetch-site': 'same-origin' });
  eq(yes.status, 302);
  ok(yes.location.startsWith(`${GH}/web/login/oauth/authorize?`) && new URL(yes.location).searchParams.get('code_challenge_method') === 'S256' && new URL(yes.location).searchParams.get('redirect_uri') === `${AUTH}/callback`, yes.location);
  const state = /__Host-bdslab_state=([^;]+)/.exec(yes.cookies.join('\n'))?.[1];
  ok(state && yes.cookies.some((c) => /__Host-bdslab_consent=;/.test(c)), 'the state cookie set, the consent cookie cleared');
  const gh = await fetch(yes.location, { redirect: 'manual' }), cbUrl = gh.headers.get('location');
  // without the browser's state cookie: nobody's sign-in
  const stolen = await H(cbUrl);
  eq(new URL(stolen.location).searchParams.get('error'), 'access_denied', 'the callback without its cookie');
  // the same browser: (GitHub's code was taken by the try above — the fake's codes are once) a new round trip
  const yes2 = await H(`${AUTH}/authorize?${new URLSearchParams(q)}`), n2 = /__Host-bdslab_consent=([^;]+)/.exec(yes2.cookies.join('\n'))[1];
  const go2 = await send({ req: /name="req" value="([^"]+)"/.exec(yes2.text)[1], csrf: /name="csrf" value="([^"]+)"/.exec(yes2.text)[1] }, { cookie: `__Host-bdslab_consent=${n2}` });
  const st2 = /__Host-bdslab_state=([^;]+)/.exec(go2.cookies.join('\n'))[1];
  const cb2 = await fetch(go2.location, { redirect: 'manual' }).then((x) => x.headers.get('location'));
  const back = await H(cb2, { headers: { cookie: `__Host-bdslab_state=${st2}` } });
  const to = new URL(back.location);
  eq([back.status, `${to.origin}${to.pathname}`, to.searchParams.get('state'), to.searchParams.get('iss')], [302, RU, 'st-123', AUTH]);
  CODE = to.searchParams.get('code');
  ok(/^bdsl_cd\./.test(CODE) && !back.location.includes('ghu_'), 'a sealed code: no GitHub token in the address');
});

await t('token: the code traded with its PKCE verifier by the client that asked (another verifier, another client, the code twice as another kind, too late: invalid_grant); sealed tokens, no GitHub token in them; refresh; the code is no access token', async () => {
  const trade = (o) => H(`${AUTH}/token`, form({ grant_type: 'authorization_code', code: CODE, redirect_uri: RU, client_id: CLIENT.client_id, code_verifier: VERIFIER, ...o }));
  eq([(await trade({ code_verifier: b64url(crypto.randomBytes(32)) })).json.error], ['invalid_grant'], 'another verifier');
  const other = await H(`${AUTH}/register`, jsonPost({ redirect_uris: [RU] }));
  eq((await trade({ client_id: other.json.client_id })).json.error, 'invalid_grant', 'another client');
  eq((await trade({ redirect_uri: 'https://claude.test/other' })).json.error, 'invalid_grant', 'another redirect address');
  eq((await trade({ client_id: 'bdsc1.x.y' })).status, 401, 'a client not signed');
  clock += 3 * 60_000;
  eq((await trade({})).json.error, 'invalid_grant', 'two minutes and more after');
  clock -= 3 * 60_000;
  const r = await trade({});
  eq(r.status, 200, r.text);
  ok(/^bdsl_at\./.test(r.json.access_token) && /^bdsl_rt\./.test(r.json.refresh_token) && r.json.token_type === 'Bearer' && r.json.expires_in === 28800 && r.headers.get('cache-control') === 'no-store', r.text);
  ok(!/gh[ur]_/.test(r.text), 'GitHub\'s tokens stay sealed');
  AT = r.json.access_token; RT = r.json.refresh_token;
  eq((await rpc('ping', null, CODE)).status, 401, 'a code is not an access token');
  eq((await rpc('ping', null, RT)).status, 401, 'nor is a refresh token');
  eq((await rpc('ping', null, `${AT.slice(0, -4)}AAAA`)).status, 401, 'an access token altered');
  // refresh: a new pair; the old refresh token (GitHub rotates them) refused
  const rf = await H(`${AUTH}/token`, form({ grant_type: 'refresh_token', refresh_token: RT, client_id: CLIENT.client_id }));
  ok(rf.status === 200 && /^bdsl_at\./.test(rf.json.access_token) && rf.json.refresh_token !== RT, rf.text);
  eq((await H(`${AUTH}/token`, form({ grant_type: 'refresh_token', refresh_token: RT, client_id: CLIENT.client_id }))).json.error, 'invalid_grant', 'the old refresh token');
  eq((await H(`${AUTH}/token`, form({ grant_type: 'refresh_token', refresh_token: rf.json.refresh_token, client_id: other.json.client_id }))).json.error, 'invalid_grant', 'another client\'s refresh');
  eq((await H(`${AUTH}/token`, form({ grant_type: 'password' }))).status, 401, 'no client: invalid_client first');
  AT = rf.json.access_token;
  clock += 9 * 3600_000;
  eq((await rpc('ping')).status, 401, 'past its hours: 401 (the client refreshes)');
  clock -= 9 * 3600_000;
});

await t('MCP: initialize (the version asked for, the lab in the instructions), notifications answered 202, tools/list (every write takes confirm; read-only hints), ping, an unknown method or tool said as JSON-RPC errors, a batch', async () => {
  const init = await rpc('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'test', version: '1' } });
  eq([init.status, init.json.result.protocolVersion, init.json.result.serverInfo.name], [200, '2025-06-18', 'bds-lab']);
  ok(/o\/lab/.test(init.json.result.instructions) && /confirm: true/.test(init.json.result.instructions) && /\.github\//.test(init.json.result.instructions), 'the instructions');
  eq((await rpc('initialize', { protocolVersion: '1999-01-01' })).json.result.protocolVersion, API.MCP_VERSIONS[0], 'an unknown version: the newest');
  const note = await H(`${AUTH}/mcp`, jsonPost({ jsonrpc: '2.0', method: 'notifications/initialized' }, { authorization: `Bearer ${AT}` }));
  eq(note.status, 202);
  const list = await rpc('tools/list');
  const tools = list.json.result.tools, names = tools.map((x) => x.name);
  for (const n of ['lab_status', 'setup_checks', 'setup_fix', 'runs_list', 'run_detail', 'run_log', 'run_rerun', 'run_cancel', 'workflows_list', 'workflow_get', 'workflow_run', 'units_list', 'unit_run', 'unit_new', 'ai_make', 'files_list', 'file_read', 'file_write', 'file_delete', 'secrets_list', 'secret_set', 'secret_delete', 'variables_list', 'variable_set', 'variable_delete', 'releases_list', 'artifacts_list', 'members_list', 'member_set', 'member_remove', 'audit_log', 'issue_from_run', 'schedule_get', 'schedule_set']) ok(names.includes(n), `tool ${n}`);
  ok(tools.every((x) => x.inputSchema.type === 'object' && x.inputSchema.additionalProperties === false && x.description && x.annotations), 'every schema an object, closed, described');
  ok(tools.filter((x) => !x.annotations.readOnlyHint).every((x) => x.inputSchema.properties.confirm?.type === 'boolean'), 'every write takes confirm');
  ok(tools.find((x) => x.name === 'secret_delete').annotations.destructiveHint && tools.find((x) => x.name === 'file_read').annotations.readOnlyHint, 'hints');
  eq((await rpc('ping')).json.result, {});
  eq((await rpc('nope/nope')).json.error.code, -32601);
  eq((await rpc('tools/call', { name: 'nope' })).json.error.code, -32602);
  const batch = await H(`${AUTH}/mcp`, jsonPost([{ jsonrpc: '2.0', id: 'a', method: 'ping' }, { jsonrpc: '2.0', id: 'b', method: 'ping' }], { authorization: `Bearer ${AT}` }));
  eq(batch.json.map((x) => x.id), ['a', 'b']);
  const badArgs = await tool('runs_list', { nope: 1 });
  ok(badArgs.isError && /知らない引数/.test(badArgs.text), badArgs.text);
});

await t('reading: lab_status (who, role, allowed, setup rows, newest runs, failing), runs_list, run_detail (the diagnosis from the failed job\'s annotation), run_log (the log\'s storage reached without the token; timestamps and colours off; grep with context; tail), workflows, units (one tree and one GraphQL query), files, releases, artifacts', async () => {
  const st = await tool('lab_status');
  ok(!st.isError && /o\/lab: o（GitHub admin・役割 admin）/.test(st.text) && /落ちている: verify\.yml/.test(st.text), st.text.slice(0, 400));
  ok(st.meta.you.allowed.includes('secrets.put') && st.meta.policy.audit === 'issue' && Array.isArray(st.meta.setup) && st.meta.setup.find((x) => x.key === 'pages')?.ok === true, JSON.stringify(st.meta).slice(0, 600));
  ok(st.meta.setup.find((x) => x.key === 'auth')?.ok === true, `the service's own /health answered without the network: ${JSON.stringify(st.meta.setup.find((x) => x.key === 'auth'))}`);
  const runs = await tool('runs_list', { workflow: 'verify.yml' });
  ok(runs.meta.runs.length === 1 && runs.meta.runs[0].id === 100 && runs.meta.runs[0].conclusion === 'failure', runs.text);
  const d = await tool('run_detail', { run_id: '100' });
  ok(/📍 どこで/.test(d.text) && d.meta.annotations[0].message.includes('expected "hi"') && d.meta.jobs[0].steps.some((s) => /❌ tests/.test(s)), d.text);
  const log = await tool('run_log', { run_id: 100, grep: 'error', context: 1 });
  ok(log.raw.includes('2: Error: boom') && log.raw.includes('1: setting up') && log.raw.includes('3: after') && !/\d{4}-\d\d-\d\dT/.test(log.raw) && !log.raw.includes('\x1b'), log.raw);
  ok(G.blobAuth.length && G.blobAuth.every((x) => x === null), 'the log\'s storage never sees the token');
  const tail = await tool('run_log', { job_id: 1001, tail: 5 });
  ok(tail.raw.split('\n').length === 5 && tail.raw.endsWith('53: line 49'), tail.raw);
  ok(G.seen.filter((x) => x.p.startsWith('/api/')).every((x) => /^bds-lab-api\//.test(x.ua ?? '')), 'every GitHub call says who it is (User-Agent)');
  const wf = await tool('workflow_get', { workflow: 'unit.yml' });
  ok(wf.meta.dispatchable && wf.raw.includes('workflow_dispatch') && !wf.raw.includes('runs-on'), wf.raw);
  const g0 = G.graphql, units = await tool('units_list');
  const coins = units.meta.units.find((u) => u.name === 'coins');
  ok(coins && coins.title === 'Coins' && coins.version === '1.2.0' && coins.tests === 2 && coins.latest?.file === 'Coins.mcaddon' && !units.meta.units.some((u) => u.name === 'zz_old'), JSON.stringify(units.meta));
  eq(G.graphql - g0, 1, 'one GraphQL query for every unit\'s files');
  ok((await tool('units_list', { q: 'nothing-like-this' })).meta.units.length === 0, 'a search');
  const fl = await tool('files_list', { path: 'bds/addons/coins' });
  ok(fl.meta.entries.some((e) => e.name === 'tests.txt' && e.type === 'file') && fl.meta.entries.some((e) => e.name === 'src' && e.type === 'dir'), fl.text);
  const f = await tool('file_read', { path: 'bds/addons/coins/src/main.ts' });
  ok(f.raw === 'import { cmd } from "./kit";\nexport const x = 1;\n' && f.meta.sha === G.files.get('bds/addons/coins/src/main.ts').sha, `the text as it is, its sha: ${JSON.stringify(f)}`);
  eq((await tool('file_read', { path: 'bds/addons/coins/src/main.ts', from: 2, to: 2 })).raw, 'export const x = 1;');
  const bin = await tool('file_read', { path: 'tex.png' });
  ok(bin.meta.binary && Buffer.from(bin.meta.base64, 'base64').equals(G.files.get('tex.png').bytes), bin.text);
  for (const bad of ['../etc/passwd', 'a/../../b', 'a\\b', '%2e%2e/x']) ok((await tool('file_read', { path: bad })).isError, `refused: ${bad}`);
  ok((await tool('file_read', { path: 'nope.txt' })).isError, 'a file that is not there');
  ok((await tool('releases_list')).meta.releases[0].assets[0].name === 'Coins.mcaddon', 'releases');
  ok((await tool('artifacts_list', { run_id: 100 })).meta.artifacts[0].name === 'dist', 'artifacts');
  ok((await tool('workflows_list')).meta.workflows.some((w) => w.file === 'unit.yml'), 'workflows');
  const sec = await tool('secrets_list');
  ok(sec.meta.secrets.some((s) => s.name === 'APP_PRIVATE_KEY') && !JSON.stringify(sec.meta).includes('sealed'), 'secret names only');
  ok((await tool('variables_list')).meta.variables.some((v) => v.name === 'LAB_HOSTS' && v.value === 'x/host'), 'variables with values');
  ok((await tool('members_list')).meta.members.some((m) => m.login === 'w' && m.permission === 'push'), 'members');
  const sc = await tool('setup_checks');
  ok(sc.meta.checks.length >= 5 && sc.meta.checks.every((x) => 'key' in x && 'ok' in x), sc.text);
});

await t('writing: workflow_run (dispatched with its inputs, the new run found, kept in the audit log as via mcp), unit_run / unit_new checked first, ai_make and AI workflows only with confirm, rerun / cancel', async () => {
  const w = await tool('workflow_run', { workflow: 'unit.yml', inputs: { job: 'test', unit: 'coins', fast: true } });
  ok(!w.isError && w.meta.run?.id && /run \d+/.test(w.text), w.text);
  eq(G.dispatched.at(-1), { file: 'unit.yml', ref: 'main', inputs: { job: 'test', unit: 'coins', fast: 'true' }, by: 'o' }, 'inputs as strings, on the default branch');
  const auditIssue = G.issues.find((i) => i.labels.some((l) => l.name === 'bds-lab-audit'));
  ok(auditIssue && auditIssue.locked && /"via":"mcp"/.test(auditIssue.comments.at(-1).body) && /"workflow":"unit\.yml"/.test(auditIssue.comments.at(-1).body), `audit: ${JSON.stringify(auditIssue?.comments.at(-1))}`);
  ok(w.meta.audit === 'kept', 'the result says it was kept');
  const ai = await tool('workflow_run', { workflow: 'ai-make.yml', inputs: { request: 'x' } });
  ok(ai.isError && /confirm: true/.test(ai.text) && G.dispatched.at(-1).file === 'unit.yml', 'an AI workflow without confirm: nothing started');
  ok((await tool('ai_make', { request: 'ルビーの剣' })).isError, 'ai_make without confirm');
  const aiOk = await tool('ai_make', { request: 'ルビーの剣', confirm: true });
  ok(!aiOk.isError && G.dispatched.at(-1).file === 'ai-make.yml' && G.dispatched.at(-1).inputs.request === 'ルビーの剣', aiOk.text);
  ok((await tool('unit_run', { unit: 'nope' })).isError, 'a unit that is not there');
  ok((await tool('unit_run', { unit: 'coins', job: 'deploy' })).isError, 'a job that is not one');
  const go = await tool('unit_run', { unit: 'coins', job: 'go' });
  ok(!go.isError && JSON.stringify(G.dispatched.at(-1).inputs) === JSON.stringify({ job: 'go', unit: 'coins' }), go.text);
  ok((await tool('unit_new', { unit: 'coins', request: 'x' })).isError, 'a name taken');
  ok((await tool('unit_new', { unit: 'Bad-Name', request: 'x' })).isError, 'a name of another form');
  const nu = await tool('unit_new', { unit: 'ruby_sword', title: 'ルビーの剣', request: '右クリックで火を出す剣' });
  ok(!nu.isError && G.dispatched.at(-1).inputs.job === 'new' && G.dispatched.at(-1).inputs.unit === 'ruby_sword', nu.text);
  await tool('run_rerun', { run_id: 100 });
  await tool('run_rerun', { run_id: 100, failed_only: false });
  await tool('run_cancel', { run_id: 201 });
  eq(G.reruns, ['rerun-failed-jobs 100', 'rerun 100', 'cancel 201']);
});

await t('files: a new file made; one that exists only over the sha read (none: 409 with its sha; a stale one: said, nothing overwritten); manifest.json kept JSON; .github/, auto/STOP, auto/policy.json and .env never; deleted over its sha', async () => {
  const mk = await tool('file_write', { path: 'bds/addons/coins/notes.md', content: '# メモ\n', message: 'メモ' });
  ok(!mk.isError && G.files.get('bds/addons/coins/notes.md').bytes.toString() === '# メモ\n', mk.text);
  const blind = await tool('file_write', { path: 'bds/addons/coins/src/main.ts', content: 'x' });
  ok(blind.isError && blind.text.includes(G.files.get('bds/addons/coins/src/main.ts').sha) && G.files.get('bds/addons/coins/src/main.ts').bytes.toString().startsWith('import'), `blind: ${blind.text}`);
  const stale = await tool('file_write', { path: 'bds/addons/coins/src/main.ts', content: 'x', sha: 'deadbeef' });
  ok(stale.isError && /sha が古い/.test(stale.text), stale.text);
  const read = await tool('file_read', { path: 'bds/addons/coins/src/main.ts' });
  const save = await tool('file_write', { path: 'bds/addons/coins/src/main.ts', content: `${read.raw}export const y = 2;\n`, sha: read.meta.sha });
  ok(!save.isError && G.files.get('bds/addons/coins/src/main.ts').bytes.toString().endsWith('export const y = 2;\n') && save.meta.sha === G.files.get('bds/addons/coins/src/main.ts').sha, save.text);
  const man = await tool('file_read', { path: 'bds/addons/coins/bp/manifest.json' });
  ok((await tool('file_write', { path: 'bds/addons/coins/bp/manifest.json', content: '{ broken', sha: man.meta.sha })).isError, 'a manifest that is no JSON');
  ok((await tool('file_write', { path: 'bds/addons/coins/bp/manifest.json', content: '{"format_version":2}', sha: man.meta.sha })).isError, 'a manifest without its header');
  const before = G.writes.length;
  for (const p of ['.github/workflows/evil.yml', '.github/bds-lab-panel.json', 'auto/STOP', 'auto/policy.json', '.env', 'app/.env.local', '.git/config']) {
    const r = await tool('file_write', { path: p, content: 'x' });
    ok(r.isError, `protected: ${p}`);
  }
  eq(G.writes.length, before, 'nothing written to the protected files');
  const png = await tool('file_write', { path: 'bds/addons/coins/rp/textures/x.png', content_base64: Buffer.from([1, 2, 0, 3]).toString('base64') });
  ok(!png.isError && G.files.get('bds/addons/coins/rp/textures/x.png').bytes.equals(Buffer.from([1, 2, 0, 3])), png.text);
  ok((await tool('file_write', { path: 'a.txt', content: 'x', content_base64: 'eA==' })).isError, 'one of content and content_base64');
  const del = await tool('file_delete', { path: 'bds/addons/coins/notes.md', sha: G.files.get('bds/addons/coins/notes.md').sha });
  ok(!del.isError && !G.files.has('bds/addons/coins/notes.md'), del.text);
  ok((await tool('file_delete', { path: '.github/workflows/unit.yml', sha: 'x' })).isError && G.files.has('.github/workflows/unit.yml'), 'never deleted there either');
});

await t('secrets and variables: a secret sealed with the lab\'s key (GitHub opens it) and never shown; GITHUB_ names refused before sending; deleting asks confirm (the default policy); a variable set with its value before kept for LAB_HOSTS, deleted', async () => {
  const s = await tool('secret_set', { name: 'MY_KEY', value: 's3cr3t-value-0123' });
  ok(!s.isError, s.text);
  const box = SEAL.fromB64(G.secrets.get('MY_KEY').sealed), epk = box.subarray(0, 32), both = new Uint8Array(64); both.set(epk, 0); both.set(pk, 32);
  const k = SEAL.hsalsa20(SEAL.x25519(sk, epk), new Uint8Array(16)), nonce = SEAL.blake2b(both, 24);
  const plain = SEAL.secretbox(box.subarray(48), nonce, k).subarray(16);
  eq(new TextDecoder().decode(plain), 's3cr3t-value-0123', 'GitHub opens it');
  ok(Buffer.from(SEAL.secretbox(plain, nonce, k).subarray(0, 16)).equals(Buffer.from(box.subarray(32, 48))), 'its tag holds');
  ok((await tool('secret_set', { name: 'GITHUB_TOKEN', value: 'x' })).isError && !G.secrets.has('GITHUB_TOKEN'), 'GITHUB_ refused');
  ok((await tool('secret_set', { name: 'lower', value: 'x' })).isError, 'a name of another form');
  const noConfirm = await tool('secret_delete', { name: 'MY_KEY' });
  ok(noConfirm.isError && /confirm: true/.test(noConfirm.text) && G.secrets.has('MY_KEY'), noConfirm.text);
  ok(!(await tool('secret_delete', { name: 'MY_KEY', confirm: true })).isError && !G.secrets.has('MY_KEY'), 'deleted with confirm');
  const v = await tool('variable_set', { name: 'LAB_HOSTS', value: 'x/host,y/host' });
  ok(!v.isError && G.vars.get('LAB_HOSTS') === 'x/host,y/host', v.text);
  const last = G.issues.find((i) => i.labels.some((l) => l.name === 'bds-lab-audit')).comments.at(-1).body;
  ok(/"before":"x\/host"/.test(last) && /"name":"LAB_HOSTS"/.test(last), `the value before, for 取り消す: ${last}`);
  ok(!(await tool('variable_set', { name: 'NEW_ONE', value: '1' })).isError && G.vars.get('NEW_ONE') === '1', 'a new variable made');
  ok(!(await tool('variable_delete', { name: 'NEW_ONE' })).isError && !G.vars.has('NEW_ONE'), 'deleted');
  ok(!answers.some((a) => a.text.includes('s3cr3t-value-0123')), 'the secret\'s value in no answer');
});

await t('members, issues, schedule, audit: the owner and oneself never changed; an invitation; removing asks confirm; an Issue from a failed run once; the timetable checked, over its sha, AI jobs with confirm; the audit log read back (actor, via mcp)', async () => {
  ok((await tool('member_set', { login: 'o', permission: 'pull' })).isError, 'the owner');
  const inv = await tool('member_set', { login: 'newbie', permission: 'push' });
  ok(!inv.isError && G.invitations.some((i) => i.login === 'newbie') && /招待/.test(inv.text), inv.text);
  ok((await tool('member_set', { login: 'ghost-user', permission: 'push' })).isError, 'a user GitHub does not know');
  ok((await tool('member_set', { login: 'w', permission: 'owner' })).isError, 'a role that is not one');
  const rm0 = await tool('member_remove', { login: 'w' });
  ok(rm0.isError && /confirm: true/.test(rm0.text) && G.collaborators.some((c) => c.login === 'w'), rm0.text);
  ok(!(await tool('member_remove', { login: 'newbie', confirm: true })).isError && !G.invitations.some((i) => i.login === 'newbie'), 'an invitation cancelled');
  const i1 = await tool('issue_from_run', { run_id: 100 });
  ok(!i1.isError && /Issue #\d+ を作りました/.test(i1.text), i1.text);
  const i2 = await tool('issue_from_run', { run_id: 100 });
  ok(/前からあったもの/.test(i2.text), 'once per run');
  const s0 = await tool('schedule_get');
  ok(s0.meta.jobs.length === 0 && s0.meta.sha === null, s0.text);
  ok((await tool('schedule_set', { jobs: [{ id: 'v', workflow: 'verify.yml', every: 'sometimes' }] })).isError, 'a timetable that does not check out');
  ok((await tool('schedule_set', { jobs: [{ id: 'ai', workflow: 'ai-make.yml', every: 'day', at: '03:00' }] })).isError, 'an AI job without confirm');
  const set = await tool('schedule_set', { jobs: [{ id: 'v', workflow: 'verify.yml', every: 'day', at: '03:00', timezone: 'Asia/Tokyo' }] });
  ok(!set.isError && G.files.has('.github/bds-lab-schedule.json'), set.text);
  const s1 = await tool('schedule_get');
  ok(s1.meta.jobs[0].when === '毎日 03:00（Asia/Tokyo）' && s1.meta.jobs[0].next.length === 3 && s1.meta.sha, s1.text);
  ok((await tool('schedule_set', { jobs: [] })).isError, 'the file exists: its sha is needed');
  ok(!(await tool('schedule_set', { jobs: [], sha: s1.meta.sha })).isError, 'over its sha');
  const log = await tool('audit_log', { limit: 100 });
  const acts = log.meta.entries.map((e) => e.action);
  for (const a of ['dispatch', 'secrets.put', 'secrets.delete', 'variables', 'members', 'issues', 'run.rerun', 'run.cancel']) ok(acts.includes(a), `audit has ${a}: ${acts.join(' ')}`);
  ok(log.meta.entries.every((e) => e.actor === 'o' && e.detail.via === 'mcp'), 'by the person, via mcp');
});

await t('the role policy and GitHub: a policy that allows a role only to start workflows refuses secrets (in its words, nothing sent); a reader may start nothing; a writer may not change members (GitHub\'s admin); plain HTTP with a GitHub token: 401 without, 200 with, 404 for no such tool, its errors with their status', async () => {
  put('.github/bds-lab-panel.json', JSON.stringify({ roles: { admin: ['dispatch'], write: [], read: [] } }));
  const n = G.secrets.size, s = await tool('secret_set', { name: 'X_KEY', value: 'v' });
  ok(s.isError && /秘密を登録するは、あなたの役割（admin）には許されていません/.test(s.text) && G.secrets.size === n, s.text);
  ok(!(await tool('workflow_run', { workflow: 'verify.yml' })).isError, 'what it allows still goes');
  G.files.delete('.github/bds-lab-panel.json');
  const call = (name, body, token) => H(`${AUTH}/api/${name}`, jsonPost(body ?? {}, token ? { authorization: `Bearer ${token}` } : {}));
  const none = await call('lab_status');
  ok(none.status === 401 && /resource_metadata=/.test(none.headers.get('www-authenticate')), 'no token');
  eq((await call('lab_status', {}, 'not-a-token-at-all-123')).status, 401, 'something that is no token');
  const owner = await call('lab_status', {}, 'ghp_OwnerToken0123456789abcdefghij');
  ok(owner.status === 200 && owner.json.ok && owner.json.result.you.login === 'o' && owner.json.result.you.via === 'token', owner.text.slice(0, 300));
  eq((await call('nope', {}, 'ghp_OwnerToken0123456789abcdefghij')).status, 404);
  eq((await H(`${AUTH}/api/lab_status`, { method: 'POST', headers: { authorization: 'Bearer ghp_OwnerToken0123456789abcdefghij' }, body: '{nope' })).status, 400, 'a body that is no JSON');
  const reader = await call('workflow_run', { workflow: 'verify.yml' }, 'ghp_ReaderToken0123456789abcdefghi');
  ok(reader.status === 403 && /ワークフローを始めるは、あなたの役割（read）には許されていません/.test(reader.json.error), reader.text);
  const writer = await call('member_set', { login: 'newbie', permission: 'pull' }, 'ghp_WriterToken0123456789abcdefghi');
  ok(writer.status === 403 && /メンバーと役割を変える/.test(writer.json.error), writer.text);
  const wsecret = await call('secret_set', { name: 'W_KEY', value: 'v' }, 'ghp_WriterToken0123456789abcdefghi');
  ok(wsecret.status === 200 && G.secrets.has('W_KEY'), `a writer may (the default policy): ${wsecret.text}`);
  const conf = await call('secret_delete', { name: 'W_KEY' }, 'ghp_WriterToken0123456789abcdefghi');
  eq(conf.status, 428, 'a confirmation needed: 428');
  const read = await call('file_read', { path: 'AGENTS.md' }, 'ghp_WriterToken0123456789abcdefghi');
  ok(read.status === 200 && read.json.text === '# bds-lab\n' && read.json.result.sha, read.text);
});

await t('nothing secret in any answer: the client secret, the state secret, GitHub\'s tokens (sealed always), the secret\'s value; every answer no-store', async () => {
  const all = answers.map((a) => `${a.text}\n${a.location ?? ''}\n${a.cookies.join('\n')}`).join('\n');
  ok(!all.includes(CLIENT_SECRET) && !all.includes(STATE_SECRET), 'no service secret');
  ok(!/ghu_AccessToken|ghr_RefreshToken/.test(all), 'no GitHub token');
  ok(!all.includes('s3cr3t-value-0123'), 'no secret value');
  ok(answers.every((a) => /no-store/.test(a.headers.get('cache-control') ?? '')), 'no-store everywhere');
});

await t('a lab without LAB_SLUG: the API says so (503), the sign-in goes on; worker.mjs serves both; the API\'s files use no node: module and import only the panel\'s pure modules', async () => {
  const fs = await import('node:fs');
  const bare = API.api({ ...ENV, LAB_SLUG: '' }, { self: auth });
  const r = await bare(new Request(`${AUTH}/api`));
  eq(r.status, 503);
  eq(await bare(new Request(`${AUTH}/health`)), null, 'not its path: the sign-in service\'s');
  const W = (await imp('auth/worker.mjs')).default;
  const h = await W.fetch(new Request(`${AUTH}/health`), ENV);
  eq([h.status, (await h.json()).lab], [200, 'o/lab']);
  const a = await W.fetch(new Request(`${AUTH}/api`), ENV);
  eq([a.status, (await a.json()).lab], [200, 'o/lab']);
  for (const f of ['auth/api.mjs', 'auth/handler.mjs', 'auth/worker.mjs']) {
    const src = fs.readFileSync(path.join(TOP, f), 'utf8');
    ok(!/from 'node:|require\(/.test(src), `${f}: no node: module`);
    for (const [, spec] of src.matchAll(/^import .* from '([^']+)';$/gm)) ok(/^\.\/(handler|api)\.mjs$|^\.\.\/panel\/lib\/[a-z]+\.mjs$/.test(spec), `${f} imports ${spec}`);
  }
});

await t('the lab\'s Claude plugin (panel/lib/pluginpack.mjs): its MCP server (this lab\'s /mcp over HTTP), a skill and a README in a zip any unzip reads (stored, CRC-32 right, UTF-8 names, the same bytes each time); a wrong address or lab refused; the command line builds the same', async () => {
  const PK = await imp('panel/lib/pluginpack.mjs'), CLI = await imp('common/claude-plugin.mjs');
  const opts = { mcpUrl: 'https://bds-lab-auth.o.workers.dev/mcp', lab: 'o/lab', panelUrl: 'https://o.github.io/lab/' };
  const files = PK.pluginFiles(opts);
  eq(Object.keys(files), ['.claude-plugin/plugin.json', '.mcp.json', 'skills/bds-lab/SKILL.md', 'README.md']);
  eq(JSON.parse(files['.mcp.json']), { mcpServers: { 'bds-lab': { type: 'http', url: opts.mcpUrl } } });
  const man = JSON.parse(files['.claude-plugin/plugin.json']);
  ok(man.name === 'bds-lab' && /^\d+\.\d+\.\d+$/.test(man.version) && man.homepage === opts.panelUrl, JSON.stringify(man));
  ok(/^---\nname: bds-lab\ndescription: .+\n---\n/.test(files['skills/bds-lab/SKILL.md']) && /lab_status/.test(files['skills/bds-lab/SKILL.md']) && /confirm: true/.test(files['skills/bds-lab/SKILL.md']) && /\.github\//.test(files['skills/bds-lab/SKILL.md']), 'the skill: when, how, what never');
  ok(files['skills/bds-lab/SKILL.md'].split(/\s+/).length < 3000, 'a lean skill');
  for (const bad of [{ ...opts, mcpUrl: 'http://x.test/mcp' }, { ...opts, mcpUrl: 'https://x.test/' }, { ...opts, lab: 'nope' }]) { let e = null; try { PK.pluginFiles(bad); } catch (x) { e = x; } ok(e, JSON.stringify(bad)); }
  const z = PK.zip(files), again = PK.zip(PK.pluginFiles(opts));
  ok(Buffer.from(z).equals(Buffer.from(again)), 'the same files, the same bytes');
  // read it back: the central directory's entries, each local file stored with its CRC
  const v = new DataView(z.buffer, z.byteOffset, z.byteLength), end = z.length - 22;
  eq(v.getUint32(end, true), 0x06054b50, 'end of central directory');
  const n = v.getUint16(end + 10, true), cdOff = v.getUint32(end + 16, true), dec = new TextDecoder(), got = {};
  let at = cdOff;
  for (let i = 0; i < n; i++) {
    eq(v.getUint32(at, true), 0x02014b50);
    const nameLen = v.getUint16(at + 28, true), off = v.getUint32(at + 42, true), crc = v.getUint32(at + 16, true), size = v.getUint32(at + 24, true), name = dec.decode(z.subarray(at + 46, at + 46 + nameLen));
    ok(v.getUint16(at + 8, true) & 0x0800, 'UTF-8 names');
    eq([v.getUint32(off, true), v.getUint16(off + 8, true)], [0x04034b50, 0], `${name}: a local header, stored`);
    const data = z.subarray(off + 30 + v.getUint16(off + 26, true), off + 30 + v.getUint16(off + 26, true) + size);
    eq(PK.crc32(data), crc, `${name}: its CRC-32`);
    got[name] = dec.decode(data);
    at += 46 + nameLen;
  }
  eq(got, files, 'every file whole');
  eq(PK.crc32(new TextEncoder().encode('123456789')), 0xcbf43926, 'CRC-32 of the check string');
  eq(CLI.options(['--url', 'https://bds-lab-auth.o.workers.dev', '--lab', 'o/lab']).url, 'https://bds-lab-auth.o.workers.dev/mcp', 'the service\'s address becomes its /mcp');
  eq(CLI.options(['--url', 'https://bds-lab-auth.o.workers.dev/mcp/']).url, 'https://bds-lab-auth.o.workers.dev/mcp');
});

fake.close();
console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
