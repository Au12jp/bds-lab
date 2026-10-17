// the panel's setup without a browser or a network: the GitHub App's manifest (what GitHub makes from it, its permissions),
// where its form goes and the way back (?code= with this tab's state only), storeApp sealing the App's keys into secrets and
// setting its variables with nothing kept (a fake GitHub on node:http that opens what it is sent), every check in each of its
// states with the fix it offers and what that fix asks GitHub (Pages, the App, its installation, the sign-in service, putting
// it on Cloudflare through auth-deploy.yml's notice of this person's own run, the workflows, a lender's link), and the 「準備」
// tab on a small fake DOM (fixes for administrators the policy lets do them only, the App's real form, the code taken out of
// the address before anything else and used only when it can be kept).
// node tests/setup-offline.mjs
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { fakeCheck } from '../panel/lib/ghrules.mjs';

const TOP = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const imp = (p) => import(pathToFileURL(path.join(TOP, p)).href);
const S = await imp('panel/lib/setup.mjs'), G = await imp('panel/lib/gh.mjs'), SEAL = await imp('panel/lib/seal.mjs'), AC = await imp('panel/lib/accounts.mjs');
let pass = 0, fail = 0;
const t = async (name, fn) => { try { await fn(); pass++; console.log(`ok   ${name}`); } catch (e) { fail++; console.log(`FAIL ${name}\n     ${e.stack?.split('\n').slice(0, 3).join('\n     ') ?? e.message}`); } };
const eq = (a, b, m = '') => { if (JSON.stringify(a) !== JSON.stringify(b)) throw new Error(`${m} want ${JSON.stringify(b)} got ${JSON.stringify(a)}`); };
const ok = (c, m) => { if (!c) throw new Error(m); };
const throws = async (fn, re, m) => { let e = null; try { await fn(); } catch (x) { e = x; } ok(e && re.test(e.message), `${m}: ${e?.message ?? 'did not throw'}`); };

// ---- a fake GitHub (and a fake sign-in service under /auth): it keeps what it is sent and opens the sealed secrets ----
const PEM = `-----BEGIN RSA ${'PRIVATE'} KEY-----\nMIIEpAIBAAKCAQEAfakefakefake\n-----END RSA ${'PRIVATE'} KEY-----\n`, // (made at run time: the lab's secret scan reads this file)
  CLIENT_SECRET = 'cs_0123456789abcdef0123456789abcdef01234567';
const CF_TOKEN = 'cf-token-ABCDEFGHIJKLMNOPQRSTUV', CF_ACCOUNT = '0123456789abcdef0123456789abcdef', AUTH_URL = 'https://bds-lab-auth.o.workers.dev';
async function fakeGitHub(init = {}) {
  const sk = crypto.randomBytes(32), pk = SEAL.x25519Public(sk);
  const st = { secrets: new Map(), vars: new Map(Object.entries(init.vars ?? {})), pages: init.pages ?? null, pagesStatus: init.pagesStatus ?? 200, installs: init.installs ?? [], instRepos: init.instRepos ?? {},
    runs: [{ id: 1, status: 'completed', conclusion: 'success', event: 'workflow_dispatch', created_at: '2026-01-01T00:00:00Z' }], deployConclusion: init.deployConclusion ?? 'success', notice: init.notice ?? AUTH_URL,
    health: init.health ?? { ok: true, clientId: 'Iv1.app', origins: ['https://o.github.io'], version: 1 }, seen: [], failSecret: init.failSecret ?? null, log: init.log ?? [], intruders: init.intruders ?? false,
    appPerms: init.appPerms ?? { actions: 'write', contents: 'write', secrets: 'write', actions_variables: 'write', issues: 'write', workflows: 'write', pages: 'write', pull_requests: 'read', metadata: 'read', members: 'read' } };
  const send = (res, code, j) => { res.writeHead(code, { 'content-type': 'application/json' }); res.end(j === null || j === undefined ? '' : JSON.stringify(j)); };
  const srv = http.createServer((req, res) => {
    let b = ''; req.setEncoding('utf8'); req.on('data', (d) => { b += d; });
    req.on('end', () => {
      const u = req.url, m = req.method, body = b ? JSON.parse(b) : null;
      st.seen.push({ m, u, auth: req.headers.authorization ?? null, body: b });
      { const bad = fakeCheck(m, u, body); if (bad) return send(res, 422, { message: bad.message }); } // (GitHub's rules for a write: ghrules)
      let x;
      if (u === '/auth/health') return send(res, st.health === 500 ? 500 : 200, st.health);
      // (the App as GitHub shows it to anyone: one made before administration was asked for)
      if ((x = /^\/apps\/(lab-o(?:-[0-9a-f]{4})?)$/.exec(u))) return send(res, 200, { slug: x[1], permissions: st.appPerms });
      if ((x = /^\/app-manifests\/([\w-]+)\/conversions$/.exec(u)) && m === 'POST') { st.log.push('convert'); return send(res, 201, { id: 4242, slug: 'lab-o', node_id: 'N', client_id: 'Iv1.app', client_secret: CLIENT_SECRET, webhook_secret: null, pem: PEM, html_url: 'https://github.com/apps/lab-o', owner: { login: 'o' }, code: x[1] }); }
      if (u === '/repos/o/lab/actions/secrets/public-key') return send(res, 200, { key_id: 'KID', key: SEAL.toB64(pk) });
      if ((x = /^\/repos\/o\/lab\/actions\/secrets\/(\w+)$/.exec(u)) && m === 'PUT') { if (x[1] === st.failSecret) return send(res, 403, { message: 'Resource not accessible by integration' }); st.secrets.set(x[1], body); return send(res, 201, null); }
      if ((x = /^\/repos\/o\/lab\/actions\/variables\/(\w+)$/.exec(u))) {
        if (m === 'GET') return st.vars.has(x[1]) ? send(res, 200, { name: x[1], value: st.vars.get(x[1]) }) : send(res, 404, { message: 'Not Found' });
        if (m === 'PATCH') { if (!st.vars.has(x[1])) return send(res, 404, { message: 'Not Found' }); st.vars.set(x[1], body.value); return send(res, 204, null); }
      }
      if (u === '/repos/o/lab/actions/variables' && m === 'POST') { st.vars.set(body.name, body.value); return send(res, 201, null); }
      if (u === '/repos/o/lab/pages') {
        if (m === 'GET') return st.pagesStatus !== 200 ? send(res, st.pagesStatus, { message: 'Resource not accessible' }) : st.pages ? send(res, 200, st.pages) : send(res, 404, { message: 'Not Found' });
        if (m === 'POST') { if (st.pages) return send(res, 409, { message: 'already enabled' }); st.pages = { build_type: body.build_type, html_url: 'https://o.github.io/lab/' }; return send(res, 201, st.pages); }
        if (m === 'PUT') { st.pages = { ...st.pages, build_type: body.build_type }; return send(res, 204, null); }
      }
      if ((x = /^\/repos\/o\/lab\/actions\/workflows\/([\w.-]+)\/dispatches$/.exec(u)) && m === 'POST') {
        if (x[1] === 'auth-deploy.yml') {
          st.runs.unshift({ id: 900 + st.runs.length, status: 'queued', conclusion: null, event: 'workflow_dispatch', head_branch: body.ref, actor: { login: 'o' }, triggering_actor: { login: 'o' }, created_at: '2020-01-01T00:00:00Z' });
          // (runs that are not this person's, newer than theirs: a fork's pull request, another branch, someone else)
          if (st.intruders) st.runs.unshift({ id: 7001, status: 'queued', conclusion: null, event: 'pull_request', head_branch: 'main', actor: { login: 'mallory' }, triggering_actor: { login: 'mallory' } },
            { id: 7002, status: 'queued', conclusion: null, event: 'workflow_dispatch', head_branch: 'evil', actor: { login: 'o' }, triggering_actor: { login: 'o' } },
            { id: 7003, status: 'queued', conclusion: null, event: 'workflow_dispatch', head_branch: 'main', actor: { login: 'mallory' }, triggering_actor: { login: 'mallory' } });
        }
        return send(res, 204, null);
      }
      if (/^\/repos\/o\/lab\/actions\/workflows\/auth-deploy\.yml\/runs\?/.test(u)) {
        const out = st.runs.map((r) => ({ ...r }));
        // (each look moves a new run on: queued → in_progress → completed)
        for (const r of st.runs) if (r.status === 'queued') r.status = 'in_progress'; else if (r.status === 'in_progress') { r.status = 'completed'; r.conclusion = st.deployConclusion; }
        return send(res, 200, { workflow_runs: out });
      }
      if ((x = /^\/repos\/o\/lab\/actions\/runs\/(\d+)\/jobs\?/.exec(u))) return send(res, 200, { jobs: [{ name: 'deploy', check_run_url: `https://api.github.com/repos/o/lab/check-runs/${x[1]}1` }] });
      if ((x = /^\/repos\/o\/lab\/check-runs\/(\d+)\/annotations\?/.exec(u)) && st.failWhy && st.deployConclusion !== 'success') return send(res, 200, [{ annotation_level: 'failure', title: 'auth-deploy', message: st.failWhy }]);
      if ((x = /^\/repos\/o\/lab\/check-runs\/(\d+)\/annotations\?/.exec(u))) return send(res, 200, /^700\d1$/.test(x[1]) ? [{ annotation_level: 'notice', title: 'auth-url', message: 'https://evil.example' }] : st.notice ? [{ annotation_level: 'warning', title: 'auth-url', message: 'https://wrong.example' }, { annotation_level: 'notice', title: 'auth-url', message: ` ${st.notice}/ ` }, { annotation_level: 'notice', title: 'auth-plan', message: st.notice }] : []);
      if (u === '/user/installations?per_page=100') return send(res, 200, { total_count: st.installs.length, installations: st.installs });
      if ((x = /^\/user\/installations\/(\d+)\/repositories\?per_page=100&page=1$/.exec(u))) return send(res, 200, { repositories: (st.instRepos[x[1]] ?? []).map((full_name) => ({ full_name })) });
      send(res, 404, { message: `Not Found ${m} ${u}` });
    });
  }).listen(0, '127.0.0.1');
  await new Promise((r) => srv.once('listening', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  /** a sealed secret opened as GitHub's Actions would: crypto_box_seal_open with the repository's secret key */
  const open = (name) => {
    const s = SEAL.fromB64(st.secrets.get(name).encrypted_value), epk = s.subarray(0, 32), nonce = SEAL.blake2b(Buffer.concat([epk, pk]), 24), k = SEAL.hsalsa20(SEAL.x25519(sk, epk), new Uint8Array(16));
    const pt = SEAL.secretbox(s.subarray(48), nonce, k).subarray(16);
    ok(Buffer.from(SEAL.secretbox(pt, nonce, k)).equals(Buffer.from(s.subarray(32))), `${name}: its tag holds`);
    return new TextDecoder().decode(pt);
  };
  return { st, base, open, close: () => srv.close(), api: G.gh({ token: 'ghu_usertoken0123456789', base }), fetchImpl: (url, o) => fetch(String(url).replace(/^https:\/\/auth\.test/, `${base}/auth`), o) };
}
const WF = ['pages.yml', 'auth-deploy.yml', 'hostrun.yml', 'secrets.yml'].map((f) => ({ path: `.github/workflows/${f}` }));
const LAB = (over = {}) => ({ slug: 'o/lab', role: 'admin', repo: { default_branch: 'main', visibility: 'private', owner: { login: 'o', type: 'User' }, permissions: { admin: true } }, secrets: [], workflows: WF, ...over });
const byKey = (cs) => Object.fromEntries(cs.map((c) => [c.key, c]));
const QUICK = { sleep: async () => {}, every: 1, timeoutMs: 50 };

await t('the App\'s manifest: no webhook, no events, public (a lender puts it on their own account), its way back to the panel and its sign-in to the service; the permissions the panel and the workflows use and no more (pure)', () => {
  eq(S.APP_PERMISSIONS, { administration: 'write', actions: 'write', contents: 'write', secrets: 'write', actions_variables: 'write', issues: 'write', workflows: 'write', pages: 'write', pull_requests: 'read', metadata: 'read', members: 'read' }, 'members: read, an organization\'s teams for the policy; administration: a lending fork\'s whole say given to the lab\'s owner');
  // (an App made before asks its owner to add what is new: what GitHub's App lacks, write covering read)
  eq(S.appMissing({ actions: 'write', contents: 'write', secrets: 'write', actions_variables: 'write', issues: 'write', workflows: 'write', pages: 'write', pull_requests: 'write', metadata: 'read', members: 'read' }), [['administration', 'write']]);
  eq(S.appMissing({ ...S.APP_PERMISSIONS }), []); eq(S.appMissing(null).length, Object.keys(S.APP_PERMISSIONS).length);
  ok(Object.isFrozen(S.APP_PERMISSIONS), 'one constant, not changed by anyone');
  const m = S.appManifest({ owner: 'aokiJP', repo: 'bds-lab', panelUrl: 'https://aokijp.github.io/bds-lab/#runs', authUrl: 'https://bds-lab-auth.aoki.workers.dev/' });
  eq(m, { name: 'bds-lab-aokiJP', url: 'https://aokijp.github.io/bds-lab/', hook_attributes: { url: 'https://aokijp.github.io/bds-lab/', active: false }, redirect_url: 'https://aokijp.github.io/bds-lab/', callback_urls: ['https://bds-lab-auth.aoki.workers.dev/callback'], setup_url: 'https://aokijp.github.io/bds-lab/',
    public: true, default_permissions: S.APP_PERMISSIONS, default_events: [], request_oauth_on_install: false });
  // (GitHub refuses a #fragment in the ways back: 「redirect_url must be a valid URL」)
  ok(![m.url, m.redirect_url, m.setup_url, m.hook_attributes.url, ...m.callback_urls].some((u) => u.includes('#')), 'no #fragment in any address of the manifest');
  for (const k of ['organization_administration', 'emails', 'checks']) ok(!(k in m.default_permissions), `no ${k}`);
  ok(m.default_permissions.administration === 'write', 'administration: the repositories it is put on (a lending fork, the lab), nothing of the account');
  eq(m.default_permissions.members, 'read', 'teams read, never written');
  eq(S.appManifest({ owner: 'o', repo: 'lab', panelUrl: 'https://o.github.io/lab/' }).callback_urls, [], 'no service yet: no callback (the check \'callback\' says to set it)');
  eq(S.appManifest({ owner: 'o', repo: 'lab', panelUrl: 'https://o.github.io/lab/', authUrl: 'http://plain.example' }).callback_urls, [], 'only an https service');
  eq(S.appManifest({ owner: 'o', repo: 'lab', panelUrl: 'https://o.github.io/lab/', authUrl: 'https://example.com/auth' }).callback_urls, [], 'a service under a path: none (it answers at its origin\'s /callback)');
  // the service's address: the root of an https origin only (the panel signs in at <origin>/…, the service's redirect_uri is <origin>/callback)
  eq(['https://auth.example', 'https://auth.example/', 'https://auth.example:8443', ' https://a-b.workers.dev// '].map(S.cleanAuthUrl), ['https://auth.example', 'https://auth.example', 'https://auth.example:8443', 'https://a-b.workers.dev']);
  eq(['https://example.com/auth', 'https://example.com/auth/', 'https://x.example/?a=1', 'https://x.example/#h', 'http://x.example', 'javascript:alert(1)', 'https://user@x.example', ''].map(S.cleanAuthUrl), Array(8).fill(null));
  ok(S.appManifest({ owner: 'a-very-long-organization-name-x', repo: 'bds-lab', panelUrl: 'https://x.github.io/y/' }).name.length <= 34, 'a name GitHub takes (34 at most)');
  eq(S.appManifest({ owner: 'o', repo: 'lab', panelUrl: 'https://o.github.io/lab/', name: 'Our <lab>' }).name, 'Our -lab', 'a given name, made safe');
  ok(S.appManifest({ owner: 'o', repo: 'lab', panelUrl: 'https://o.github.io/lab/' }).default_permissions !== S.APP_PERMISSIONS, 'a copy: the constant stays as it is');
});

await t('the form goes to GitHub alone (the person\'s account or the organization\'s) with a state; the way back is taken only with this tab\'s state (pure)', () => {
  eq(S.manifestAction('o', false, 'abc123'), 'https://github.com/settings/apps/new?state=abc123');
  eq(S.manifestAction('acme-inc', true, 'abc123'), 'https://github.com/organizations/acme-inc/settings/apps/new?state=abc123');
  eq(S.manifestAction('o', false, 'a&b=c'), 'https://github.com/settings/apps/new?state=a%26b%3Dc', 'the state cannot add a parameter');
  let threw = false; try { S.manifestAction('../evil', true, 's'); } catch { threw = true; }
  ok(threw, 'an organization name GitHub would not give: no address');
  const st = S.newState((n) => new Uint8Array(n).fill(171));
  eq(st, 'ab'.repeat(16)); const [s1, s2] = [S.newState(), S.newState()];
  ok(/^[0-9a-f]{32}$/.test(s1) && s1 !== s2, 'random, 16 bytes');
  eq(S.takeManifestCode('?code=0a1b2c3d&state=s1', 's1'), { code: '0a1b2c3d', state: 's1' });
  eq(S.takeManifestCode('#setup?code=0a1b2c3d&state=s1', 's1'), { code: '0a1b2c3d', state: 's1' }, 'GitHub may put it after the #');
  eq(S.takeManifestCode('?code=0a1b2c3d&state=other', 's1'), null, 'another state: not this tab\'s');
  eq(S.takeManifestCode('?code=0a1b2c3d', 's1'), null, 'no state');
  eq(S.takeManifestCode('?code=0a1b2c3d&state=', ''), null, 'no state kept: nothing taken');
  eq(S.takeManifestCode('?code=..%2Fx&state=s1', 's1'), null, 'a code of another form');
  eq(S.takeManifestCode('', 's1'), null);
});

await t('storeApp: the App\'s private key, client secret and a new 48-byte state secret sealed into secrets on the spot (GitHub opens them), its id, slug and client id in variables; the keys wiped, none in an address or the answer (fake GitHub)', async () => {
  const f = await fakeGitHub();
  try {
    const conv = await f.api.appFromManifest('c0dec0de');
    const asked = f.st.seen.find((s) => /conversions/.test(s.u));
    ok(asked.m === 'POST' && asked.auth === null, `the code alone, without the person's token: ${JSON.stringify(asked)}`);
    const rnd = new Uint8Array(48).map((_, i) => i * 5 + 1);
    let given = null;
    const r = await S.storeApp(f.api, 'o/lab', conv, { random: (n) => { eq(n, 48); given = rnd; return rnd; } });
    eq(r, { id: 4242, slug: 'lab-o', clientId: 'Iv1.app', owner: 'o', url: 'https://github.com/apps/lab-o', secrets: ['APP_PRIVATE_KEY', 'APP_CLIENT_SECRET', 'AUTH_STATE_SECRET'], variables: ['APP_ID', 'APP_SLUG', 'APP_CLIENT_ID', 'APP_CALLBACK_URL'] });
    eq(f.st.vars.get('APP_CALLBACK_URL'), 'none', 'made with no Callback URL: kept as none (the lab then knows to make it again)');
    eq([f.open('APP_PRIVATE_KEY'), f.open('APP_CLIENT_SECRET')], [PEM, CLIENT_SECRET], 'GitHub (the key\'s owner) opens them');
    const state = f.open('AUTH_STATE_SECRET');
    eq(state, Buffer.from(new Uint8Array(48).map((_, i) => i * 5 + 1)).toString('base64url'), 'the state secret: the 48 random bytes, base64url');
    ok(state.length === 64 && given.every((b) => b === 0), 'long enough for the service (32+), its bytes wiped');
    eq(Object.fromEntries(f.st.vars), { APP_ID: '4242', APP_SLUG: 'lab-o', APP_CLIENT_ID: 'Iv1.app', APP_CALLBACK_URL: 'none' });
    eq([conv.pem, conv.client_secret, conv.webhook_secret], [undefined, undefined, undefined], 'the answer\'s keys wiped');
    const wire = f.st.seen.map((s) => `${s.u} ${s.body}`).join('\n');
    ok(!wire.includes('MIIEpAIBAAKCAQEAfakefakefake') && !wire.includes(CLIENT_SECRET) && !wire.includes(state), 'no key travels plain');
    ok(!f.st.seen.some((s) => /APP_PRIVATE_KEY.*BEGIN|cs_|state=/.test(s.u)), 'none in an address');
    ok(!JSON.stringify(r).includes('BEGIN') && !JSON.stringify(r).includes(CLIENT_SECRET), 'none in the answer');
    // (GitHub refusing one: the App is there, said so; the keys wiped all the same)
    const g = await fakeGitHub({ failSecret: 'APP_CLIENT_SECRET' });
    const conv2 = await g.api.appFromManifest('c0de2');
    await throws(() => S.storeApp(g.api, 'o/lab', conv2), /権限がありません[\s\S]*App lab-o はできています[\s\S]*APP_PRIVATE_KEY/, 'a refusal');
    ok(conv2.pem === undefined && conv2.client_secret === undefined, 'wiped after a refusal too');
    g.close();
    await throws(() => S.storeApp(f.api, 'o/lab', { id: 1, slug: 'x', client_id: 'c' }), /鍵がありません/, 'an answer without the keys');
    await throws(() => S.storeApp(f.api, '../x', { id: 1 }), /owner\/名前/, 'a lab GitHub would not name');
  } finally { f.close(); }
});

await t('checks, a new lab: Pages off (its fix turns it on built by pages.yml), no App (its form), no service (an address of one\'s own, or Cloudflare once the App is there), workflows on a person\'s token, a lender\'s link waits for the App (fake GitHub)', async () => {
  const f = await fakeGitHub();
  try {
    const ctx = { api: f.api, lab: LAB(), hosts: [{ slug: 'lender/host' }, { slug: 'bad slug' }], config: {}, panelUrl: 'https://o.github.io/lab/', signedInWithApp: false, fetchImpl: f.fetchImpl };
    const cs = await S.checks(ctx), c = byKey(cs);
    eq(cs.map((x) => x.key), ['pages', 'app', 'installed', 'deploy', 'workflows', 'host:lender/host'], 'in the order to do them (one row for the sign-in service); a host that is not owner/repo is left out');
    eq(cs.map((x) => x.ok), [false, false, false, false, false, false]);
    ok(cs.every((x) => typeof x.label === 'string' && x.label && x.need), 'each says what is missing');
    ok(c.app.fix.manifest === true && /1 回のクリック/.test(c.app.need), JSON.stringify(c.app));
    const up = /まず上の「GitHub App」の行で App を作ります/;
    ok(up.test(c.installed.need) && up.test(c['host:lender/host'].need), 'what needs the App says so, and where to make it');
    // the sign-in service: Cloudflare's own token page with everything chosen, one field (the token), even before the App
    ok(c.deploy.fix.help.link === S.cfTokenUrl() && /^https:\/\/dash\.cloudflare\.com\/profile\/api-tokens\?permissionGroupKeys=/.test(c.deploy.fix.help.link) && c.deploy.fix.inputs.map((i) => i.name).join() === 'token' && c.deploy.fix.auto === true, JSON.stringify(c.deploy.fix));
    ok(JSON.parse(new URL(S.cfTokenUrl()).searchParams.get('permissionGroupKeys')).map((k) => `${k.key}:${k.type}`).join() === 'workers_scripts:edit,account_settings:read', 'what the token may do: put Workers in place, find the account');
    ok(/APP_ID（変数）・APP_PRIVATE_KEY（秘密）/.test(c.workflows.need) && /LAB_HOST_TOKEN・LAB_SECRETS_TOKEN は要りません/.test(c.workflows.need), c.workflows.need);
    // Pages turned on, built by a workflow, pages.yml started
    const msg = await c.pages.fix.run();
    ok(/Pages を有効にしました（pages.yml/.test(msg), msg);
    const post = f.st.seen.find((s) => s.m === 'POST' && s.u === '/repos/o/lab/pages');
    eq(JSON.parse(post.body), { build_type: 'workflow' });
    ok(f.st.seen.some((s) => s.m === 'POST' && s.u === '/repos/o/lab/actions/workflows/pages.yml/dispatches' && JSON.parse(s.body).ref === 'main'), 'pages.yml started on the default branch');
    eq(byKey(await S.checks(ctx)).pages.ok, true, 'and then it is there');
    // the service: an address of one's own (https only) → LAB_AUTH_URL, pages.yml to hand it to the page (folded under the
    // Cloudflare row: 「自分のサーバーに置いたとき」)
    c.auth = { fix: c.deploy.fix.alt, need: 'サービスは origin の / に（auth/README.md）' };
    eq(c.auth.fix.inputs.map((i) => i.name), ['url']);
    await throws(() => c.auth.fix.run({ url: 'http://plain.example' }), /https:\/\//, 'not https');
    await throws(() => c.auth.fix.run({ url: 'https://x.example/?a=1' }), /https:\/\//, 'a query');
    await throws(() => c.auth.fix.run({ url: 'https://example.com/auth' }), /origin の \/ に（auth\/README\.md）/, 'a path: the service is at its origin\'s /');
    ok(!f.st.vars.has('LAB_AUTH_URL'), 'nothing set for a wrong one');
    ok(/サービスは origin の \/ に（auth\/README\.md）/.test(c.auth.need), c.auth.need);
    eq([c.pages.fix.needs, c.auth.fix.needs, c.app.fix.needs], [['dispatch'], ['variables', 'dispatch'], ['secrets.put', 'variables']], 'each fix says what it does, in the policy\'s words');
    ok(/LAB_AUTH_URL を https:\/\/auth\.mine\.example にしました/.test(await c.auth.fix.run({ url: 'https://auth.mine.example/' })), 'the slash trimmed');
    eq(f.st.vars.get('LAB_AUTH_URL'), 'https://auth.mine.example');
    const later = byKey(await S.checks(ctx));
    ok(later.auth.ok === false && /まだありません: pages\.yml をもう一度/.test(later.auth.need) && /pages\.yml/.test(later.auth.fix.label) && !later.deploy, 'the variable set, the page not built yet: pages.yml again; no Cloudflare step');
  } finally { f.close(); }
});

await t('checks, the App made: it is there; installed (only an App\'s sign-in can tell: a token gets null and a link), a lender\'s install link; workflows on the App\'s token; the callback URL to look at (fake GitHub)', async () => {
  const vars = { APP_ID: '4242', APP_SLUG: 'lab-o', APP_CLIENT_ID: 'Iv1.app' };
  const f = await fakeGitHub({ vars, pages: { build_type: 'workflow' }, installs: [{ id: 7, app_slug: 'lab-o' }, { id: 8, app_slug: 'someone-else' }], instRepos: { 7: ['o/lab', 'Lender/Host'], 8: ['o/other'] } });
  try {
    const lab = LAB({ secrets: ['APP_PRIVATE_KEY', 'APP_CLIENT_SECRET', 'AUTH_STATE_SECRET'] });
    const base = { api: f.api, lab, hosts: [{ slug: 'lender/host' }, { slug: 'friend/host2' }], config: { authUrl: 'https://auth.test' }, panelUrl: 'https://o.github.io/lab/', fetchImpl: f.fetchImpl };
    const tok = byKey(await S.checks({ ...base, signedInWithApp: false }));
    ok(tok.app.ok === true && /lab-o/.test(tok.app.label), JSON.stringify(tok.app));
    ok(tok.installed.ok === null && tok.installed.need === 'App でサインインすると分かります' && tok.installed.fix.link === 'https://github.com/apps/lab-o/installations/new', JSON.stringify(tok.installed));
    ok(!f.st.seen.some((s) => s.u.startsWith('/user/installations')), 'a token: installations not asked');
    ok(tok['host:lender/host'].ok === null && tok['host:lender/host'].fix.link === 'https://github.com/apps/lab-o/installations/new' && /貸し手/.test(tok['host:lender/host'].fix.label), JSON.stringify(tok['host:lender/host']));
    ok(/Only select repositories」でホストのリポジトリだけ/.test(tok['host:lender/host'].need) && /contents・actions・workflows だけ（hostrun）/.test(tok['host:lender/host'].need), `the lender told to give it the host alone: ${tok['host:lender/host'].need}`);
    ok(tok.workflows.ok === true && tok.workflows.need === '', 'APP_ID and APP_PRIVATE_KEY: no personal token for hostrun or secrets');
    ok(tok.callback.ok === null && /https:\/\/auth\.test\/callback/.test(tok.callback.need) && tok.callback.fix.manifest === true && tok.callback.fix.remake === true, JSON.stringify(tok.callback));
    // (the lab keeps the Callback URL the App was made with: known without anyone looking)
    f.st.vars.set('APP_CALLBACK_URL', 'https://auth.test/callback');
    eq(byKey(await S.checks({ ...base, signedInWithApp: false })).callback.ok, true, 'made with this service\'s: ✅');
    f.st.vars.set('APP_CALLBACK_URL', 'none');
    const none = byKey(await S.checks({ ...base, signedInWithApp: false })).callback;
    ok(none.ok === false && /別の Callback URL（なし）/.test(none.need) && none.fix.remake, JSON.stringify(none));
    f.st.vars.delete('APP_CALLBACK_URL');
    // (an App made before administration was asked for: what to add, and where on GitHub)
    ok(tok['app-perms'].ok === false && /administration: write/.test(tok['app-perms'].need) && tok['app-perms'].fix.link === 'https://github.com/settings/apps/lab-o/permissions', JSON.stringify(tok['app-perms']));
    f.st.appPerms = { ...S.APP_PERMISSIONS };
    eq(byKey(await S.checks({ ...base, signedInWithApp: false }))['app-perms'].ok, true, 'all there: ok');
    const app = byKey(await S.checks({ ...base, signedInWithApp: true }));
    eq([app.installed.ok, app['host:lender/host'].ok, app['host:friend/host2'].ok, app.callback.ok], [true, true, false, true], 'this App\'s installations only; any case');
    ok(/Only select repositories/.test(app['host:friend/host2'].need), app['host:friend/host2'].need);
    ok(!f.st.seen.some((s) => s.u.startsWith('/user/installations/8/')), 'another App\'s installation not read');
    // the lab not among them
    f.st.instRepos[7] = ['Lender/Host'];
    const other = byKey(await S.checks({ ...base, signedInWithApp: true }));
    ok(other.installed.ok === false && /o\/lab に App が入っていません/.test(other.installed.need) && other.installed.fix.link, JSON.stringify(other.installed));
    f.st.instRepos[7] = ['o/lab', 'Lender/Host'];
    // an organization's App: its settings under the organization
    const org = byKey(await S.checks({ ...base, lab: { ...lab, repo: { ...lab.repo, owner: { login: 'acme', type: 'Organization' } } } }));
    eq(org.workflows.ok === true || org['app-perms'].fix.link, true, 'an organization\'s App read');
    ok(/organizations\/acme\/settings\/apps\/lab-o/.test(org['app-perms'].fix.link), org['app-perms'].fix.link);
    // the private key gone: its settings to make another
    const nokey = byKey(await S.checks({ ...base, lab: { ...lab, secrets: [] } }));
    ok(nokey.workflows.ok === false && /APP_PRIVATE_KEY（秘密）/.test(nokey.workflows.need) && /作り直し/.test(nokey.workflows.need) && nokey.workflows.fix.link === 'https://github.com/settings/apps/lab-o', nokey.workflows.need);
    eq(byKey(await S.checks({ ...base, lab: { ...lab, secrets: null } })).workflows.ok, null, 'secrets not visible: cannot tell');
  } finally { f.close(); }
});

await t('checks, the sign-in service: answering with this App\'s client id for this panel\'s origin; not answering, another client id, another origin, an old address in the page — each with its fix (fake service)', async () => {
  const vars = { APP_ID: '4242', APP_SLUG: 'lab-o', APP_CLIENT_ID: 'Iv1.app' };
  const run = async (init, over = {}) => {
    const f = await fakeGitHub({ vars, pages: { build_type: 'workflow' }, ...init });
    try { return { c: byKey(await S.checks({ api: f.api, lab: LAB({ secrets: ['APP_PRIVATE_KEY', 'APP_CLIENT_SECRET', 'AUTH_STATE_SECRET', ...(over.cf ? ['CLOUDFLARE_API_TOKEN', 'CLOUDFLARE_ACCOUNT_ID'] : [])] }), config: { authUrl: 'https://auth.test/' }, panelUrl: 'https://o.github.io/lab/#setup', fetchImpl: f.fetchImpl, ...over.ctx })), f }; } finally { f.close(); }
  };
  const good = await run({});
  ok(good.c.auth.ok === true && good.c.auth.label.includes('https://auth.test') && !good.c.deploy, `answering: ${JSON.stringify(good.c.auth)}`);
  ok(good.f.st.seen.some((s) => s.u === '/auth/health' && s.auth === null), 'the service asked without the token');
  const other = await run({ health: { ok: true, clientId: 'Iv1.someone', origins: ['https://o.github.io'] } }, { cf: true });
  ok(other.c.auth.ok === false && /Iv1\.someone/.test(other.c.auth.need) && /APP_CLIENT_ID Iv1\.app/.test(other.c.auth.need) && /auth-deploy\.yml/.test(other.c.auth.fix.label), JSON.stringify(other.c.auth));
  const origin = await run({ health: { ok: true, clientId: 'Iv1.app', origins: 'https://elsewhere.example, https://x.example' } });
  ok(origin.c.auth.ok === false && /PANEL_ORIGINS にこのパネル（https:\/\/o\.github\.io）/.test(origin.c.auth.need) && origin.c.auth.fix.inputs, JSON.stringify(origin.c.auth));
  const down = await run({ health: 500 });
  ok(down.c.auth.ok === false && /答えません（HTTP 500）/.test(down.c.auth.need), JSON.stringify(down.c.auth));
  const gone = await run({}, { ctx: { fetchImpl: () => Promise.reject(new Error('net')) } });
  ok(gone.c.auth.ok === false && /つながりません/.test(gone.c.auth.need), JSON.stringify(gone.c.auth));
  const moved = await run({ vars: { ...vars, LAB_AUTH_URL: 'https://new.example' } });
  ok(moved.c.auth.ok === false && /LAB_AUTH_URL（https:\/\/new\.example）が、このページの設定/.test(moved.c.auth.need) && /pages\.yml/.test(moved.c.auth.fix.label), JSON.stringify(moved.c.auth));
  const noapp = await run({ vars: { APP_SLUG: 'lab-o' } });
  ok(noapp.c.auth.ok === false && /APP_CLIENT_ID/.test(noapp.c.auth.need), JSON.stringify(noapp.c.auth));
  // a service that names the panels' addresses (path and all): this panel's must begin with one — its origins no longer enough
  const panels = await run({ health: { ok: true, clientId: 'Iv1.app', origins: ['https://o.github.io'], panels: ['https://o.github.io/lab/'] } });
  ok(panels.c.auth.ok === true, JSON.stringify(panels.c.auth));
  const otherPanel = await run({ health: { ok: true, clientId: 'Iv1.app', origins: ['https://o.github.io'], panels: 'https://o.github.io/other/' } });
  ok(otherPanel.c.auth.ok === false && /PANEL_ORIGINS にこのパネルのアドレス（パス付き: https:\/\/o\.github\.io\/lab\/）/.test(otherPanel.c.auth.need) && /o\.github\.io\/other/.test(otherPanel.c.auth.need) && otherPanel.c.auth.fix, JSON.stringify(otherPanel.c.auth));
  eq((await run({ health: { ok: true, clientId: 'Iv1.app', origins: ['https://elsewhere.example'], panels: ['https://o.github.io/lab/'] } })).c.auth.ok, true, 'panels said: they decide');
  eq((await run({ health: { ok: true, clientId: 'Iv1.app', origins: ['https://o.github.io'], panels: [] } })).c.auth.ok, false, 'no panel allowed: none');
  // the page's own setting under a path: not a service the panel can sign in at, said so
  const pathed = await run({}, { ctx: { config: { authUrl: 'https://example.com/auth' } } });
  ok(pathed.c.auth.ok === false && /https の origin の根ではありません: サービスは origin の \/ に（auth\/README\.md）/.test(pathed.c.auth.need) && pathed.c.auth.fix.inputs && !pathed.f.st.seen.some((s) => s.u === '/auth/health'), JSON.stringify(pathed.c.auth));
});

await t('checks, putting the service on Cloudflare: its token and account sealed into secrets, auth-deploy.yml started and waited for (the new run, not an old one), its notice 「auth-url」 into LAB_AUTH_URL, pages.yml started; a failed run said (fake GitHub)', async () => {
  const vars = { APP_ID: '4242', APP_SLUG: 'lab-o', APP_CLIENT_ID: 'Iv1.app' }, secrets = ['APP_PRIVATE_KEY', 'APP_CLIENT_SECRET', 'AUTH_STATE_SECRET'];
  const f = await fakeGitHub({ vars, pages: { build_type: 'workflow' } });
  try {
    const ctx = { api: f.api, lab: LAB({ secrets }), me: { login: 'o' }, config: {}, panelUrl: 'https://o.github.io/lab/', fetchImpl: f.fetchImpl, wait: QUICK };
    const c = byKey(await S.checks(ctx));
    eq(c.deploy.fix.needs, ['secrets.put', 'dispatch', 'variables'], 'what it does, in the policy\'s words');
    ok(c.deploy.ok === false && /Cloudflare のトークンを作って貼るだけ/.test(c.deploy.need) && c.deploy.fix.inputs.map((i) => `${i.name}:${Boolean(i.secret)}`).join() === 'token:true', JSON.stringify(c.deploy));
    await throws(() => c.deploy.fix.run({ token: 'short' }), /トークンの形/, 'a token of another form');
    ok(!f.st.secrets.size, 'nothing sent for a wrong form');
    const steps = [];
    const msg = await c.deploy.fix.run({ token: CF_TOKEN }, { onStep: (s) => steps.push(s) });
    ok(msg.includes(AUTH_URL) && steps.length === 3, `${msg}\n${steps.join('\n')}`);
    eq([f.open('CLOUDFLARE_API_TOKEN'), f.st.secrets.has('CLOUDFLARE_ACCOUNT_ID')], [CF_TOKEN, false], 'the token sealed (GitHub opens it); the account found by the workflow, not asked');
    eq(f.st.vars.get('LAB_AUTH_URL'), AUTH_URL, 'the notice\'s address (not the warning\'s), trimmed');
    const order = f.st.seen.filter((s) => s.m !== 'GET').map((s) => s.u.replace('/repos/o/lab', ''));
    eq(order, ['/actions/secrets/CLOUDFLARE_API_TOKEN', '/actions/workflows/auth-deploy.yml/dispatches', '/actions/variables/LAB_AUTH_URL', '/actions/variables', '/actions/workflows/pages.yml/dispatches']);
    ok(f.st.seen.some((s) => s.u === '/repos/o/lab/check-runs/9011/annotations?per_page=50') && !f.st.seen.some((s) => /check-runs\/11\//.test(s.u)), 'the new run\'s notice, not the old run\'s');
    ok(!f.st.seen.some((s) => s.u.includes(CF_TOKEN) || (s.body.includes(CF_TOKEN))), 'the token never plain');
    // with the secrets already there: no inputs, just put it there
    const ready = byKey(await S.checks({ ...ctx, lab: LAB({ secrets: [...secrets, 'CLOUDFLARE_API_TOKEN', 'CLOUDFLARE_ACCOUNT_ID'] }), config: {}, wait: QUICK }));
    ok(ready.auth.ok === false && /pages\.yml をもう一度/.test(ready.auth.need), 'LAB_AUTH_URL set, the page not rebuilt yet');
    f.st.vars.delete('LAB_AUTH_URL');
    const ready2 = byKey(await S.checks({ ...ctx, lab: LAB({ secrets: [...secrets, 'CLOUDFLARE_API_TOKEN', 'CLOUDFLARE_ACCOUNT_ID'] }), wait: QUICK }));
    ok(ready2.deploy.ok === true && !ready2.deploy.fix.inputs && /Cloudflare に置く/.test(ready2.deploy.fix.label), JSON.stringify(ready2.deploy));
    eq(byKey(await S.checks({ ...ctx, lab: LAB({ secrets: null }) })).deploy.ok, null, 'secrets not visible: cannot tell');
    ok(/auth-deploy\.yml がありません/.test(byKey(await S.checks({ ...ctx, lab: LAB({ secrets, workflows: [] }) })).deploy.need), 'no workflow to put it with');
  } finally { f.close(); }
  const bad = await fakeGitHub({ vars, deployConclusion: 'failure' });
  try { await throws(() => S.deployAuth(bad.api, 'o/lab', { me: 'o', ...QUICK }), /failure で終わりました/, 'a failed deploy'); ok(!bad.st.vars.has('LAB_AUTH_URL'), 'nothing set'); } finally { bad.close(); }
  const mute = await fakeGitHub({ vars, notice: '' });
  try { await throws(() => S.deployAuth(mute.api, 'o/lab', { me: 'o', ...QUICK }), /注釈 auth-url/, 'no notice'); } finally { mute.close(); }
  const slow = await fakeGitHub({ vars });
  try { await throws(() => S.deployAuth(slow.api, 'o/lab', { me: 'o', sleep: async () => {}, every: 10, timeoutMs: 5 }), /時間内に終わりません/, 'too long'); } finally { slow.close(); }
  const evil = await fakeGitHub({ vars, notice: 'javascript:alert(1)' });
  try { await throws(() => S.deployAuth(evil.api, 'o/lab', { me: 'o', ...QUICK }), /注釈 auth-url/, 'an address that is not https'); } finally { evil.close(); }
  const pathed = await fakeGitHub({ vars, notice: 'https://bds-lab-auth.o.workers.dev/auth' });
  try { await throws(() => S.deployAuth(pathed.api, 'o/lab', { me: 'o', ...QUICK }), /注釈 auth-url: https の origin の根/, 'an address under a path'); ok(!pathed.st.vars.has('LAB_AUTH_URL'), 'nothing set'); } finally { pathed.close(); }
  // nobody known to start it: nothing started
  const anon = await fakeGitHub({ vars });
  try { await throws(() => S.deployAuth(anon.api, 'o/lab', { ...QUICK }), /始める人/, 'no login'); ok(!anon.st.seen.some((s) => s.m !== 'GET'), 'nothing sent'); } finally { anon.close(); }
  // newer runs that are not this person's own (a fork's pull request, another branch, someone else's): never read; theirs is
  const crowd = await fakeGitHub({ vars, intruders: true });
  try {
    eq(await S.deployAuth(crowd.api, 'o/lab', { me: 'O', ...QUICK }), AUTH_URL, 'this person\'s run on this branch, any case');
    eq(crowd.st.vars.get('LAB_AUTH_URL'), AUTH_URL);
    ok(!crowd.st.seen.some((s) => /runs\/700\d\/jobs|check-runs\/700\d1\//.test(s.u)), `the others' runs not read: ${crowd.st.seen.filter((s) => /700\d/.test(s.u)).map((s) => s.u)}`);
  } finally { crowd.close(); }
});

await t('checks, Pages on another source (its fix switches it to the workflow) or not readable (cannot tell); variables not readable (cannot tell) (fake GitHub)', async () => {
  const f = await fakeGitHub({ pages: { build_type: 'legacy' } });
  try {
    const c = byKey(await S.checks({ api: f.api, lab: LAB(), config: {}, panelUrl: 'https://o.github.io/lab/' }));
    ok(c.pages.ok === false && /GitHub Actions」ではありません/.test(c.pages.need), c.pages.need);
    await c.pages.fix.run();
    ok(f.st.seen.some((s) => s.m === 'PUT' && s.u === '/repos/o/lab/pages' && JSON.parse(s.body).build_type === 'workflow') && f.st.pages.build_type === 'workflow', 'switched');
  } finally { f.close(); }
  // signed in with the App (no administration permission): GitHub's own Pages settings, no button
  const a = await fakeGitHub({});
  try {
    const off = byKey(await S.checks({ api: a.api, lab: LAB(), config: {}, panelUrl: 'https://o.github.io/lab/', signedInWithApp: true })).pages;
    ok(off.ok === false && off.fix.link === 'https://github.com/o/lab/settings/pages' && !off.fix.run && /Source を GitHub Actions に/.test(off.fix.label) && /Source を「GitHub Actions」に/.test(off.need), JSON.stringify(off));
    a.st.pages = { build_type: 'legacy' };
    const legacy = byKey(await S.checks({ api: a.api, lab: LAB(), config: {}, panelUrl: 'https://o.github.io/lab/', signedInWithApp: true })).pages;
    ok(legacy.ok === false && legacy.fix.link === 'https://github.com/o/lab/settings/pages' && !legacy.fix.run, JSON.stringify(legacy));
    ok(!a.st.seen.some((s) => s.m !== 'GET'), 'nothing asked of GitHub');
  } finally { a.close(); }
  const g = await fakeGitHub({ pagesStatus: 403 });
  try {
    g.api.variable = async () => { throw new G.GhError(403, 'no', '/x'); };
    const c = byKey(await S.checks({ api: g.api, lab: LAB(), config: {}, panelUrl: 'https://o.github.io/lab/' }));
    // (what this token may not read is no dead end: each such row offers the token with everything in, and says what to do)
    const tok = S.tokenUrl('o'), q = new URL(tok).searchParams;
    ok(tok.startsWith('https://github.com/settings/personal-access-tokens/new?') && q.get('target_name') === 'o' && ['actions', 'contents', 'secrets', 'variables', 'issues', 'pages', 'administration'].every((k) => q.get(k) === 'write') && q.get('pull_requests') === 'read' && q.get('actions_variables') === 'write', tok);
    ok(!new URL(S.tokenUrl('bad owner!')).searchParams.has('target_name'), 'an owner that is no login is not written in');
    ok(c.pages.ok === null && /読めません/.test(c.pages.need) && c.pages.fix?.link === tok && /入り直して/.test(c.pages.need), JSON.stringify(c.pages));
    ok(c.app.ok === null && /Variables: Read/.test(c.app.need) && c.app.fix?.link === tok && /トークンを作り直す/.test(c.app.fix.label), JSON.stringify(c.app));
    ok(c.workflows.ok === null && c.workflows.fix?.link === tok, JSON.stringify(c.workflows));
    // (signed in with the App: the App's permissions, not a token)
    const w = byKey(await S.checks({ api: g.api, lab: LAB(), config: { appSlug: 'lab-app' }, panelUrl: 'https://o.github.io/lab/', signedInWithApp: true }));
    ok(w.workflows.ok === null && /\/settings\/apps\/lab-app\/permissions$/.test(w.workflows.fix?.link ?? '') && /Permissions/.test(w.workflows.need), JSON.stringify(w.workflows));
    ok(S.moreRights({ owner: 'o', signedInWithApp: true }).link === 'https://github.com/settings/apps', 'no App known: the list of Apps');
  } finally { g.close(); }
});

// ---- a small DOM: enough for panel/ui/dom.mjs's h and the tab ----
function fakeDom() {
  class N { get textContent() { return ''; } }
  class T extends N { constructor(s) { super(); this.data = String(s); } get textContent() { return this.data; } }
  class E extends N {
    constructor(tag) { super(); Object.assign(this, { tagName: tag.toUpperCase(), kids: [], attrs: {}, on: {}, style: {}, className: '', value: '', checked: false, disabled: false, parent: null }); }
    setAttribute(k, v) { this.attrs[k] = String(v); }
    getAttribute(k) { return this.attrs[k] ?? null; }
    addEventListener(type, fn) { (this.on[type] ??= []).push(fn); }
    append(...xs) { for (const x of xs) { const n = x instanceof N ? x : new T(x); if (n.parent) n.parent.kids = n.parent.kids.filter((k) => k !== n); n.parent = this; this.kids.push(n); } }
    replaceChildren(...xs) { for (const k of this.kids) k.parent = null; this.kids = []; this.append(...xs); }
    remove() { if (this.parent) this.parent.kids = this.parent.kids.filter((k) => k !== this); this.parent = null; }
    get textContent() { return this.kids.map((k) => k.textContent).join(''); }
    fire(type) { return Promise.all((this.on[type] ?? []).map((fn) => fn({ target: this, preventDefault() {} }))); }
    click() { return this.fire('click'); }
    all(test) { const out = [], walk = (e) => { for (const k of e.kids) if (k instanceof E) { if (test(k)) out.push(k); walk(k); } }; walk(this); return out; }
    focus() {}
  }
  const toast = new E('div');
  globalThis.Node = N;
  globalThis.document = { createElement: (tag) => new E(tag), createTextNode: (s) => new T(s), getElementById: (id) => (id === 'toast' ? toast : null), body: new E('body') };
  return { E, toast };
}

await t('the 「準備」 tab: the list for anyone; fixes for the lab\'s administrators only (a lender\'s link for all); the App\'s real form posted to GitHub with its manifest; GitHub\'s code taken out of the address before anything, used only with this tab\'s state, the keys sealed, nothing left in the page (fake DOM, fake GitHub)', async () => {
  const { E, toast } = fakeDom();
  const UI = await imp('panel/ui/setup.mjs');
  const f = await fakeGitHub({ vars: { APP_SLUG: 'lab-o' } });
  try {
    f.st.vars.delete('APP_SLUG');
    const nav = (search = '', hash = '#setup') => ({ location: { search, hash, pathname: '/lab/' }, history: { replaceState: (_a, _b, u) => { f.st.log.push(`replace ${u}`); } } });
    const base = { api: f.api, lab: LAB(), hosts: [{ slug: 'lender/host' }], me: { login: 'o' }, config: {}, panelUrl: 'https://o.github.io/lab/', signedInWithApp: false, fetchImpl: f.fetchImpl, storage: AC.memoryStorage() };
    const body = new E('div');
    await UI.setupTab(body, { ...base, ...nav() });
    const rows = body.all((e) => e.attrs['data-check']);
    eq(rows.map((r) => r.attrs['data-check']), ['pages', 'app', 'installed', 'deploy', 'workflows', 'host:lender/host']);
    const form = body.all((e) => e.tagName === 'FORM')[0];
    ok(form && form.attrs.method === 'post' && /^https:\/\/github\.com\/settings\/apps\/new\?state=[0-9a-f]{32}$/.test(form.attrs.action), `a real form to GitHub: ${JSON.stringify(form?.attrs)}`);
    const hidden = form.all((e) => e.tagName === 'INPUT' && e.attrs.type === 'hidden')[0];
    eq([hidden.attrs.name, JSON.parse(hidden.value)], ['manifest', S.appManifest({ owner: 'o', repo: 'lab', panelUrl: 'https://o.github.io/lab/' })], 'its manifest');
    await form.fire('submit');
    const kept = JSON.parse(base.storage.getItem('bdslab.setup.manifest'));
    eq([kept.state, kept.lab], [form.attrs.action.split('state=')[1], 'o/lab'], 'the state kept in this tab as the form goes');
    const ul = body.all((e) => e.tagName === 'UL')[0];
    ok(ul.all((e) => e.tagName === 'BUTTON' && /Pages を有効に/.test(e.textContent)).length === 1 && ul.all((e) => e.tagName === 'INPUT' && e.attrs.type === 'password').length === 1, 'Pages\' button; Cloudflare\'s one field even before the App (its address goes into the App)');
    // someone who is not the lab's administrator: the list and the links, no button, no form
    const ro = new E('div');
    await UI.setupTab(ro, { ...base, lab: LAB({ role: 'write' }), ...nav() });
    ok(!ro.all((e) => e.tagName === 'FORM').length && !ro.all((e) => e.tagName === 'BUTTON' && e.textContent !== 'コピー').length && /見るだけです/.test(ro.textContent) && /管理者が直せます/.test(ro.textContent), ro.textContent);
    // a fix's button: Pages turned on, the record kept, the tab reloaded
    let reloads = 0; const recs = [];
    const adm = new E('div');
    await UI.setupTab(adm, { ...base, ...nav(), reload: () => { reloads++; }, record: (a, d) => recs.push([a, d]) });
    await adm.all((e) => e.tagName === 'BUTTON' && /Pages を有効に/.test(e.textContent))[0].click();
    ok(f.st.pages?.build_type === 'workflow' && reloads === 1 && JSON.stringify(recs) === '[["setup.pages",{}]]', `${reloads} ${JSON.stringify(recs)}`);
    // the way back with another tab's state: the code removed, not used
    f.st.log.length = 0;
    const wrong = new E('div');
    await UI.setupTab(wrong, { ...base, ...nav('?code=c0de1&state=nope') });
    ok(f.st.log.join() === 'replace /lab/#setup' && !f.st.seen.some((s) => /conversions/.test(s.u)) && /このタブで始めたものではない/.test(wrong.textContent), `${f.st.log.join()} ${wrong.textContent}`);
    // the way back with this tab's state: the address cleaned first, then the App's keys sealed into secrets
    base.storage.setItem('bdslab.setup.manifest', JSON.stringify({ state: 'abc', lab: 'o/lab', owner: 'o', isOrg: false, at: Date.now() }));
    f.st.log.length = 0; reloads = 0; recs.length = 0;
    const back = new E('div');
    await UI.setupTab(back, { ...base, ...nav('?code=c0de2&state=abc'), reload: () => { reloads++; }, record: (a, d) => recs.push([a, d]) });
    eq(f.st.log, ['replace /lab/#setup', 'convert'], 'the code out of the address before it is used');
    eq([f.open('APP_PRIVATE_KEY'), f.st.vars.get('APP_SLUG'), reloads, JSON.stringify(recs)], [PEM, 'lab-o', 1, '[["setup.app",{"app":"lab-o"}]]']);
    ok(/App lab-o を作り/.test(back.textContent), back.textContent);
    ok(base.storage.getItem('bdslab.setup.manifest') === null, 'the state used once');
    const page = `${back.textContent}\n${toast.textContent}\n${JSON.stringify(base.storage)}`;
    ok(!page.includes('BEGIN RSA') && !page.includes(CLIENT_SECRET), 'no key in the page or the storage');
    // the same code again (a reload): the state is gone, nothing done
    f.st.log.length = 0;
    await UI.setupTab(new E('div'), { ...base, ...nav('?code=c0de2&state=abc') });
    eq(f.st.log, ['replace /lab/#setup'], 'once only');
    // panel.js may take it first, before any request: the address cleaned at once, the answer handed to the tab (used once;
    // another lab's not used; older than GitHub's hour not used)
    base.storage.setItem('bdslab.setup.manifest', JSON.stringify({ state: 'def', lab: 'o/other', owner: 'o', isOrg: false, at: Date.now() }));
    f.st.log.length = 0;
    const early = UI.takeAppReturn({ ...nav('?code=c0de3&state=def'), storage: base.storage });
    eq([early, f.st.log], [{ code: 'c0de3', lab: 'o/other', owner: 'o', isOrg: false, callback: null }, ['replace /lab/#setup']]);
    const el = new E('div');
    await UI.setupTab(el, { ...base, ...nav(), appReturn: early });
    ok(/別のラボ（o\/other）/.test(el.textContent) && !f.st.log.includes('convert') && early.used === true, el.textContent);
    ok(/App は GitHub にできています: App の設定で鍵/.test(el.textContent) && /App を消して/.test(el.textContent) && el.all((e) => e.tagName === 'A' && e.attrs.href === 'https://github.com/settings/apps').length === 1, `what to do with the App made: ${el.textContent}`);
    eq(UI.takeAppReturn({ ...nav('', '#setup'), storage: base.storage }), null, 'no code: nothing');
    base.storage.setItem('bdslab.setup.manifest', JSON.stringify({ state: 'old', lab: 'o/lab', at: Date.now() - 2 * 3_600_000 }));
    ok(/古い/.test(UI.takeAppReturn({ ...nav('?code=c0de4&state=old'), storage: base.storage }).error), 'older than an hour');
    // a lender's link for everyone; for the administrator, Cloudflare's token page linked and one field (no account id)
    f.st.vars.set('APP_ID', '4242'); f.st.vars.set('APP_CLIENT_ID', 'Iv1.app');
    const later = new E('div');
    await UI.setupTab(later, { ...base, lab: LAB({ secrets: ['APP_PRIVATE_KEY', 'APP_CLIENT_SECRET', 'AUTH_STATE_SECRET'] }), ...nav(), wait: QUICK });
    const a = later.all((e) => e.tagName === 'A' && e.attrs.href === 'https://github.com/apps/lab-o/installations/new');
    ok(a.length >= 2 && a.every((x) => x.attrs.rel === 'noopener noreferrer'), 'the install links');
    const pw = later.all((e) => e.tagName === 'UL')[0].all((e) => e.tagName === 'INPUT' && e.attrs.type === 'password');
    eq(pw.length, 1, 'Cloudflare\'s token as a password field');
    eq(pw[0].attrs.autocomplete, 'off', 'not offered to the browser\'s password manager');
    ok(later.all((e) => e.tagName === 'A' && e.attrs.href === S.cfTokenUrl()).length === 1, 'Cloudflare\'s own token page, everything chosen');
    ok(!later.all((e) => e.tagName === 'INPUT' && /ACCOUNT/i.test(e.attrs['aria-label'] ?? '')).length, 'no account field');
    pw[0].value = CF_TOKEN;
    await later.all((e) => e.tagName === 'BUTTON' && /貼って置く/.test(e.textContent))[0].click();
    eq([f.open('CLOUDFLARE_API_TOKEN'), f.st.vars.get('LAB_AUTH_URL'), pw[0].value], [CF_TOKEN, AUTH_URL, ''], 'sealed, put there, the field emptied');
    ok(!later.textContent.includes(CF_TOKEN) && !toast.textContent.includes(CF_TOKEN), 'the token not shown');
  } finally { f.close(); }
});

await t('the 「準備」 tab and the policy: a fix only for a GitHub administrator whose role the policy lets do all it does (secrets, variables, starting a workflow), else why — the role and the policy — in place of its button; the App\'s form the same, and its way back looked at before the code is used (fake DOM, fake GitHub)', async () => {
  const { E } = fakeDom();
  const UI = await imp('panel/ui/setup.mjs'), P = await imp('panel/lib/policy.mjs');
  const f = await fakeGitHub();
  try {
    const nav = (search = '', hash = '#setup') => ({ location: { search, hash, pathname: '/lab/' }, history: { replaceState: () => {} } });
    const base = { api: f.api, lab: LAB(), hosts: [], me: { login: 'o' }, config: {}, panelUrl: 'https://o.github.io/lab/', signedInWithApp: false, fetchImpl: f.fetchImpl, storage: AC.memoryStorage() };
    // (the checks' own buttons: 「全自動で準備する」 above them is its own card, tried below)
    const buttons = (b) => (b.all((e) => e.tagName === 'UL')[0] ?? b).all((e) => e.tagName === 'BUTTON' && e.textContent !== 'コピー'), rowOf = (b, k) => b.all((e) => e.attrs['data-check'] === k)[0];
    // an administrator whose role may start workflows only: Pages' button (it starts pages.yml); not the App (secrets and
    // variables) nor the service's address (a variable): why, in place of them
    const dispatchOnly = P.checkPolicy({ roles: { admin: ['dispatch'], write: [] } }).policy;
    const b1 = new E('div');
    await UI.setupTab(b1, { ...base, ...nav(), policy: dispatchOnly, role: P.roleFor({ repoRole: 'admin', policy: dispatchOnly }) });
    eq(buttons(b1).map((x) => x.textContent), ['Pages を有効に（GitHub Actions で）']);
    ok(!b1.all((e) => e.tagName === 'FORM').length, 'no App form');
    ok(/役割「admin」には、ポリシー（\.github\/bds-lab-panel\.json の roles）が「秘密を登録する・変数を変える」を許していません/.test(rowOf(b1, 'app').textContent), rowOf(b1, 'app').textContent);
    ok(/「秘密を登録する・変数を変える」を許していません/.test(rowOf(b1, 'deploy').textContent) && !b1.all((e) => e.tagName === 'INPUT').length, rowOf(b1, 'deploy').textContent);   // (and 「全自動で準備する」 offers no Cloudflare field to a role that may not put secrets)
    // a policy that allows nothing (or a broken file): no button, no form, no field
    for (const policy of [P.checkPolicy({ roles: { admin: [] } }).policy, P.LOCKED_POLICY]) {
      const b = new E('div');
      await UI.setupTab(b, { ...base, ...nav(), policy, role: 'admin' });
      ok(!buttons(b).length && !b.all((e) => e.tagName === 'FORM').length && /ワークフローを始める/.test(rowOf(b, 'pages').textContent), b.textContent);
    }
    // a writer given everything by the policy: still not GitHub's administrator
    const all = P.checkPolicy({ roles: { admin: ['*'], write: ['*'] } }).policy, w = new E('div');
    await UI.setupTab(w, { ...base, lab: LAB({ role: 'write' }), ...nav(), policy: all, role: P.roleFor({ repoRole: 'write', policy: all }) });
    ok(!buttons(w).length && !w.all((e) => e.tagName === 'FORM').length && /管理者が直せます/.test(w.textContent), w.textContent);
    // the policy's role read from a team: said by the role's name
    const teamed = P.checkPolicy({ roles: { admin: ['*'], ops: ['dispatch'] }, teams: { ops: 'ops' } }).policy, tm = new E('div');
    await UI.setupTab(tm, { ...base, ...nav(), policy: teamed, role: P.roleFor({ repoRole: 'admin', teams: ['ops'], policy: teamed }) });
    ok(/役割「ops」/.test(rowOf(tm, 'app').textContent) && !tm.all((e) => e.tagName === 'FORM').length, rowOf(tm, 'app').textContent);
    // the way back while the policy does not let this role keep the App's keys: the code not used, what to do said
    // (an organization's App: its Apps' page)
    for (const [over, re] of [[{ policy: dispatchOnly, role: 'admin' }, /秘密を登録する・変数を変える/], [{ lab: LAB({ role: 'write' }) }, /管理者が直せます/]]) {
      base.storage.setItem('bdslab.setup.manifest', JSON.stringify({ state: 'xyz', lab: 'o/lab', owner: 'acme', isOrg: true, at: Date.now() }));
      f.st.log.length = 0;
      const b = new E('div');
      await UI.setupTab(b, { ...base, ...nav('?code=c0de9&state=xyz'), ...over });
      ok(!f.st.log.includes('convert') && !f.st.secrets.size && !f.st.seen.some((s) => /conversions/.test(s.u)), 'the code not used');
      ok(/戻ってきた App の code は使いません/.test(b.textContent) && re.test(b.textContent) && /App は GitHub にできています/.test(b.textContent) && /APP_PRIVATE_KEY・APP_CLIENT_SECRET/.test(b.textContent), b.textContent);
      eq(b.all((e) => e.tagName === 'A' && e.attrs.href === 'https://github.com/organizations/acme/settings/apps').length, 1, 'the organization\'s Apps');
    }
    // the policy allowing it: the keys kept as before
    base.storage.setItem('bdslab.setup.manifest', JSON.stringify({ state: 'ok1', lab: 'o/lab', owner: 'o', isOrg: false, at: Date.now() }));
    const keep = P.checkPolicy({ roles: { admin: ['secrets.put', 'variables'] } }).policy, b2 = new E('div');
    await UI.setupTab(b2, { ...base, ...nav('?code=c0dea&state=ok1'), policy: keep, role: 'admin' });
    ok(/App lab-o を作り/.test(b2.textContent) && f.st.vars.get('APP_SLUG') === 'lab-o', b2.textContent);
  } finally { f.close(); }
});

await t('全自動で準備する: the next step from the checks (pure), the lab chosen on the App\'s install page, nothing to type; on the tab: Pages turned on by itself, Cloudflare\'s token page opened by the run and the copied token read back by itself, the address settled, the App made with its Callback URL, the service put in place and the page loaded again, the App installed once, done with every row ✅ (fake DOM, fake GitHub)', async () => {
  const R = (key, ok, fix = null, extra = {}) => ({ key, label: key, ok, need: ok === true ? '' : `${key} needed`, fix, ...extra });
  const run = { run: async () => 'done' };
  eq(S.autoNext([R('pages', false, run), R('app', false, { manifest: true })]), { kind: 'run', key: 'pages' }, 'Pages first');
  eq(S.autoNext([R('pages', true), R('app', false, { manifest: true })]), { kind: 'app' }, 'then the App');
  eq(S.autoNext([R('pages', true), R('app', null)]).kind, 'stop', 'variables not readable: stop, with why');
  eq(S.autoNext([R('pages', true), R('app', true), R('installed', null)]), { kind: 'install' }, 'then install it');
  eq(S.autoNext([R('pages', true), R('app', true), R('installed', null), R('deploy', true, run), R('auth', false)]), { kind: 'run', key: 'deploy' }, 'the service before installing (the App that stays is installed once)');
  // Cloudflare's token page opened by the run itself — before the App, its address going into the App's Callback URL
  const cfRow = R('deploy', false, { ...run, inputs: [{ name: 'token' }], help: { link: 'https://dash.cloudflare.com/x' } });
  eq(S.autoNext([R('pages', true), R('app', false, { manifest: true }), cfRow]), { kind: 'cloudflare', link: 'https://dash.cloudflare.com/x' }, 'no token: Cloudflare first, before the App');
  eq(S.autoNext([R('pages', true), R('app', true), R('installed', true), cfRow]), { kind: 'cloudflare', link: 'https://dash.cloudflare.com/x' }, 'the App there already: Cloudflare too');
  // skipped only when the person says so: then named
  eq(S.autoNext([R('pages', true), R('app', true), R('installed', true), cfRow, R('auth', false, { ...run, inputs: [{ name: 'url' }] })], { cfSkip: true }), { kind: 'done', skipped: ['deploy', 'auth'] }, 'skipped on the person\'s word: named');
  eq(S.autoNext([R('pages', true), R('app', true), R('installed', true), R('auth', false, run)]), { kind: 'run', key: 'auth' }, 'what the panel can do alone about the service, it does');
  eq(S.autoNext([R('pages', true), R('app', true), R('installed', true), R('auth', true), R('callback', null)]), { kind: 'done', skipped: ['callback'] }, 'the Callback URL: skipped, not asked');
  eq(S.autoNext([R('pages', true), R('app', true), R('installed', true), R('app-perms', false, { link: 'https://x/permissions', label: 'p' })]), { kind: 'stop', key: 'app-perms', why: 'app-perms needed', link: 'https://x/permissions', linkLabel: 'p' }, 'the App\'s permissions short: stop with the link');
  eq(S.autoNext([R('pages', true), R('app', true), R('installed', true), R('workflows', null)]).kind, 'stop', 'a ❔ that is not skippable is not done');
  eq(S.autoNext([R('pages', true), R('app', true), R('installed', null)], { installed: true }), { kind: 'done', skipped: [] }, 'back from installing: done');
  eq(S.autoNext([R('pages', true), R('app', true), R('installed', true), R('workflows', true), R('host:l/h', false)]), { kind: 'done', skipped: [] }, 'a lender\'s host is theirs');
  eq(S.autoNext([R('pages', false, { link: 'https://github.com/o/lab/settings/pages' })]).kind, 'stop', 'Pages that only GitHub\'s page turns on: stop');
  eq(S.installLink('lab-o', 11, 22), 'https://github.com/apps/lab-o/installations/new/permissions?suggested_target_id=11&repository_ids[]=22');
  eq(S.installLink('lab-o'), 'https://github.com/apps/lab-o/installations/new', 'no ids: the plain page');
  eq(S.installLink('Bad Slug!', 1, 2), null);
  ok(/トークンの形/.test(S.cfProblem({ token: 'short', account: CF_ACCOUNT })) && /32 文字/.test(S.cfProblem({ token: CF_TOKEN, account: 'x' })) && S.cfProblem({ token: CF_TOKEN, account: CF_ACCOUNT }) === null, 'Cloudflare\'s fields checked');

  const { E } = fakeDom();
  const UI = await imp('panel/ui/setup.mjs');
  const f = await fakeGitHub({});
  try {
    const store = AC.memoryStorage(), went = [], submitted = [];
    globalThis.document.body.append = (x) => { x.requestSubmit = () => { x.fire('submit'); submitted.push(x.attrs.action); }; };
    // (the browser around the page: a tab opened, the clipboard, this window's focus; the page's config and the service)
    const opened = [], clip = { text: '' }, winOn = {}, live = { config: null };
    const win = { addEventListener: (t, fn) => { (winOn[t] ??= []).push(fn); }, removeEventListener: (t, fn) => { winOn[t] = (winOn[t] ?? []).filter((x) => x !== fn); } };
    const focus = () => Promise.all((winOn.focus ?? []).map((fn) => fn()));
    const fetchImpl = async (url, o) => {
      if (/config\.json/.test(url)) return { ok: true, json: async () => ({ authUrl: live.config }) };
      if (String(url) === `${AUTH_URL}/health`) return { ok: true, json: async () => ({ ok: true, clientId: f.st.vars.get('APP_CLIENT_ID'), panels: ['https://o.github.io/lab/'] }) };
      return f.fetchImpl(url, o);
    };
    const reloaded = [];
    const ctx = { api: f.api, lab: LAB({ repo: { default_branch: 'main', owner: { login: 'o', type: 'User', id: 11 }, id: 22 } }), hosts: [], me: { login: 'o' }, config: {}, panelUrl: 'https://o.github.io/lab/', signedInWithApp: false, fetchImpl, storage: store,
      wait: { ...QUICK, timeoutMs: 1000, sleep: async () => { live.config = AUTH_URL; } }, reloadPage: () => reloaded.push(1),
      open: (u) => { opened.push(u); return { close() {} }; }, clipboard: { readText: async () => clip.text }, win,
      location: { search: '', hash: '#setup', pathname: '/lab/', assign: (u) => went.push(u) }, history: { replaceState() {} } };
    const body = new E('div');
    await UI.setupTab(body, ctx);
    const go = body.all((e) => e.tagName === 'BUTTON' && e.textContent === '全自動で準備する')[0];
    ok(go, 'the button for the lab\'s administrator');
    ok(!body.all((e) => e.tagName === 'DIV' && e.className === 'card').filter((x) => /全自動で準備する/.test(x.textContent) && !/準備と診断/.test(x.textContent)).some((x) => x.all((e) => e.tagName === 'INPUT').length), 'nothing to type on the card before it starts');
    await go.click();
    ok(f.st.pages?.build_type === 'workflow', `Pages turned on by itself: ${JSON.stringify(f.st.pages)}`);
    eq(opened, [S.cfTokenUrl()], 'Cloudflare\'s token page opened by the run, in its own tab, on the press');
    ok(/開いた Cloudflare のタブで/.test(body.textContent) && !submitted.length, `waiting for the token, the App not made yet: ${body.textContent.slice(0, 400)}`);
    // back in this tab with something else copied: nothing taken; then the token copied: taken by itself, no button
    clip.text = 'hello'; await focus();
    ok(!f.st.secrets.has('CLOUDFLARE_API_TOKEN'), 'not a token: nothing sent');
    clip.text = CF_TOKEN; await focus();
    eq(f.open('CLOUDFLARE_API_TOKEN'), CF_TOKEN, 'the copied token read and sealed, nothing pressed');
    // then on by itself: the address settled (plan), the App made with its Callback URL
    ok(f.st.seen.some((x) => /auth-deploy\.yml\/dispatches/.test(x.u) && JSON.parse(x.body).inputs?.plan === 'true'), 'the address asked of Cloudflare');
    ok(submitted.length === 1 && /^https:\/\/github\.com\/settings\/apps\/new\?state=/.test(submitted[0]) && JSON.parse(store.getItem('bdslab.setup.auto')).stage === 'app', `then the App's form: ${submitted}`);
    const kept = JSON.parse(store.getItem('bdslab.setup.manifest'));
    eq(kept.callback, `${AUTH_URL}/callback`, 'the App made with its Callback URL');
    ok(/Create GitHub App/.test(body.textContent), 'what to press on GitHub, said');
    // back from GitHub with the App made: the service put in place, the page waited for and loaded again
    f.st.vars.set('APP_ID', '5'); f.st.vars.set('APP_SLUG', 'lab-o'); f.st.vars.set('APP_CLIENT_ID', 'Iv1.x'); f.st.vars.set('APP_CALLBACK_URL', kept.callback);
    f.st.appPerms = { ...f.st.appPerms, administration: 'write' };
    ctx.lab.secrets = ['APP_PRIVATE_KEY', 'APP_CLIENT_SECRET', 'AUTH_STATE_SECRET', 'CLOUDFLARE_API_TOKEN'];
    await UI.setupTab(new E('div'), ctx);
    eq([f.st.vars.get('LAB_AUTH_URL'), reloaded.length, went.length], [AUTH_URL, 1, 0], 'put in place, the page loaded again, not installed yet');
    // loaded again: the Callback URL right from the start — straight to installing the App, once
    const b3 = new E('div');
    await UI.setupTab(b3, { ...ctx, config: { authUrl: AUTH_URL, appSlug: 'lab-o', appClientId: 'Iv1.x' } });
    eq(went, ['https://github.com/apps/lab-o/installations/new/permissions?suggested_target_id=11&repository_ids[]=22'], 'to the install page with the lab chosen');
    // back from installing: every row ✅ — done, nothing skipped
    const b4 = new E('div');
    await UI.setupTab(b4, { ...ctx, config: { authUrl: AUTH_URL, appSlug: 'lab-o', appClientId: 'Iv1.x' } });
    ok(/✅ 準備はすべて終わりました（全部の行が ✅）/.test(b4.textContent) && !store.getItem('bdslab.setup.auto'), b4.textContent.slice(0, 900));
  } finally { f.close(); delete globalThis.document.body.append; }
});

await t('全自動で準備する from where a real lab stood: the App made before the service (no APP_CALLBACK_URL), the service up — the App made again with the Callback URL under a new name, the service put in place again for the new App, installed once, done (fake DOM, fake GitHub)', async () => {
  const { E } = fakeDom();
  const UI = await imp('panel/ui/setup.mjs');
  const f = await fakeGitHub({ pages: { build_type: 'workflow' }, vars: { APP_ID: '5', APP_SLUG: 'lab-o', APP_CLIENT_ID: 'Iv1.old', LAB_AUTH_URL: AUTH_URL } });
  try {
    f.st.appPerms = { ...f.st.appPerms, administration: 'write' };
    const store = AC.memoryStorage(), submitted = [], went = [];
    globalThis.document.body.append = (x) => { x.requestSubmit = () => { x.fire('submit'); submitted.push(x); }; };
    const fetchImpl = async (url, o) => (String(url) === `${AUTH_URL}/health` ? { ok: true, json: async () => ({ ok: true, clientId: f.st.svcClient ?? 'Iv1.old', panels: ['https://o.github.io/lab/'] }) } : f.fetchImpl(url, o));
    const ctx = { api: f.api, lab: LAB({ secrets: ['APP_PRIVATE_KEY', 'APP_CLIENT_SECRET', 'AUTH_STATE_SECRET', 'CLOUDFLARE_API_TOKEN'], repo: { default_branch: 'main', owner: { login: 'o', type: 'User', id: 11 }, id: 22 } }), hosts: [], me: { login: 'o' }, config: { authUrl: AUTH_URL, appSlug: 'lab-o', appClientId: 'Iv1.old' }, panelUrl: 'https://o.github.io/lab/', signedInWithApp: false, fetchImpl, storage: store, wait: QUICK,
      location: { search: '', hash: '#setup', pathname: '/lab/', assign: (u) => went.push(u) }, history: { replaceState() {} } };
    // the row's own button: a new name (the old one is taken on GitHub) and the Callback URL
    const b0 = new E('div');
    await UI.setupTab(b0, ctx);
    const rowForm = b0.all((e) => e.attrs['data-check'] === 'callback')[0].all((e) => e.tagName === 'FORM')[0];
    const rm = JSON.parse(rowForm.all((e) => e.tagName === 'INPUT' && e.attrs.type === 'hidden')[0].value);
    ok(rm.name !== 'lab-o' && /^lab-o-[0-9a-f]{4}$/.test(rm.name) && rm.callback_urls[0] === `${AUTH_URL}/callback`, JSON.stringify([rm.name, rm.callback_urls]));
    // 全自動: straight to making it again
    await b0.all((e) => e.tagName === 'BUTTON' && e.textContent === '全自動で準備する')[0].click();
    eq(submitted.length, 1, `the App's form sent: ${b0.textContent.slice(0, 500)}`);
    const m = JSON.parse(submitted[0].all((e) => e.tagName === 'INPUT' && e.attrs.type === 'hidden')[0].value);
    ok(/^lab-o-[0-9a-f]{4}$/.test(m.name) && m.callback_urls[0] === `${AUTH_URL}/callback`, JSON.stringify([m.name, m.callback_urls]));
    // back with the new App: the service put in place again for it (its client id), then installed, then done
    f.st.vars.set('APP_ID', '6'); f.st.vars.set('APP_SLUG', m.name); f.st.vars.set('APP_CLIENT_ID', 'Iv1.new'); f.st.vars.set('APP_CALLBACK_URL', `${AUTH_URL}/callback`);
    f.st.seen.length = 0;
    const realDispatch = f.api.dispatch; f.api.dispatch = async (...a) => { const r = await realDispatch(...a); if (a[1] === 'auth-deploy.yml') f.st.svcClient = 'Iv1.new'; return r; };
    await UI.setupTab(new E('div'), { ...ctx, config: { ...ctx.config, appSlug: m.name, appClientId: 'Iv1.new' } });
    ok(f.st.seen.some((x) => /auth-deploy\.yml\/dispatches/.test(x.u)), 'the service put in place again for the new App');
    eq(went.length, 1, `then to install it: ${went}`);
    ok(went[0].includes(`/apps/${m.name}/installations/new`), went[0]);
    const b4 = new E('div');
    await UI.setupTab(b4, { ...ctx, config: { ...ctx.config, appSlug: m.name, appClientId: 'Iv1.new' } });
    ok(/✅ 準備はすべて終わりました（全部の行が ✅）/.test(b4.textContent), b4.textContent.slice(0, 800));
  } finally { f.close(); delete globalThis.document.body.append; }
});

await t('全自動で準備する and Cloudflare: a tab the browser blocked opened by one press; a token pasted goes on by itself; 「飛ばす」 the person\'s own word, then named as skipped (fake DOM, fake GitHub)', async () => {
  const { E } = fakeDom();
  const UI = await imp('panel/ui/setup.mjs');
  for (const how of ['paste', 'skip']) {
    const f = await fakeGitHub({ pages: { build_type: 'workflow' }, vars: { APP_ID: '5', APP_SLUG: 'lab-o', APP_CLIENT_ID: 'Iv1.x' } });
    try {
      f.st.appPerms = { ...f.st.appPerms, administration: 'write' };
      const store = AC.memoryStorage(), opened = [], submitted = [];
      globalThis.document.body.append = (x) => { x.requestSubmit = () => { submitted.push(x); }; };
      // (a run going on from GitHub's way back: no press, the browser blocks the tab)
      store.setItem('bdslab.setup.auto', JSON.stringify({ stage: 'go', installed: true, lab: 'o/lab', at: Date.now() }));
      const ctx = { api: f.api, lab: LAB({ secrets: ['APP_PRIVATE_KEY', 'APP_CLIENT_SECRET', 'AUTH_STATE_SECRET'] }), hosts: [], me: { login: 'o' }, config: {}, panelUrl: 'https://o.github.io/lab/', signedInWithApp: false, fetchImpl: f.fetchImpl, storage: store, wait: QUICK,
        open: (u) => { opened.push(u); return opened.length > 1 ? { close() {} } : null; }, clipboard: { readText: async () => { throw new Error('denied'); } }, win: {},
        location: { search: '', hash: '#setup', pathname: '/lab/', assign() {} }, history: { replaceState() {} } };
      const b = new E('div');
      await UI.setupTab(b, ctx);
      const openBtn = b.all((e) => e.tagName === 'BUTTON' && e.textContent === 'Cloudflare を開く')[0];
      ok(openBtn && opened.length === 1, `blocked: one press opens it: ${b.textContent.slice(0, 300)}`);
      await openBtn.click();
      eq(opened.length, 2, 'opened on the press');
      if (how === 'paste') {
        const field = b.all((e) => e.tagName === 'INPUT' && e.attrs['aria-label'] === 'Cloudflare のトークン')[0];
        field.value = CF_TOKEN; await field.fire('input');
        eq(f.open('CLOUDFLARE_API_TOKEN'), CF_TOKEN, 'pasted: sealed, nothing else pressed');
        ok(field.value === '' && !b.textContent.includes(CF_TOKEN), 'the field emptied, the token not shown');
        ok(f.st.seen.some((x) => /auth-deploy\.yml\/dispatches/.test(x.u)), 'and on by itself: the service put in place');
      } else {
        await b.all((e) => e.tagName === 'BUTTON' && /今は使わない（飛ばす）/.test(e.textContent))[0].click();
        ok(!f.st.secrets.has('CLOUDFLARE_API_TOKEN') && !f.st.seen.some((x) => /auth-deploy\.yml\/dispatches/.test(x.u)), 'skipped: nothing sent for it');
        ok(/飛ばしたもの: 「GitHub でサインイン」/.test(b.textContent), `named as skipped: ${b.textContent.slice(0, 600)}`);
      }
    } finally { f.close(); delete globalThis.document.body.append; }
  }
});

await t('全自動で準備する: a failed auth-deploy.yml says Cloudflare\'s own reason; waiting for the page and the service times out in words; auth-deploy.yml refuses to put a half-made service and checks /health (fake DOM, fake GitHub)', async () => {
  // a failed run: its words, not just 「failure」
  const f = await fakeGitHub({ deployConclusion: 'failure' });
  try {
    f.st.failWhy = 'Cloudflare の workers.dev の名前がまだありません';
    await throws(() => S.deployAuth(f.api, 'o/lab', { me: 'o', ...QUICK }), /auth-deploy\.yml が止まりました: Cloudflare の workers\.dev の名前がまだありません/, 'the reason');
  } finally { f.close(); }
  // waiting: the page never learns the address / the service never answers ok
  const never = async (url) => (/config\.json/.test(url) ? { ok: true, json: async () => ({ authUrl: null }) } : { ok: false, status: 502 });
  await throws(() => S.waitLive({ fetchImpl: never, ...QUICK }), /config\.json）に .*サービスの URL が入りません/, 'the page');
  const down = async (url) => (/config\.json/.test(url) ? { ok: true, json: async () => ({ authUrl: AUTH_URL }) } : { ok: false, status: 502 });
  await throws(() => S.waitLive({ fetchImpl: down, ...QUICK }), /ok と答えません（HTTP 502）/, 'the service');
  const other = async (url) => (/config\.json/.test(url) ? { ok: true, json: async () => ({ authUrl: 'https://old.example' }) } : { ok: true, json: async () => ({ ok: true }) });
  await throws(() => S.waitLive({ want: AUTH_URL, fetchImpl: other, ...QUICK }), /サービスの URL が入りません/, 'an old address is not the new one');
  // the workflow: a half-made service never put in place; Cloudflare's refusals in words; /health before the address
  const y = fs.readFileSync(path.join(TOP, '.github/workflows/auth-deploy.yml'), 'utf8');
  const before = y.indexOf('App のものが足りません'), deploy = y.indexOf('$W deploy');
  ok(before > 0 && deploy > before && /秘密APP_CLIENT_SECRET/.test(y) && /秘密AUTH_STATE_SECRET/.test(y) && /変数APP_CLIENT_ID/.test(y), 'the App\'s id and secrets checked before deploying');
  ok(/workers\\\.dev subdomain/.test(y) && /トークンを断りました/.test(y) && /アカウント ID が違う/.test(y), 'Cloudflare\'s refusals said');
  ok(y.indexOf('/health') > deploy && y.indexOf('/health') < y.indexOf('::notice title=auth-url::'), '/health looked at before the address is handed on');
  ok(!/echo .*\$CLIENT_SECRET|\$STATE_SECRET"? *\|\| *true|--var "GITHUB_CLIENT_SECRET/.test(y), 'the App\'s secrets never on a command line or in the log');
});

await t('全自動で準備する with Cloudflare\'s token pasted first: the address settled before the App (auth-deploy.yml plan), the App made with its Callback URL and the lab told so (APP_CALLBACK_URL); an App whose Callback URL is not the service\'s made again — GitHub\'s buttons, nothing to paste (fake DOM, fake GitHub)', async () => {
  const R = (key, ok, fix = null, extra = {}) => ({ key, label: key, ok, need: ok === true ? '' : `${key} needed`, fix, ...extra });
  eq(S.autoNext([R('pages', true), R('app', false, { manifest: true }, { cfReady: true })]), { kind: 'plan' }, 'the address first');
  eq(S.autoNext([R('pages', true), R('app', false, { manifest: true }, { cfReady: true })], { planned: AUTH_URL }), { kind: 'app' }, 'then the App');
  eq(S.autoNext([R('pages', true), R('app', true), R('installed', true), R('auth', true), R('callback', false, { manifest: true, remake: true })]), { kind: 'app', remake: true }, 'a Callback URL not the service\'s: the App made again');
  const m = S.appManifest({ owner: 'noknoh12345-afk', repo: 'bds-lab', panelUrl: 'https://x.github.io/bds-lab/', authUrl: AUTH_URL, suffix: 'ab12' });
  ok(m.name === 'bds-lab-noknoh12345-afk-ab12' && m.name.length <= 34 && m.callback_urls[0] === `${AUTH_URL}/callback`, JSON.stringify([m.name, m.callback_urls]));
  ok(S.appManifest({ owner: 'a-very-long-organisation-name', repo: 'bds-lab', panelUrl: 'https://x/', suffix: 'ab12' }).name.length <= 34, 'still 34 at most');
  const { E } = fakeDom();
  const UI = await imp('panel/ui/setup.mjs');
  const f = await fakeGitHub({ pages: { build_type: 'workflow' } });
  try {
    const store = AC.memoryStorage(), submitted = [];
    globalThis.document.body.append = (x) => { x.requestSubmit = () => { x.fire('submit'); submitted.push(x); }; };
    const ctx = { api: f.api, lab: LAB({ secrets: ['CLOUDFLARE_API_TOKEN'], repo: { default_branch: 'main', owner: { login: 'o', type: 'User', id: 11 }, id: 22 } }), hosts: [], me: { login: 'o' }, config: {}, panelUrl: 'https://o.github.io/lab/', signedInWithApp: false, fetchImpl: f.fetchImpl, storage: store, wait: QUICK,
      location: { search: '', hash: '#setup', pathname: '/lab/', assign() {} }, history: { replaceState() {} } };
    const body = new E('div');
    await UI.setupTab(body, ctx);
    await body.all((e) => e.tagName === 'BUTTON' && e.textContent === '全自動で準備する')[0].click();
    const plan = f.st.seen.find((x) => /auth-deploy\.yml\/dispatches/.test(x.u));
    eq(JSON.parse(plan.body).inputs, { plan: 'true' }, 'auth-deploy.yml asked for the address only');
    eq(submitted.length, 1, 'then the App\'s form');
    const manifest = JSON.parse(submitted[0].all((e) => e.tagName === 'INPUT' && e.attrs.type === 'hidden')[0].value);
    eq(manifest.callback_urls, [`${AUTH_URL}/callback`], 'the App made with its Callback URL already right');
    const kept = JSON.parse(store.getItem('bdslab.setup.manifest'));
    eq(kept.callback, `${AUTH_URL}/callback`, 'kept for the way back');
    // the way back: the Callback URL the App was made with, kept in the lab
    const r = await S.storeApp(f.api, 'o/lab', await f.api.appFromManifest('c0de'), { callback: kept.callback });
    ok(r.variables.includes('APP_CALLBACK_URL') && f.st.vars.get('APP_CALLBACK_URL') === `${AUTH_URL}/callback`, JSON.stringify(r));
  } finally { f.close(); delete globalThis.document.body.append; }
});

await t('a failure\'s notice offers the way out the page gives it (setOnFail: e.g. more rights), nothing when it gives none or it throws', async () => {
  const { toast } = fakeDom();
  const D = await imp('panel/ui/dom.mjs');
  const last = () => toast.kids.at(-1);
  D.setOnFail((e) => (e.status === 403 ? D.link(S.tokenUrl('o'), 'トークンを作り直す') : null));
  ok(await D.act(async () => { throw new G.GhError(403, 'このトークンには、その操作の権限がありません（no）', '/x'); }) === undefined, 'act answers undefined on a failure');
  const a = last().all((x) => x.tagName === 'A')[0];
  ok(last().className === 'bad' && /権限がありません/.test(last().textContent) && a?.attrs.href === S.tokenUrl('o') && /作り直す/.test(a.textContent), last().textContent);
  await D.act(async () => { throw new G.GhError(500, 'GitHub: 500', '/x'); });
  ok(!last().all((x) => x.tagName === 'A').length, 'no way out offered for another failure');
  D.setOnFail(() => { throw new Error('boom'); });
  await D.act(async () => { throw new Error('plain'); });
  ok(last().textContent === 'plain', 'a way out that throws: the notice alone');
  D.setOnFail(null);
});

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
