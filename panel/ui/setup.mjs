// setup (the 「準備」 tab): the lab's checks (lib/setup.mjs) as a list — what is there, what is missing and why — with the
// buttons that fix it for the lab's administrators whose role the policy lets do what each fix does (anyone else sees the
// list and why not: GitHub would refuse them anyway), the GitHub App made by a real form posted to GitHub (its manifest in a
// hidden field; the page's CSP lets a form go to github.com alone), and the way back: GitHub's ?code= taken once, checked
// against the state this tab sent, removed from the address at once, and — only when this lab, this person and the policy
// may keep it — turned into the App's keys and sealed into the lab's secrets (storeApp: nothing kept, nothing shown). A
// secret typed into a fix's field is sealed and sent, and the field emptied (the browser is not asked to remember it).
import { h, toast, act, link, failView } from './dom.mjs';
import * as S from '../lib/setup.mjs';
import * as P from '../lib/policy.mjs';
import { pluginZip, PLUGIN_NAME } from '../lib/pluginpack.mjs';

const STATE_KEY = 'bdslab.setup.manifest';
const ICON = (ok) => (ok === null ? '❔ ' : ok ? '✅ ' : '⚠️ ');

/** the 「準備」 tab. ctx: { api, lab: { slug, repo, role, secrets, workflows }, hosts, me, config: { authUrl, appSlug,
 *  appClientId }, panelUrl, signedInWithApp, policy (lib/policy.mjs), role (policy.roleFor's answer; else lab.role), reload,
 *  record(action, detail)? (the audit log), appReturn? (takeAppReturn's answer, when panel.js took it first) } — location,
 *  history and sessionStorage are the page's (ctx.location / ctx.history / ctx.storage: tests only). → a promise of the
 *  checks drawn */
export function setupTab(body, ctx) {
  const admin = ctx.lab?.role === 'admin', back = h('div', {}), list = h('ul', { class: 'plain' }, h('li', { class: 'muted' }, '確かめています…'));
  body.append(h('div', { class: 'card' }, h('h2', {}, `準備と診断（${ctx.lab.slug}）`),
    h('p', { class: 'muted' }, admin ? 'サインインと許可の準備を、上から順に確かめます。⚠️ の行のボタンで、このパネルから直せます（秘密はこのブラウザで封じてから GitHub へ。値は残しません）。'
      : '見るだけです: 直すのはラボの管理者です（GitHub が管理者にだけ許します）。貸し手に渡すリンクは誰でも使えます。'),
    back, admin ? autoCard(ctx, () => draw()) : null, list), ctx.config?.authUrl ? aiCard(ctx) : null);
  // (a check that could not be made at all: the words of why and the way on, with 「もう一度」 — never the waiting line for good)
  const draw = async () => {
    try { const cs = await S.checks(ctx); list.replaceChildren(...cs.map((c) => row(ctx, c))); lastChecks = cs; return cs; } catch (e) {
      list.replaceChildren(h('li', {}, failView(e, draw), h('div', { class: 'muted' }, 'ラボを読めませんでした: つながりを確かめて「もう一度」。続くときは、権限の足りたトークンで入り直します。'), link(S.tokenUrl(ctx.lab.slug.split('/')[0]), '権限が全部入ったトークンを作る（GitHub へ）')));
      return undefined;
    }
  };
  // (the newest tab drawn is the one a run going on uses: the lab read again after the App's keys are kept, not the old one)
  live = { ctx, draw };
  return comeBack(ctx, back).then(draw).then(async (cs) => { if (cs && autoOn(ctx)) await autoRun(ctx, draw); return cs; });
}
let live = null, lastChecks = null;

// ---- 「全自動で準備する」: everything the panel may do itself, in order, the person pressing only GitHub's two buttons (make the
// App, install it); the run goes on by itself when the tab comes back from GitHub (its stage kept in this tab) ----
const AUTO_KEY = 'bdslab.setup.auto';
const autoGet = (ctx) => { try { const a = JSON.parse((ctx.storage ?? globalThis.sessionStorage).getItem(AUTO_KEY) ?? 'null'); return a?.lab === ctx.lab.slug && Date.now() - Number(a.at) < 3_600_000 ? a : null; } catch { return null; /* not ours: no run going on */ } };
const autoSet = (ctx, v) => { const st = ctx.storage ?? globalThis.sessionStorage; if (v) st.setItem(AUTO_KEY, JSON.stringify({ ...v, lab: ctx.lab.slug, at: Date.now() })); else st.removeItem(AUTO_KEY); };
const autoOn = (ctx) => Boolean(autoGet(ctx));
let autoSay = null;
function autoCard(ctx, draw) {
  const say = h('div', { class: 'muted', role: 'status' });
  autoSay = say;
  // (nothing to type: the button alone; what only typing could set up is skipped and said)
  const go = h('button', { class: 'primary', onclick: async () => {
    go.disabled = true;
    // (Cloudflare's token page opened now, while this press still counts as the person's — a browser lets a page open a tab
    // only then; the run below then waits for the token instead of opening it itself)
    const d = lastChecks?.find((c) => c.key === 'deploy');
    if (d && d.ok === false && (d.fix?.inputs ?? []).some((i) => i.name === 'token') && d.fix.help?.link && !notAllowed(ctx, d.fix)) cfOpen(ctx, d.fix.help.link);
    try {
      autoSet(ctx, { stage: 'go', installed: Boolean(autoGet(ctx)?.installed) || instGet(ctx) });
      await autoRun(ctx, draw);
    } finally { go.disabled = false; }
  } }, '全自動で準備する');
  return h('div', { class: 'card' }, h('h3', {}, '⚡ 全自動で準備する'),
    h('p', { class: 'muted' }, '押すと、パネルができることを上から順に全部やります。Cloudflare の画面も自動で開きます（「Continue to summary」→「Create Token」→「Copy」だけ。このタブに戻ると、コピーしたトークンを自動で読んで続けます）。あとは GitHub の画面の「Create GitHub App」と「Install」を押すだけで、戻ってくると続きを自動でやります。'),
    h('div', { class: 'row' }, go), say);
}
/** one step after another until GitHub needs the person (it leaves the page), it is truly done, or it stops and says why;
 *  at most 12 steps a visit */
let autoBusy = false;
// (that this tab went to install the App on this lab: kept in the tab — a token's sign-in never sees installations, so a run
// started again does not send the person to install it once more)
const instKey = (ctx) => `bdslab.setup.installed.${ctx.lab.slug}`;
const instGet = (ctx) => { try { return (ctx.storage ?? globalThis.sessionStorage).getItem(instKey(ctx)) === '1'; } catch { return false; } };
const instSet = (ctx, on) => { try { const st = ctx.storage ?? globalThis.sessionStorage; if (on) st.setItem(instKey(ctx), '1'); else st.removeItem(instKey(ctx)); } catch { /* this tab only */ } };
async function autoRun(ctx, draw) {
  // (one run at a time: the tab drawn again while one goes on — after the App's keys are kept — does not start a second)
  if (autoBusy) return;
  autoBusy = true;
  try { await autoSteps(ctx, draw); } catch (e) { autoSet(ctx, null); autoSay?.replaceChildren(`止まりました: ${e?.message ?? e}`); } finally { autoBusy = false; }
}
async function autoSteps(ctx0, draw0) {
  const say = (t, kids = []) => { autoSay?.replaceChildren(t, ...kids); };
  const cur = () => (live && live.ctx.lab?.slug === ctx0.lab.slug ? live : { ctx: ctx0, draw: draw0 });
  const halt = (t, kids) => { autoSet(cur().ctx, null); say(`⛔ 止まりました: ${t}`, kids); };
  for (let i = 0; i < 12; i++) {
    const { ctx, draw } = cur();
    const a = autoGet(ctx); if (!a) return;
    if (a.installed) instSet(ctx, true);
    // (the page told to learn the service's address: wait until it has (config.json) and the service answers, then load the
    // page again — the address goes into the page's CSP, which only a new load takes)
    if (a.stage === 'wait-live' && !ctx.config?.authUrl) {
      say('ページとサービスが新しくなるのを待っています…');
      const url = await S.waitLive({ want: a.want ?? null, configUrl: ctx.configUrl ?? './config.json', fetchImpl: ctx.fetchImpl, ...(ctx.wait ?? {}), onStep: (t) => say(t) });
      autoSet(ctx, { ...a, stage: 'go' });
      say(`✅ ${url} が答えました: ページを読み直して続けます`);
      (ctx.reloadPage ?? (() => (ctx.location ?? globalThis.location).reload()))();
      return;
    }
    const cs = await draw();
    if (!cs) return halt('準備の様子を読めませんでした: 上の「もう一度」から');
    const next = S.autoNext(cs, { installed: Boolean(a.installed), planned: a.planned ?? null, cfSkip: Boolean(a.cfSkip) });
    if (next.kind === 'run') {
      const c = cs.find((x) => x.key === next.key), no = notAllowed(ctx, c.fix);
      if (no) return halt(`${c.label} — ${no}`);
      say(`${c.label}: やっています…`);
      const msg = await act(() => c.fix.run({}, { onStep: (t) => say(`${c.label}: ${t}`) }));
      if (msg === undefined) return halt(`${c.label}（上の知らせに理由と次の 1 手）。直してから、もう一度「全自動で準備する」`);
      ctx.record?.(`setup.${c.key}`, { auto: true });
      if (next.key === 'deploy' || next.key === 'auth') {
        const want = (/https:\/\/[A-Za-z0-9.-]+/.exec(msg) ?? [])[0] ?? null;
        autoSet(ctx, { ...a, stage: 'wait-live', want: S.cleanAuthUrl(want) });
        continue;
      }
      continue;
    }
    if (next.kind === 'cloudflare') {
      const d = cs.find((x) => x.key === 'deploy'), no = notAllowed(ctx, d?.fix);
      if (no) { autoSet(ctx, { ...a, cfSkip: true }); continue; }
      autoSet(ctx, { ...a, stage: 'cf-wait' });
      const opened = cfWin || cfOpen(ctx, next.link);
      cfWait(ctx, { link: next.link, opened, say });
      return;
    }
    if (next.kind === 'plan') {
      const no = notAllowed(ctx, { needs: ['dispatch'] });
      if (no) return halt(`Cloudflare を確かめられません — ${no}`);
      const url = await act(() => S.planAuth(ctx.api, ctx.lab.slug, { ref: ctx.lab.repo?.default_branch ?? 'main', me: ctx.me?.login, onStep: (t) => say(t), ...(ctx.wait ?? {}) }));
      if (url === undefined) return halt('Cloudflare を確かめられませんでした（上の知らせに理由）。直してから、もう一度「全自動で準備する」');
      autoSet(ctx, { ...a, planned: url });
      continue;
    }
    if (next.kind === 'app') {
      const no = notAllowed(ctx, { needs: S.APP_NEEDS });
      if (no) return halt(`App を作れません — ${no}`);
      say(next.remake ? 'GitHub の画面へ: Callback URL 入りの App を作ります。「Create GitHub App」を押してください（戻ってくると続きます）' : 'GitHub の画面へ: 「Create GitHub App」を押してください（戻ってくると続きます）');
      // (a new App is installed anew: the way there again)
      if (next.remake) instSet(ctx, false);
      autoSet(ctx, { ...a, stage: 'app', ...(next.remake ? { installed: false } : {}) });
      const f = appForm(ctx, { remake: Boolean(next.remake), planned: a.planned ?? null });
      if (f.tagName !== 'FORM') return halt(f.textContent);
      f.hidden = true; globalThis.document.body.append(f);
      // (requestSubmit: the form's own submit — its state kept for the way back — then to GitHub)
      if (typeof f.requestSubmit === 'function') f.requestSubmit(); else { f.dispatchEvent?.(new globalThis.Event('submit')); f.submit?.(); }
      return;
    }
    if (next.kind === 'install') {
      const appSlug = cs.find((c) => c.key === 'app')?.slug ?? ctx.config?.appSlug;
      const to = S.installLink(appSlug, ctx.lab.repo?.owner?.id, ctx.lab.repo?.id);
      if (!to) return halt('App の名前（APP_SLUG）が分からないので、入れるページを開けません: 「GitHub App」の行から');
      say('GitHub の画面へ: ラボを選んである「Install」を押してください（戻ってくると続きます）');
      autoSet(ctx, { ...a, stage: 'go', installed: true });
      (ctx.location ?? globalThis.location).assign(to);
      return;
    }
    if (next.kind === 'stop') {
      const c = cs.find((x) => x.key === next.key);
      return halt(`${c?.label ?? next.key} — ${next.why}`, next.link ? [h('div', { class: 'row' }, link(next.link, next.linkLabel ?? 'GitHub へ'))] : []);
    }
    // (done: every row ✅ — said only now)
    autoSet(ctx, null);
    return say(next.skipped?.length ? `✅ 準備はすべて終わりました（飛ばしたもの: ${next.skipped.join('・')}。サインインは今と同じトークンで）` : '✅ 準備はすべて終わりました（全部の行が ✅）');
  }
  halt('同じことを 12 回繰り返したので止めました: 下の ⚠️ の行を見てください');
}
// ---- Cloudflare: its token page opened by the run, the token read back from the clipboard when this tab comes back (the
// browser asks once), or pasted into the one field — either way the run goes on by itself; nothing is pressed here ----
let cfWin = null, cfStop = null;
const TOKEN_SHAPE = /^[A-Za-z0-9_-]{30,200}$/;
function cfOpen(ctx, url) {
  if (!url) return null;
  try { const w = (ctx.open ?? globalThis.open)?.(url, '_blank'); if (w) { try { w.opener = null; } catch { /* another origin */ } cfWin = w; } return w ?? null; } catch { return null; }
}
function cfWait(ctx, { link: url, opened, say }) {
  cfStop?.();
  const field = h('input', { type: 'password', autocomplete: 'off', 'aria-label': 'Cloudflare のトークン', placeholder: 'ここに貼る（貼るだけで続きます）' });
  let done = false;
  const take = async (raw) => {
    const token = String(raw ?? '').trim();
    if (done || !TOKEN_SHAPE.test(token) || S.cfProblem({ token })) return false;
    done = true; cfStop?.(); field.value = '';
    say('Cloudflare のトークンを封じて登録しています…');
    const ok = await act(async () => { await ctx.api.putSecret(ctx.lab.slug, 'CLOUDFLARE_API_TOKEN', token); return true; });
    if (!ok) { done = false; return false; }
    ctx.lab.secrets = [...new Set([...(ctx.lab.secrets ?? []), 'CLOUDFLARE_API_TOKEN'])];
    try { cfWin?.close?.(); } catch { /* its own tab */ } cfWin = null;
    // (the stage moved on before anything that may draw the tab again — the audit log — so a redraw does not start a second run)
    autoSet(ctx, { ...(autoGet(ctx) ?? {}), stage: 'go' });
    ctx.record?.('setup.deploy', { auto: true });
    const l = live?.ctx?.lab?.slug === ctx.lab.slug ? live : { ctx, draw: async () => undefined };
    await autoRun(l.ctx, l.draw);
    return true;
  };
  // (back in this tab: the clipboard read — a token copied on Cloudflare's page goes on without a paste)
  const clip = ctx.clipboard ?? globalThis.navigator?.clipboard;
  const tryClip = async () => { if (done) return; try { const t = await clip?.readText?.(); if (await take(t)) return; } catch { /* not allowed: the field */ } field.focus?.(); };
  const win = ctx.win ?? globalThis;
  const onFocus = () => tryClip();
  const onVis = () => (globalThis.document?.visibilityState === 'hidden' ? undefined : tryClip());
  win.addEventListener?.('focus', onFocus); globalThis.document?.addEventListener?.('visibilitychange', onVis);
  cfStop = () => { win.removeEventListener?.('focus', onFocus); globalThis.document?.removeEventListener?.('visibilitychange', onVis); cfStop = null; };
  field.addEventListener('input', () => take(field.value));
  field.addEventListener('paste', (e) => { const t = e?.clipboardData?.getData?.('text'); return t ? take(t) : undefined; });
  const skip = h('button', { onclick: async () => { cfStop?.(); autoSet(ctx, { ...(autoGet(ctx) ?? {}), stage: 'go', cfSkip: true }); const l = live?.ctx?.lab?.slug === ctx.lab.slug ? live : { ctx, draw: async () => undefined }; await autoRun(l.ctx, l.draw); } }, '「GitHub でサインイン」は今は使わない（飛ばす）');
  // (the browser blocked the tab — a run that went on from GitHub's way back has no press of the person's: one press opens it)
  const openBtn = opened ? null : h('button', { class: 'primary', onclick: () => { cfOpen(ctx, url); } }, 'Cloudflare を開く');
  say(opened ? '👉 開いた Cloudflare のタブで（ログイン画面が出たら「Sign in with GitHub」→ 初回だけ GitHub の「Authorize cloudflare」）「Continue to summary」→「Create Token」→「Copy」を押して、このタブに戻ってください（コピーしたトークンを自動で読んで続けます）。読めないときは、下の欄に貼るだけ。'
    : '👉 「Cloudflare を開く」→（ログイン画面なら「Sign in with GitHub」）→「Continue to summary」→「Create Token」→「Copy」→ このタブに戻るだけ（コピーしたトークンを自動で読んで続けます）。読めないときは、下の欄に貼るだけ。',
  [h('div', { class: 'row' }, openBtn, skip), field]);
  if (opened === null && !openBtn) field.focus?.();
  return { take, tryClip };
}
// ---- 🤖 AI から操作: the lab's API for AI (auth/api.mjs) on the sign-in service — its MCP address, how Claude (and any other
// AI) connects, a check that it answers, and the lab's Claude plugin (lib/pluginpack.mjs) to hand to Claude ----
function aiCard(ctx) {
  const base = ctx.config.authUrl, mcp = `${base}/mcp`, say = h('div', { class: 'muted', role: 'status' });
  const copy = (text, what) => h('button', { onclick: () => act(() => globalThis.navigator.clipboard.writeText(text), `${what}をコピーしました`) }, 'コピー');
  const code = `claude mcp add --transport http ${PLUGIN_NAME} ${mcp}`;
  // (any AI that can read the web: one sentence — it reads the service's own instructions, shows a link, the person approves)
  const ask = `このラボを操作して: ${base}/llms.txt を読み、そこにある「デバイスのサインイン」でつないでください（出たリンクを私が開いて許可します）`;
  const check = h('button', { onclick: async () => {
    say.replaceChildren('確かめています…');
    try {
      const r = await (ctx.fetchImpl ?? ((...a) => globalThis.fetch(...a)))(`${base}/api`, { cache: 'no-store', credentials: 'omit' });
      const j = r.ok ? await r.json() : null;
      say.replaceChildren(j?.tools?.length ? `✅ API が答えました: 道具 ${j.tools.length} 個（${j.lab}）。Claude からつなげます${j.auth?.device ? '。コードでつなぐ方法（どの AI でも）も使えます' : '（コードでつなぐ方法は、この Cloudflare のアカウントでは使えません: MCP の OAuth か GitHub のトークンで）'}` : `⚠️ API がまだありません（HTTP ${r.status}）: サインインのサービスを置き直すと入ります（上の行の「auth-deploy.yml でもう一度置く」か「全自動で準備する」）`);
    } catch (e) { say.replaceChildren(`⚠️ つながりません（${e?.message ?? e}）`); }
  } }, 'API を確かめる');
  const dl = h('button', { onclick: () => act(async () => {
    const lab = ctx.lab.slug, bytes = pluginZip({ mcpUrl: mcp, lab, panelUrl: ctx.panelUrl });
    if (typeof globalThis.URL?.createObjectURL !== 'function') throw new Error('このブラウザではファイルを作れません');
    const href = URL.createObjectURL(new Blob([bytes], { type: 'application/zip' })), a = h('a', { href, download: `${PLUGIN_NAME}.plugin` });
    globalThis.document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(href), 10_000);
  }, `${PLUGIN_NAME}.plugin を作りました: Claude のチャットに添付して「入れて」と頼むか、Claude の設定のプラグインから入れます`) }, 'Claude 用プラグイン（.plugin）');
  return h('div', { class: 'card', id: 'ai' }, h('h2', {}, '🤖 AI から操作（Claude ほか）'),
    h('p', { class: 'muted' }, 'AI がこのラボを直接操作できます: 様子・実行・ログ・ファイル・試験と仕上げ・秘密・変数・メンバー・予約。AI はつないだ人の GitHub のアカウントで動き、GitHub の権限・ラボの役割の決まり・確認・監査ログはこのパネルと同じです。.github/（CI と決まり）、auto/policy.json・auto/STOP、.env は AI からは変えられません。'),
    h('label', {}, 'MCP の URL'), h('div', { class: 'row' }, h('code', {}, mcp), copy(mcp, 'MCP の URL')),
    h('ol', {},
      h('li', {}, 'Claude（アプリ・Web）: 下の「Claude 用プラグイン」をチャットに添付して入れる。または「設定」→「コネクタ」→「カスタムコネクタを追加」に上の URL。最初に使うとき「許可して GitHub へ」→ GitHub の「Authorize」。'),
      h('li', {}, 'Claude Code: ', h('code', {}, code), ' ', copy(code, 'コマンド')),
      h('li', {}, 'どの AI でも（コードでつなぐ）: AI にこう頼むだけ → AI が出すリンクを開いて「許可して GitHub へ」→ GitHub の「Authorize」。', h('div', { class: 'row' }, h('code', {}, ask), copy(ask, '頼み方'))),
      h('li', {}, 'スクリプト: ', h('code', {}, `POST ${base}/api/<道具>`), '（Authorization: Bearer <コードで受け取ったトークンか GitHub のトークン>。読むだけの道具は GET でも。一覧は ', h('code', {}, `GET ${base}/api`), '、説明は ', link(`${base}/`, 'AI 用のページ'), '・', link(`${base}/openapi.json`, 'OpenAPI'), '）')),
    h('div', { class: 'row' }, dl, check), say);
}
const roleName = (r) => (typeof r === 'string' ? r : r?.name ?? (r?.names?.length ? `${r.names.join(' か ')}（チームが読めません）` : 'なし'));
/** why this person may not use a fix (words), null when they may: the lab's administrator on GitHub, and the policy's role
 *  allows each thing the fix does (its needs) */
function notAllowed(ctx, f) {
  if (ctx.lab?.role !== 'admin') return 'ラボの管理者が直せます（GitHub でこのラボの admin の人）';
  const policy = ctx.policy ?? P.DEFAULT_POLICY, role = ctx.role ?? ctx.lab.role;
  const no = (f?.needs ?? []).filter((a) => !P.can(policy, role, a));
  return no.length ? `役割「${roleName(role)}」には、ポリシー（${P.POLICY_FILE} の roles）が「${no.map((a) => P.ACTION_WORDS[a] ?? a).join('・')}」を許していません` : null;
}

/** one check: what it found, what is missing, and its fix (a link for anyone; a button, an input or the App's form for the
 *  lab's administrators the policy lets do it; why not for anyone else) */
function row(ctx, c) {
  return h('li', { 'data-check': c.key }, h('div', {}, ICON(c.ok), h('strong', {}, c.label)), c.need ? h('div', { class: 'muted' }, c.need) : null, fixOf(ctx, c));
}
function fixOf(ctx, c) {
  const f = c.fix;
  // (no fix of its own: another row comes first — a link that takes there; not a button: the buttons are the fixes)
  if (!f) return c.next && c.ok !== true ? h('div', { class: 'row' }, h('a', { class: 'btn', href: '#setup', role: 'button', onclick: (ev) => { ev?.preventDefault?.(); globalThis.document.querySelector?.(`[data-check="${c.next.goto}"]`)?.scrollIntoView?.(); } }, c.next.label)) : null;
  if (f.link) return h('div', { class: 'row' }, link(f.link, f.label), h('button', { onclick: () => act(() => globalThis.navigator.clipboard.writeText(f.link), 'リンクをコピーしました') }, 'コピー'));
  const no = notAllowed(ctx, f);
  if (no) return c.ok === true ? null : h('div', { class: 'muted' }, `（${no}）`);
  if (f.manifest) return appForm(ctx, { remake: Boolean(f.remake) });
  // (a secret's field: not offered to the browser's password manager)
  const fields = (f.inputs ?? []).map((i) => [i, h('input', { type: i.secret ? 'password' : 'text', autocomplete: 'off', placeholder: i.placeholder ?? null, 'aria-label': i.label })]);
  const step = h('div', { class: 'muted' });
  const btn = h('button', { class: c.ok === true ? null : 'primary', onclick: async () => {
    const values = Object.fromEntries(fields.map(([i, el]) => [i.name, el.value.trim()]));
    const empty = fields.find(([, el]) => !el.value.trim());
    if (empty) return toast(`空の欄があります: 「${empty[0].label}」を入れてください`, true);
    btn.disabled = true;
    const msg = await act(() => f.run(values, { onStep: (t) => step.replaceChildren(t) }));
    // (what was typed leaves the page: sealed and sent, or refused)
    for (const [, el] of fields) el.value = '';
    btn.disabled = false;
    if (msg === undefined) return;
    toast(msg); step.replaceChildren(msg);
    ctx.record?.(`setup.${c.key.split(':')[0]}`, {});
    // (a paste that starts the rest: 「全自動で準備する」 goes on from here by itself — put in place: wait for the page and the
    // service; only stored: the App made with the service's address, then put in place)
    if (f.auto) {
      const want = S.cleanAuthUrl((/https:\/\/[A-Za-z0-9.-]+/.exec(msg) ?? [])[0]);
      const app = (await S.checks(ctx).catch(() => [])).find((x) => x.key === 'app');
      autoSet(ctx, want ? { stage: 'wait-live', want, installed: Boolean(app?.ok) } : { stage: 'go', installed: Boolean(autoGet(ctx)?.installed) });
      return autoRun(live?.ctx ?? ctx, live?.draw ?? (async () => undefined));
    }
    ctx.reload?.();
  } }, f.label);
  // (a link to where the value is made — Cloudflare's token page — above the field; another way folded below)
  const help = f.help?.link ? h('div', { class: 'row' }, link(f.help.link, f.help.label)) : null;
  const alt = f.alt ? h('details', {}, h('summary', {}, '自分のサーバーに置いたとき'), fixOf(ctx, { ...c, fix: f.alt })) : null;
  return h('div', {}, help, fields.map(([i, el]) => [h('label', {}, i.label), el]), h('div', { class: 'row' }, btn), step, alt);
}

/** the App's form: posted to GitHub with its manifest; the state it carries kept in this tab to know the way back */
function appForm(ctx, { remake = false, planned = null } = {}) {
  const owner = ctx.lab.repo?.owner?.login ?? ctx.lab.slug.split('/')[0], isOrg = ctx.lab.repo?.owner?.type === 'Organization', state = S.newState();
  // (the service's address when it is known — put in place, or planned from Cloudflare — so the App's Callback URL is right
  // from the start; an App made again takes a short suffix, its old name being taken)
  const manifest = S.appManifest({ owner, repo: ctx.lab.slug.split('/')[1], panelUrl: ctx.panelUrl, authUrl: ctx.config?.authUrl ?? planned ?? autoGet(ctx)?.planned ?? null, suffix: remake ? state.slice(0, 4) : '' });
  const callback = manifest.callback_urls[0] ?? null;
  const store = ctx.storage ?? globalThis.sessionStorage;
  // (what GitHub would refuse, said here before going: never its 「Invalid GitHub App configuration」 page)
  const bad = S.manifestProblems(manifest);
  if (bad.length) return h('div', { class: 'bad', role: 'alert' }, `App の設定に GitHub が受け付けないものがあります: ${bad.join('・')}。パネルの不具合です: この文を写して作者に知らせてください`);
  return h('form', { method: 'post', action: S.manifestAction(owner, isOrg, state), onsubmit: () => store.setItem(STATE_KEY, JSON.stringify({ state, lab: ctx.lab.slug, owner, isOrg, callback, at: Date.now() })) },
    h('input', { type: 'hidden', name: 'manifest', value: JSON.stringify(manifest) }),
    h('p', { class: 'muted' }, isOrg ? `組織 ${owner} の App として作ります（組織の管理者だけが作れます）。` : `あなた（${ctx.me?.login ?? owner}）のアカウントの App として作ります。`,
      `名前「${manifest.name}」は GitHub の画面で変えられます。権限: ${Object.entries(S.APP_PERMISSIONS).map(([k, v]) => `${k}=${v}`).join(' ')}`),
    h('div', { class: 'row' }, h('button', { class: 'primary', type: 'submit' }, 'App を作る（GitHub へ）')));
}

/** GitHub's way back from making the App, taken out of the address at once (panel.js may call it first thing, before any
 *  request, and hand its answer to setupTab as ctx.appReturn): the state kept by this tab's form used once → { code, lab,
 *  owner, isOrg } (whose App it is), { error } (not this tab's, or older than GitHub's hour), or null when the address has
 *  no code */
export function takeAppReturn({ location: loc = globalThis.location, history: hist = globalThis.history, storage: store = globalThis.sessionStorage } = {}) {
  if (!/[?&]code=/.test(String(loc?.search ?? '')) && !/[?&]code=/.test(String(loc?.hash ?? ''))) return null;
  let saved = null;
  try { saved = JSON.parse(store.getItem(STATE_KEY) ?? 'null'); } catch { /* not ours */ }
  store.removeItem(STATE_KEY);
  const got = S.takeManifestCode(loc.search, saved?.state) ?? S.takeManifestCode(loc.hash, saved?.state);
  // (out of the address at once: not in the history, a bookmark or a shared link)
  hist.replaceState(null, '', `${loc.pathname}#setup`);
  if (!got || !(Date.now() - Number(saved?.at) < 3_600_000)) return { error: '戻ってきた App の code は、このタブで始めたものではないか古いので使いません（もう一度「App を作る」から）' };
  return { code: got.code, lab: saved.lab, owner: /^[A-Za-z0-9-]{1,39}$/.test(String(saved.owner ?? '')) ? saved.owner : null, isOrg: saved.isOrg === true, callback: typeof saved.callback === 'string' ? saved.callback : null };
}

/** the way back used (once): this lab, its administrator and the policy looked at first — the code is turned into the App's
 *  keys only when they can be kept here, sealed into the lab's secrets; else what to do with the App GitHub already made */
async function comeBack(ctx, box) {
  const ret = ctx.appReturn !== undefined ? ctx.appReturn : takeAppReturn({ location: ctx.location, history: ctx.history, storage: ctx.storage });
  if (!ret || ret.used) return;
  ret.used = true;
  if (ret.error) return box.replaceChildren(h('p', { class: 'bad' }, ret.error));
  const no = ret.lab !== ctx.lab.slug ? `別のラボ（${ret.lab}）のものです` : notAllowed(ctx, { needs: S.APP_NEEDS });
  if (no) {
    return box.replaceChildren(h('p', { class: 'bad' }, `戻ってきた App の code は使いません: ${no}。`),
      h('p', { class: 'muted' }, `App は GitHub にできています: App の設定で鍵（private key・client secret）を作り直し、ラボ（${ret.lab}）の管理者が「秘密」で APP_PRIVATE_KEY・APP_CLIENT_SECRET に（App の id・slug・client ID は「変数」の APP_ID・APP_SLUG・APP_CLIENT_ID に）入れるか、要らなければ App を消してください（消せば、もう一度「App を作る」から）。`),
      link(S.appsUrl(ret.owner, ret.isOrg), 'App の設定（GitHub へ）'));
  }
  box.replaceChildren(h('p', { class: 'muted' }, 'GitHub から App の鍵を受け取り、ラボの秘密に封じています…'));
  const r = await act(async () => S.storeApp(ctx.api, ctx.lab.slug, await ctx.api.appFromManifest(ret.code), { callback: ret.callback ?? null }));
  if (!r) return box.replaceChildren(h('p', { class: 'bad' }, 'App を入れられませんでした（上の知らせに理由があります）。GitHub に App ができているかもしれません: 下のリンクで見て、あれば鍵を作り直して「秘密」に入れるか、消してもう一度「App を作る」から。'), link(S.appsUrl(ret.owner, ret.isOrg), 'App の設定（GitHub へ）'));
  box.replaceChildren(h('p', { class: 'ok' }, `✅ App ${r.slug} を作り、秘密 ${r.secrets.join('・')} と変数 ${r.variables.join('・')} を入れました。次は「App を入れる」です。`), r.url ? link(r.url, 'App のページ（GitHub）') : null);
  ctx.record?.('setup.app', { app: r.slug });
  ctx.reload?.();
}
