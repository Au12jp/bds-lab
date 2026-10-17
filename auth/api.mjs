// auth/api.mjs: the lab's API for AI — what the management panel does, as tools an AI calls: MCP (Streamable HTTP, POST
// /mcp: Claude's apps and connectors, Claude Code, any MCP client) or plain HTTP (GET /api: the tools; POST /api/<tool>: one
// call). It runs beside the sign-in service (handler.mjs) on the same Worker, acts on the one lab it was put in place for
// (LAB_SLUG) and with the caller's own GitHub user token — from MCP's sign-in (the lab's GitHub App, sealed by handler.mjs)
// or handed as it is (Authorization: Bearer <a GitHub token>) — through the panel's own modules (panel/lib): the same checks,
// the same role policy (.github/bds-lab-panel.json: GitHub's role first, never wider), the same confirmations (asked as
// confirm: true), the same audit log. It holds no token and adds no power: what GitHub lets that person do, and no more.
// Never through it: the lab's CI and policy (.github/ — but for the timetable, checked: schedule_set), auto/policy.json and
// auto/STOP, .env files: a person changes those. Runs as it is on Workers and Node 22 (no node: module).
import { gh, GhError, explain } from '../panel/lib/gh.mjs';
import { secretPayloadFast } from '../panel/lib/seal.mjs';
import * as P from '../panel/lib/policy.mjs';
import * as AU from '../panel/lib/audit.mjs';
import * as S from '../panel/lib/setup.mjs';
import * as U from '../panel/lib/units.mjs';
import * as W from '../panel/lib/workspace.mjs';
import * as FS from '../panel/lib/failsum.mjs';
import * as RI from '../panel/lib/runissue.mjs';
import * as M from '../panel/lib/members.mjs';
import * as R from '../panel/lib/releases.mjs';
import * as SC from '../panel/lib/schedule.mjs';
import { SLUG } from '../panel/lib/model.mjs';
import { tokenBox, HEADERS } from './handler.mjs';

export const API_VERSION = '1';
/** the MCP versions this server speaks (the newest first) */
export const MCP_VERSIONS = ['2025-06-18', '2025-03-26', '2024-11-05'];
const UA = `bds-lab-api/${API_VERSION}`;
const MAX_BODY = 2_000_000, LOG_MAX = 60_000, READ_MAX = 200_000, FILE_MAX = 1_400_000;
const FAILED = new Set(['failure', 'timed_out', 'cancelled', 'startup_failure', 'action_required']);
const CORS = { 'access-control-allow-origin': '*', 'access-control-allow-headers': 'authorization, content-type, mcp-protocol-version, mcp-session-id', 'access-control-allow-methods': 'GET, POST, OPTIONS', 'access-control-expose-headers': 'www-authenticate', 'access-control-max-age': '600' };
const reply = (status, body, extra = {}) => new Response(body === null ? null : JSON.stringify(body), { status, headers: { ...HEADERS, ...CORS, ...(body === null ? {} : { 'content-type': 'application/json; charset=utf-8' }), ...extra } });

/** a tool's refusal in words, with the HTTP status the plain API answers it with */
export class ToolError extends Error { constructor(message, status = 400) { super(message); this.status = status; } }
const no = (m, status) => new ToolError(m, status);
const enc = new TextEncoder();
const b64 = (bytes) => { let s = ''; for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000)); return btoa(s); };
// (a loop, not a callback per byte: a megabyte decoded within a Worker's short CPU time)
const unb64 = (s) => { const bin = atob(String(s ?? '').replace(/\s/g, '')), out = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i); return out; };
const utf8 = (bytes) => { try { return new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch { return null; } };
const encPath = (p) => String(p).split('/').map(encodeURIComponent).join('/');
const fileOf = (p) => String(p ?? '').split('/').pop();
const clip = (s, n) => { const t = String(s ?? ''); return t.length > n ? `${t.slice(0, n)}…` : t; };
const icon = (status, c) => (status !== 'completed' ? '⏳' : c === 'success' ? '✅' : c === 'skipped' ? '⏭' : c === 'cancelled' ? '⏹' : c === 'neutral' ? '➖' : '❌');
const runOf = (r) => ({ id: r.id, workflow: r.name, file: fileOf(r.path), event: r.event, status: r.status, conclusion: r.conclusion, branch: r.head_branch, sha: String(r.head_sha ?? '').slice(0, 7), title: r.display_title, actor: r.triggering_actor?.login ?? r.actor?.login ?? null, attempt: r.run_attempt, number: r.run_number, created: r.created_at, updated: r.updated_at, url: r.html_url });
const roleName = (r) => r?.name ?? r?.names?.join('・') ?? r?.repoRole ?? '?';
const NAME = /^[A-Z_][A-Z0-9_]{0,99}$/;
const nameOk = (n, what) => { if (!NAME.test(String(n ?? '')) || /^GITHUB_/.test(n)) throw no(`${what}の名前は英大文字・数字・_（GITHUB_ で始まらない）: ${n}`); return n; };
const refOk = (r) => { if (r === undefined || r === null || r === '') return undefined; const s = String(r); if (!/^[\w./-]{1,200}$/.test(s) || s.includes('..')) throw no(`ref・branch の形が違います: ${s}`); return s; };
/** a path in the lab as the tools take it (pure): relative, no .., no escapes, no control characters */
export function cleanPath(p, { dir = false } = {}) {
  const s = String(p ?? '').trim().replace(/^\.?\/+/, '').replace(/\/+$/, '');
  if (!dir && !s) throw no('path が要ります（例 bds/addons/coins/src/main.ts）');
  if (s.length > 400 || /(^|\/)\.\.?(\/|$)|\\|%2e|%2f|%5c|[\u0000-\u001f]/i.test(s)) throw no(`path の形が違います: ${s}`);
  return s;
}
/** what no AI changes through the API: [pattern, why] (a person changes these: in the panel, or on GitHub) */
export const PROTECTED = Object.freeze([
  [/^\.github\//, 'ラボの CI と決まり（.github/）は人が変えます（予約だけは schedule_set で）'],
  [/^auto\/(policy\.json|STOP)$/, 'auto/policy.json と auto/STOP は人が変えます（AGENTS.md）'],
  [/(^|\/)\.env(\.[\w.-]+)?$/, '.env は置きません（秘密は secret_set で）'],
  [/^\.git(\/|$)/, '.git は変えられません'],
]);
const writable = (p) => { for (const [re, why] of PROTECTED) if (re.test(p)) throw no(why, 403); return p; };

// ---- the arguments: a small JSON Schema check (the tools' own schemas: object, string, integer, number, boolean, array) ----
function checkArgs(schema, args) {
  if (!args || typeof args !== 'object' || Array.isArray(args)) return 'arguments はオブジェクトで';
  const props = schema.properties ?? {};
  for (const k of Object.keys(args)) if (!Object.hasOwn(props, k)) return `知らない引数です: ${k}（${Object.keys(props).join(' ') || 'なし'}）`;
  for (const k of schema.required ?? []) if (args[k] === undefined || args[k] === null || args[k] === '') return `${k} が要ります`;
  for (const [k, sch] of Object.entries(props)) {
    let v = args[k];
    if (v === undefined || v === null) continue;
    if (sch.type === 'integer' && typeof v === 'string' && /^\d{1,17}$/.test(v)) v = args[k] = Number(v);
    const ok = sch.type === 'array' ? Array.isArray(v) : sch.type === 'object' ? typeof v === 'object' && !Array.isArray(v) : sch.type === 'integer' ? Number.isSafeInteger(v) : typeof v === sch.type;
    if (!ok) return `${k} は ${sch.type} で`;
    if (sch.enum && !sch.enum.includes(v)) return `${k} は ${sch.enum.join('・')} のどれか`;
    if (sch.type === 'string' && sch.maxLength && v.length > sch.maxLength) return `${k} が長すぎます（${sch.maxLength} 文字まで）`;
    if (sch.type === 'integer' && ((sch.minimum !== undefined && v < sch.minimum) || (sch.maximum !== undefined && v > sch.maximum))) return `${k} は ${sch.minimum ?? ''}〜${sch.maximum ?? ''}`;
  }
  return '';
}
const str = (description, extra = {}) => ({ type: 'string', description, ...extra });
const int = (description, extra = {}) => ({ type: 'integer', description, ...extra });
const bool = (description) => ({ type: 'boolean', description });
const obj = (properties, required = []) => ({ type: 'object', properties, required, additionalProperties: false });
const CONFIRM = bool('true only after the person agreed, when a call said this action needs confirmation (the lab\'s policy, or a cost)');
const RUN_ID = int('a run id (runs_list)', { minimum: 1 });

/** the tools: { name, title, description, input (JSON Schema), action (the policy's, for a write) | null, run(ctx, args) →
 *  { summary, result, raw? } }. A write's schema gets `confirm` */
function tools(H) {
  const T = [
    { name: 'lab_status', title: 'ラボの様子', readOnly: true, input: obj({}),
      description: 'Start here. The lab, who you are in it (GitHub role, the policy\'s role, the actions it allows), the setup checks (the panel\'s 「準備」), the newest run of each workflow and what is failing.',
      run: async (ctx) => {
        const [me, repo, rule, runs, setup] = await Promise.all([ctx.me(), ctx.repo(), ctx.rule(), H.listRuns(ctx, { limit: 60 }), H.checks(ctx).then((cs) => cs.map(H.row), (e) => ({ error: e.message }))]);
        const latest = [], seen = new Set();
        for (const x of runs) if (!seen.has(x.workflow)) { seen.add(x.workflow); latest.push(x); }
        const failing = latest.filter((x) => x.status === 'completed' && FAILED.has(x.conclusion));
        const allowed = P.ACTIONS.filter((a) => P.can(rule.policy, rule.role, a)), okN = Array.isArray(setup) ? setup.filter((x) => x.ok === true).length : 0;
        return {
          summary: `${H.lab}: ${me.login}（GitHub ${rule.role.repoRole ?? '?'}・役割 ${roleName(rule.role)}）。準備 ${Array.isArray(setup) ? `${okN}/${setup.length} ✅` : '読めません'}。最近: ${latest.slice(0, 8).map((x) => `${icon(x.status, x.conclusion)}${x.file}`).join(' ') || 'なし'}${failing.length ? `。落ちている: ${failing.map((x) => x.file).join('・')}` : ''}`,
          result: { lab: { slug: H.lab, url: repo.html_url, visibility: repo.visibility, defaultBranch: repo.default_branch, panel: H.panelUrl(), mcp: `${ctx.origin}/mcp` },
            you: { login: me.login, githubRole: rule.role.repoRole, role: roleName(rule.role), allowed, via: ctx.via },
            policy: { errors: rule.errors, audit: rule.audit, confirm: rule.policy.confirm ?? [], adminsLend: P.adminsLend(rule.policy) },
            setup, latestRuns: latest.slice(0, 20), failing },
        };
      } },
    { name: 'setup_checks', title: '準備の確かめ', readOnly: true, input: obj({}),
      description: 'The panel\'s 「準備」 checks, row by row: what is there (ok true), missing (false) or cannot be told (null), why, and how it is fixed (setup_fix runs the fixes that need no GitHub button).',
      run: async (ctx) => { const cs = (await H.checks(ctx)).map(H.row); return { summary: `準備 ${cs.filter((x) => x.ok === true).length}/${cs.length} ✅${cs.filter((x) => x.ok !== true).map((x) => ` ・${x.ok === null ? '❔' : '⚠️'}${x.label}`).join('')}`, result: { checks: cs } }; } },
    { name: 'setup_fix', title: '準備を直す', action: 'setup', input: obj({ key: str('the row\'s key (setup_checks)', { maxLength: 100 }), inputs: { type: 'object', description: 'the values the fix asks for (its inputs), e.g. {"token": "<Cloudflare token>"}' } }, ['key']),
      description: 'Run one 「準備」 fix the panel can do itself (turn on Pages, start pages.yml, put the sign-in service on Cloudflare, …). Fixes that need a GitHub button (making or installing the GitHub App) return the link for the person.',
      run: (ctx, a) => H.setupFix(ctx, a) },
    { name: 'runs_list', title: '実行の一覧', readOnly: true,
      input: obj({ workflow: str('a workflow file, e.g. verify.yml or unit.yml', { maxLength: 100 }), status: str('queued, in_progress, completed, success, failure, cancelled, …', { maxLength: 30 }), branch: str('a branch', { maxLength: 200 }), event: str('push, workflow_dispatch, schedule, …', { maxLength: 40 }), limit: int('how many (default 20)', { minimum: 1, maximum: 100 }) }),
      description: 'The lab\'s GitHub Actions runs, newest first: id, workflow, status and conclusion, branch, who, when, link.',
      run: async (ctx, a) => { const runs = await H.listRuns(ctx, a); return { summary: runs.length ? runs.slice(0, 12).map((x) => `${icon(x.status, x.conclusion)} ${x.file} #${x.number} (${x.id})`).join('\n') : '実行はありません', result: { runs } }; } },
    { name: 'run_detail', title: '実行の中身', readOnly: true, input: obj({ run_id: RUN_ID }, ['run_id']),
      description: 'One run: its jobs and steps with results, the annotations of failed jobs, and the panel\'s diagnosis (where, why, the next step). Then run_log for the log.',
      run: (ctx, a) => H.runDetail(ctx, a.run_id) },
    { name: 'run_log', title: '実行のログ', readOnly: true,
      input: obj({ run_id: RUN_ID, job_id: int('a job id (run_detail); else the run\'s failed job, else its last', { minimum: 1 }), job: str('part of the job\'s name', { maxLength: 100 }), grep: str('only lines matching this regular expression (any case), with context', { maxLength: 200 }), context: int('lines around each match (default 2)', { minimum: 0, maximum: 20 }), tail: int('the last N lines (default 300)', { minimum: 1, maximum: 3000 }) }),
      description: 'A job\'s log as text (timestamps and colours taken off, lines numbered): its end, or the lines matching grep. Give run_id (the failed job is chosen) or job_id.',
      run: (ctx, a) => H.runLog(ctx, a) },
    { name: 'run_rerun', title: '実行をやり直す', action: 'dispatch', audit: 'run.rerun', input: obj({ run_id: RUN_ID, failed_only: bool('only the failed jobs (default true)') }, ['run_id']),
      description: 'Run a finished run again: its failed jobs (default) or all of it.',
      run: (ctx, a) => H.guarded(ctx, 'dispatch', a, { run: String(a.run_id) }, () => ctx.api.call('POST', `/repos/${H.lab}/actions/runs/${a.run_id}/${a.failed_only === false ? 'rerun' : 'rerun-failed-jobs'}`), { audit: 'run.rerun', done: () => `run ${a.run_id} を${a.failed_only === false ? 'もう一度' : '（落ちたジョブだけ）やり直し'}始めました: run_detail で様子を` }) },
    { name: 'run_cancel', title: '実行を止める', action: 'run.cancel', input: obj({ run_id: RUN_ID }, ['run_id']),
      description: 'Stop a run that is queued or running.',
      run: (ctx, a) => H.guarded(ctx, 'run.cancel', a, { run: String(a.run_id) }, () => ctx.api.cancel(H.lab, a.run_id), { done: () => `run ${a.run_id} を止めました` }) },
    { name: 'workflows_list', title: 'ワークフローの一覧', readOnly: true, input: obj({}),
      description: 'The lab\'s workflows: file, name, state. workflow_get shows one\'s inputs; workflow_run starts one.',
      run: async (ctx) => { const ws = (await ctx.api.workflows(H.lab)).map((w) => ({ id: w.id, name: w.name, file: fileOf(w.path), state: w.state })); return { summary: ws.map((w) => `${w.file}${w.state === 'active' ? '' : `（${w.state}）`}`).join(' '), result: { workflows: ws } }; } },
    { name: 'workflow_get', title: 'ワークフローの入力', readOnly: true, input: obj({ workflow: str('a workflow file, e.g. unit.yml', { maxLength: 100 }) }, ['workflow']),
      description: 'A workflow file\'s head — its comments, triggers and workflow_dispatch inputs (up to `jobs:`), to know what workflow_run takes.',
      run: async (ctx, a) => {
        const file = H.wfFile(a.workflow), f = await ctx.api.file(H.lab, `.github/workflows/${file}`);
        if (!f) throw no(`${file} はありません（workflows_list で）`, 404);
        const lines = f.text.split('\n'), end = lines.findIndex((l) => /^jobs:/.test(l)), head = lines.slice(0, Math.min(end < 0 ? lines.length : end, 160)).join('\n');
        return { summary: `${file}: ${/workflow_dispatch/.test(head) ? 'workflow_run で始められます' : 'workflow_dispatch がありません（手では始められません）'}`, result: { file, dispatchable: /workflow_dispatch/.test(head), sha: f.sha }, raw: head };
      } },
    { name: 'workflow_run', title: 'ワークフローを始める', action: 'dispatch',
      input: obj({ workflow: str('a workflow file, e.g. verify.yml', { maxLength: 100 }), ref: str('the branch (default: the default branch)', { maxLength: 200 }), inputs: { type: 'object', description: 'its workflow_dispatch inputs, e.g. {"job": "test", "unit": "coins"} (workflow_get)' } }, ['workflow']),
      description: 'Start a workflow (workflow_dispatch) and find its new run (its id for run_detail). An AI workflow (ai-make.yml) costs the lab\'s AI key: confirm: true after the person agreed.',
      run: async (ctx, a) => {
        const file = H.wfFile(a.workflow), inputs = H.inputsOf(a.inputs);
        if (SC.AI_WORKFLOWS.includes(file) && a.confirm !== true) throw no(`${file} は AI を使います（ラボの AI の鍵の料金がかかります）: 人に確かめてから confirm: true で`, 428);
        const ref = refOk(a.ref) ?? (await ctx.repo()).default_branch;
        return H.guarded(ctx, 'dispatch', a, { workflow: file, ref, inputs: Object.keys(inputs) }, () => H.dispatchFind(ctx, file, ref, inputs), { done: (run) => H.started(file, run), result: (run) => ({ workflow: file, ref, run }) });
      } },
    { name: 'units_list', title: 'ユニット（アドオン）の一覧', readOnly: true, input: obj({ q: str('words to find in the name, title or description', { maxLength: 200 }) }),
      description: 'The lab\'s units — bds/addons/<name> (addons), end/plugins, ll/mods: title, description, version, how many test sections, the latest release.',
      run: (ctx, a) => H.units(ctx, a.q) },
    { name: 'unit_run', title: 'ユニットの試験・仕上げ', action: 'dispatch',
      input: obj({ unit: str('the unit\'s name (bds/addons/<name>)', { maxLength: 40 }), job: { type: 'string', enum: [...W.RUN_JOBS], description: 'test: tests.txt on a real BDS with real clients (default); sim: the quick sandbox; go: test + QA + build the .mcaddon (a release)' } }, ['unit']),
      description: 'Test or finish a unit on the lab\'s own Actions (unit.yml): test (default), sim or go. Returns the new run.',
      run: async (ctx, a) => {
        const r = W.runInputs({ job: a.job ?? 'test', unit: a.unit });
        if (r.error) throw no(r.error);
        if (!(await U.unitExists(ctx.api, H.lab, r.inputs.unit))) throw no(`${r.inputs.unit} という bds のユニットはありません（units_list で）`, 404);
        const ref = (await ctx.repo()).default_branch;
        return H.guarded(ctx, 'dispatch', a, { workflow: W.WORKFLOW, job: r.inputs.job, unit: r.inputs.unit }, () => H.dispatchFind(ctx, W.WORKFLOW, ref, r.inputs), { done: (run) => H.started(`${r.inputs.unit} の ${W.JOB_WORDS[r.inputs.job] ?? r.inputs.job}`, run), result: (run) => ({ ...r.inputs, run }) });
      } },
    { name: 'unit_new', title: '新しいユニットを作る', action: 'dispatch',
      input: obj({ unit: str('a new name: lower-case letters, digits, _ (2-40)', { maxLength: 40 }), title: str('its title', { maxLength: 80 }), request: str('what the addon does (the lab writes its TASK.md and a start)', { maxLength: 2000 }) }, ['unit', 'request']),
      description: 'Make a new unit (unit.yml job new): bds/addons/<unit> with src/main.ts, tests.txt, TASK.md, packs. No AI cost.',
      run: async (ctx, a) => {
        const r = W.newUnitInputs(a);
        if (r.error) throw no(r.error);
        if (await U.unitExists(ctx.api, H.lab, r.inputs.unit)) throw no(`${r.inputs.unit} はもうあります: ほかの名前に`, 409);
        const ref = (await ctx.repo()).default_branch;
        return H.guarded(ctx, 'dispatch', a, { workflow: W.WORKFLOW, job: 'new', unit: r.inputs.unit }, () => H.dispatchFind(ctx, W.WORKFLOW, ref, r.inputs), { done: (run) => H.started(`${r.inputs.unit} を作る`, run), result: (run) => ({ unit: r.inputs.unit, run }) });
      } },
    { name: 'ai_make', title: 'AI に作らせる', action: 'dispatch',
      input: obj({ request: str('what to make, or the change', { maxLength: 4000 }), unit: str('change or harden this unit instead: <lab>/<name>, e.g. bds/rubyshop', { maxLength: 100 }) }),
      description: 'The lab\'s own AI makes an addon from an idea, changes a unit, or hardens it by playtest (ai-make.yml) — it costs the lab\'s AI key: confirm: true after the person agreed.',
      run: async (ctx, a) => {
        if (!a.request && !a.unit) throw no('request か unit のどちらかが要ります');
        if (a.unit && !/^(bds|end|ll)\/[a-z][a-z0-9_]{1,39}$/.test(a.unit)) throw no('unit は <lab>/<名前>（例 bds/rubyshop）');
        if (a.confirm !== true) throw no('ai-make.yml は AI を使います（ラボの AI の鍵の料金がかかります）: 人に確かめてから confirm: true で', 428);
        const ref = (await ctx.repo()).default_branch, inputs = H.inputsOf({ ...(a.request ? { request: a.request } : {}), ...(a.unit ? { unit: a.unit } : {}) });
        return H.guarded(ctx, 'dispatch', a, { workflow: 'ai-make.yml', ref }, () => H.dispatchFind(ctx, 'ai-make.yml', ref, inputs), { done: (run) => H.started('AI の作業（ai-make.yml）', run), result: (run) => ({ run }) });
      } },
    { name: 'files_list', title: 'ファイルの一覧', readOnly: true, input: obj({ path: str('a folder (default: the top)', { maxLength: 400 }), ref: str('a branch, tag or commit', { maxLength: 200 }) }),
      description: 'A folder of the lab: its files and folders (up to 1000).',
      run: async (ctx, a) => {
        const p = cleanPath(a.path ?? '', { dir: true }), ref = refOk(a.ref);
        const j = await ctx.api.call('GET', `/repos/${H.lab}/contents/${encPath(p)}${ref ? `?ref=${encodeURIComponent(ref)}` : ''}`).catch((e) => { if (e.status === 404) throw no(`${p || '/'} はありません`, 404); throw e; });
        if (!Array.isArray(j)) return { summary: `${p} はファイルです（file_read で）`, result: { path: p, type: j.type, size: j.size, sha: j.sha } };
        return { summary: `${p || '/'}: ${j.length} 件`, result: { path: p, entries: j.map((x) => ({ name: x.name, path: x.path, type: x.type, size: x.size })) } };
      } },
    { name: 'file_read', title: 'ファイルを読む', readOnly: true,
      input: obj({ path: str('the file, e.g. bds/addons/coins/src/main.ts', { maxLength: 400 }), ref: str('a branch, tag or commit', { maxLength: 200 }), from: int('first line (1-based)', { minimum: 1 }), to: int('last line', { minimum: 1 }) }, ['path']),
      description: 'A file of the lab: its text (the second content block, as it is) and its sha — give that sha to file_write to change it. A binary file comes back as base64 (up to 300 KB).',
      run: (ctx, a) => H.readFile(ctx, a) },
    { name: 'file_write', title: 'ファイルを書く', action: 'dispatch',
      input: obj({ path: str('the file', { maxLength: 400 }), content: str('its whole new text'), content_base64: str('or its bytes, base64 (a texture, …)'), sha: str('the sha file_read gave (required to change a file that exists: nobody\'s change is overwritten)', { maxLength: 64 }), message: str('the commit message', { maxLength: 200 }), branch: str('a branch (default: the default branch)', { maxLength: 200 }) }, ['path']),
      description: 'Write a file as a commit (the contents API): a new file, or one that exists over the sha you read. Not .github/, auto/policy.json, auto/STOP or .env files. A manifest.json must stay JSON.',
      run: (ctx, a) => H.writeFile(ctx, a) },
    { name: 'file_delete', title: 'ファイルを消す', action: 'dispatch',
      input: obj({ path: str('the file', { maxLength: 400 }), sha: str('its sha (file_read)', { maxLength: 64 }), message: str('the commit message', { maxLength: 200 }), branch: str('a branch', { maxLength: 200 }) }, ['path', 'sha']),
      description: 'Delete a file as a commit, over the sha you read. Not the protected files.',
      run: async (ctx, a) => {
        const p = writable(cleanPath(a.path)), branch = refOk(a.branch);
        return H.guarded(ctx, 'dispatch', a, { file: p }, () => ctx.api.call('DELETE', `/repos/${H.lab}/contents/${encPath(p)}`, { message: H.message(a.message, `api: ${p} を消す`), sha: a.sha, ...(branch ? { branch } : {}) }).catch(H.stale(p)), { done: (r) => `${p} を消しました（${String(r?.commit?.sha ?? '').slice(0, 7)}）`, result: (r) => ({ path: p, commit: r?.commit?.html_url ?? null }) });
      } },
    { name: 'secrets_list', title: '秘密の一覧', readOnly: true, input: obj({}),
      description: 'The lab\'s Actions secrets: names and when they changed (GitHub never gives a value).',
      run: async (ctx) => { const xs = (await ctx.api.secrets(H.lab)).map((x) => ({ name: x.name, updated: x.updated_at })); return { summary: xs.map((x) => x.name).join(' ') || '秘密はありません', result: { secrets: xs } }; } },
    { name: 'secret_set', title: '秘密を登録する', action: 'secrets.put',
      input: obj({ name: str('e.g. ANTHROPIC_API_KEY', { maxLength: 100 }), value: str('its value (sealed here with the lab\'s public key: only GitHub\'s Actions open it)', { maxLength: 48000 }) }, ['name', 'value']),
      description: 'Set an Actions secret of the lab (sealed before it leaves: libsodium\'s sealed box). The value never comes back.',
      run: async (ctx, a) => {
        const n = nameOk(a.name, '秘密');
        return H.guarded(ctx, 'secrets.put', a, { name: n }, async () => { const k = await ctx.api.call('GET', `/repos/${H.lab}/actions/secrets/public-key`); await ctx.api.call('PUT', `/repos/${H.lab}/actions/secrets/${encodeURIComponent(n)}`, await secretPayloadFast(String(a.value), k)); }, { done: () => `秘密 ${n} を封じて登録しました` });
      } },
    { name: 'secret_delete', title: '秘密を消す', action: 'secrets.delete', input: obj({ name: str('the secret', { maxLength: 100 }) }, ['name']),
      description: 'Delete an Actions secret of the lab (the default policy asks for confirm: true).',
      run: (ctx, a) => { const n = nameOk(a.name, '秘密'); return H.guarded(ctx, 'secrets.delete', a, { name: n }, () => ctx.api.deleteSecret(H.lab, n), { done: () => `秘密 ${n} を消しました` }); } },
    { name: 'variables_list', title: '変数の一覧', readOnly: true, input: obj({}),
      description: 'The lab\'s Actions variables with their values (variables are not secret).',
      run: async (ctx) => {
        const out = [];
        for (let p = 1; p <= 4; p++) { const j = await ctx.api.call('GET', `/repos/${H.lab}/actions/variables?per_page=30&page=${p}`); out.push(...(j?.variables ?? [])); if ((j?.variables ?? []).length < 30) break; }
        return { summary: out.map((v) => v.name).join(' ') || '変数はありません', result: { variables: out.map((v) => ({ name: v.name, value: v.value, updated: v.updated_at })) } };
      } },
    { name: 'variable_set', title: '変数を変える', action: 'variables',
      input: obj({ name: str('e.g. LAB_NOTIFY', { maxLength: 100 }), value: str('its value', { maxLength: 48000 }) }, ['name', 'value']),
      description: 'Set (or make) an Actions variable of the lab.',
      run: async (ctx, a) => {
        const n = nameOk(a.name, '変数'), before = AU.BEFORE_NAMES.includes(n) ? await ctx.api.variable(H.lab, n).catch(() => null) : null;
        return H.guarded(ctx, 'variables', a, { name: n, ...(typeof before === 'string' ? { before } : {}) }, () => ctx.api.setVariable(H.lab, n, String(a.value)), { done: () => `変数 ${n} を変えました` });
      } },
    { name: 'variable_delete', title: '変数を消す', action: 'variables', input: obj({ name: str('the variable', { maxLength: 100 }) }, ['name']),
      description: 'Delete an Actions variable of the lab.',
      run: (ctx, a) => { const n = nameOk(a.name, '変数'); return H.guarded(ctx, 'variables', a, { name: n }, () => ctx.api.call('DELETE', `/repos/${H.lab}/actions/variables/${encodeURIComponent(n)}`), { done: () => `変数 ${n} を消しました` }); } },
    { name: 'releases_list', title: '配布（リリース）', readOnly: true, input: obj({ limit: int('how many (default 10)', { minimum: 1, maximum: 30 }) }),
      description: 'The lab\'s releases, newest first, with their files (.mcaddon …), sizes, downloads and links.',
      run: async (ctx, a) => {
        const rs = R.newestFirst(await R.listReleases(ctx.api, H.lab)).slice(0, a.limit ?? 10).map((r) => ({ tag: r.tag_name, name: r.name, draft: r.draft, prerelease: r.prerelease, published: r.published_at, url: r.html_url, assets: (r.assets ?? []).map((x) => ({ name: x.name, size: x.size, downloads: x.download_count, url: x.browser_download_url })) }));
        return { summary: rs.map((r) => `${r.tag}（${r.assets.map((x) => x.name).join(', ') || 'ファイルなし'}）`).join('\n') || 'リリースはありません', result: { releases: rs } };
      } },
    { name: 'artifacts_list', title: '成果物', readOnly: true, input: obj({ run_id: RUN_ID, limit: int('how many (default 30)', { minimum: 1, maximum: 100 }) }),
      description: 'Actions artifacts — of one run, or the lab\'s newest: name, size, expired.',
      run: async (ctx, a) => { const xs = (await ctx.api.artifacts(H.lab, { run: a.run_id, per: a.limit ?? 30 })).map((x) => ({ id: x.id, name: x.name, size: x.size_in_bytes, expired: x.expired, created: x.created_at, run: x.workflow_run?.id ?? null })); return { summary: xs.map((x) => `${x.name}${x.expired ? '（期限切れ）' : ''}`).join(' ') || '成果物はありません', result: { artifacts: xs } }; } },
    { name: 'members_list', title: 'メンバー', readOnly: true, input: obj({}),
      description: 'The lab\'s people: the owner, collaborators with their GitHub role, pending invitations.',
      run: async (ctx) => { const m = await M.readMembers(ctx.api, H.lab, await ctx.repo()); return { summary: `${m.members.map((x) => `${x.login}（${x.permission}）`).join(' ')}${m.invitations.length ? ` 招待中: ${m.invitations.map((x) => x.login).join(' ')}` : ''}`, result: m }; } },
    { name: 'member_set', title: 'メンバーを招く・変える', action: 'members',
      input: obj({ login: str('a GitHub user name', { maxLength: 39 }), permission: { type: 'string', enum: [...M.PERMISSIONS], description: 'admin, maintain, push (write), triage or pull (read)' } }, ['login', 'permission']),
      description: 'Invite someone to the lab, or change their GitHub role. Never the owner, never yourself.',
      run: async (ctx, a) => {
        const [me, repo] = await Promise.all([ctx.me(), ctx.repo()]), c = M.canChange({ login: a.login }, { owner: repo.owner?.login, me: me.login });
        if (!c.ok) throw no(c.why, 403);
        return H.guarded(ctx, 'members', a, { user: a.login, permission: a.permission }, () => M.setMember(ctx.api, H.lab, a.login, a.permission), { done: (r) => `${a.login}: ${String(r).startsWith('invited') ? '招待を送りました' : '役割を変えました'}${String(r).endsWith('-write') ? '（個人のリポジトリなので書き込みとして）' : ''}` });
      } },
    { name: 'member_remove', title: 'メンバーを外す', action: 'members', input: obj({ login: str('a GitHub user name', { maxLength: 39 }) }, ['login']),
      description: 'Take someone out of the lab (or cancel their invitation). Always asks for confirm: true.',
      run: async (ctx, a) => {
        if (a.confirm !== true) throw no(`${a.login} をラボから外します: 人に確かめてから confirm: true で`, 428);
        const [me, repo] = await Promise.all([ctx.me(), ctx.repo()]), c = M.canChange({ login: a.login }, { owner: repo.owner?.login, me: me.login });
        if (!c.ok) throw no(c.why, 403);
        const m = await M.readMembers(ctx.api, H.lab, repo), inv = m.invitations.find((i) => i.login.toLowerCase() === a.login.toLowerCase());
        if (!inv && !m.members.some((x) => x.login.toLowerCase() === a.login.toLowerCase())) throw no(`${a.login} はラボのメンバーではありません`, 404);
        return H.guarded(ctx, 'members', a, { user: a.login, permission: 'none' }, () => (inv ? M.cancelInvitation(ctx.api, H.lab, inv.id) : M.removeMember(ctx.api, H.lab, a.login)), { done: () => `${a.login} を${inv ? '招待から' : 'ラボから'}外しました` });
      } },
    { name: 'audit_log', title: '監査ログ', readOnly: true,
      input: obj({ limit: int('how many (default 50)', { minimum: 1, maximum: 500 }), actor: str('only this person', { maxLength: 39 }), action: str('only this action, e.g. secrets.put', { maxLength: 40 }) }),
      description: 'Who did what in the lab (the panel\'s and this API\'s writes, when the policy keeps the log), newest first.',
      run: async (ctx, a) => {
        const rule = await ctx.rule();
        if (!P.can(rule.policy, rule.role, 'audit.read')) throw no(`監査ログを見ることは、あなたの役割（${roleName(rule.role)}）には許されていません（${P.POLICY_FILE}）`, 403);
        const log = await AU.readAudit(ctx.api, H.lab), xs = AU.filter(log.entries, { actor: a.actor, action: a.action }).slice().reverse().slice(0, a.limit ?? 50);
        return { summary: xs.slice(0, 10).map(AU.line).join('\n') || '記録はありません', result: { mode: rule.audit, issue: log.issue, entries: xs } };
      } },
    { name: 'issue_from_run', title: '失敗から Issue', action: 'issues', input: obj({ run_id: RUN_ID }, ['run_id']),
      description: 'Open (or find) the lab\'s Issue for a failed run: its summary, failed jobs and steps, annotations, link.',
      run: async (ctx, a) => {
        const run = await ctx.api.call('GET', `/repos/${H.lab}/actions/runs/${a.run_id}`);
        return H.guarded(ctx, 'issues', a, { run: String(a.run_id) }, () => RI.openOrCreate(ctx.api, H.lab, run), { done: (r) => `Issue #${r.issue.number}${r.existed ? '（前からあったもの）' : ' を作りました'}: ${r.issue.html_url}`, result: (r) => r });
      } },
    { name: 'schedule_get', title: '予約', readOnly: true, input: obj({}),
      description: 'The lab\'s timetable (.github/bds-lab-schedule.json, started hourly by schedule.yml): each job, when it starts, its next three times, and the file\'s sha for schedule_set.',
      run: async (ctx) => {
        const f = await ctx.api.file(H.lab, SC.SCHEDULE_FILE);
        let j = null; if (f) { try { j = JSON.parse(f.text); } catch { j = undefined; } }
        if (j === undefined) return { summary: `${SC.SCHEDULE_FILE} が JSON ではありません`, result: { sha: f.sha, errors: ['not JSON'], jobs: [] } };
        const c = SC.checkSchedule(j), at = new Date(H.now());
        return { summary: c.jobs.map((x) => `${x.id}: ${x.workflow} ${SC.describe(x)}`).join('\n') || '予約はありません', result: { sha: f?.sha ?? null, errors: c.errors, jobs: c.jobs.map((x) => ({ ...x, when: SC.describe(x), next: SC.nextRuns(x, at, 3).map((d) => d.toISOString()) })) } };
      } },
    { name: 'schedule_set', title: '予約を変える', action: 'dispatch',
      input: obj({ jobs: { type: 'array', description: 'the whole timetable: [{ id, workflow, every: hour|day|week, hours?, at?: "HH:MM", weekday?: 0-6, timezone?, inputs?, ref?, enabled? }] (schedule_get shows the form)', items: { type: 'object' } }, sha: str('the sha schedule_get gave (required when the file exists)', { maxLength: 64 }) }, ['jobs']),
      description: 'Replace the lab\'s timetable, checked as the panel checks it. A job of an AI workflow costs the lab\'s AI key: confirm: true after the person agreed.',
      run: async (ctx, a) => {
        const { text, errors } = SC.scheduleText(a.jobs);
        if (errors.length) throw no(`予約の形が違います: ${errors.join(' / ')}`);
        if (a.jobs.some((x) => SC.AI_WORKFLOWS.includes(String(x?.workflow ?? ''))) && a.confirm !== true) throw no('AI のワークフローの予約は、そのたびに AI の料金がかかります: 人に確かめてから confirm: true で', 428);
        if (!a.sha) { const cur = await ctx.api.file(H.lab, SC.SCHEDULE_FILE); if (cur) throw no(`${SC.SCHEDULE_FILE} はもうあります（sha ${cur.sha}）: schedule_get で読み、その sha を付けて`, 409); }
        return H.guarded(ctx, 'dispatch', a, { file: SC.SCHEDULE_FILE }, () => ctx.api.putFile(H.lab, SC.SCHEDULE_FILE, text, a.sha, 'api: 予約を変える').catch(H.stale(SC.SCHEDULE_FILE)), { done: () => `予約を保存しました（${a.jobs.length} 件）`, result: (r) => ({ sha: r?.content?.sha ?? null, commit: r?.commit?.html_url ?? null }) });
      } },
  ];
  for (const t of T) if (t.action && !t.input.properties.confirm) t.input.properties.confirm = CONFIRM;
  return T;
}

/** the instructions an MCP client hands the AI (MCP's initialize) */
export function instructions(lab, panel) {
  return `This server operates one bds-lab repository: ${lab} — a lab where AI makes Minecraft Bedrock addons and GitHub Actions proves them on a real Bedrock Dedicated Server with real clients. You act as the signed-in GitHub user: GitHub's permissions first, then the lab's role policy (.github/bds-lab-panel.json); writes go in the lab's audit log when it is kept. Answers are mostly Japanese; reply to the person in their language.
Start with lab_status. To fix something that fails: runs_list → run_detail (where / why / next step) → run_log (grep) → file_read → file_write (with the sha you read; never blind) → unit_run (test) or workflow_run → run_detail until it is green.
Units (addons) live in bds/addons/<name>/: src/main.ts (TypeScript, the Script API through src/kit.ts), tests.txt (one ## section per thing asked; a command line, then = exact, ~ regex, ! absent), TASK.md, bp/ and rp/. unit_run job=test runs tests.txt on a real server; job=go also does QA and builds the .mcaddon (releases_list). The lab's AGENTS.md (file_read) has the whole method.
Never through this API: .github/ (CI and policy; the timetable only by schedule_set), auto/policy.json, auto/STOP, .env files — a person changes those. When a tool says confirmation is needed, ask the person, then call again with confirm: true. Steps that need GitHub's own buttons (making or installing the GitHub App) are the person's, in the panel: ${panel || 'the lab\'s management panel'}. Never ask the person to paste a secret into the chat when the panel can take it; if they hand you one to set, use secret_set and do not repeat it.`;
}

/** env → async (Request) → Response for /mcp and /api (null for any other path: the sign-in service's). self: the sign-in
 *  service's own handler (its /health answered without the network); fetchImpl / now / sleep: tests */
export function api(env = {}, { fetchImpl = (...a) => globalThis.fetch(...a), now = () => Date.now(), sleep = (ms) => new Promise((r) => setTimeout(r, ms)), self = null, device = false } = {}) {
  const lab = SLUG.test(String(env.LAB_SLUG ?? '').trim()) ? String(env.LAB_SLUG).trim() : null;
  const base = String(env.GITHUB_API ?? '').trim().replace(/\/+$/, '') || 'https://api.github.com';
  const box = tokenBox(String(env.STATE_SECRET ?? ''));
  const panels = String(env.PANEL_ORIGINS ?? '').split(',').map((s) => s.trim()).filter((s) => /^https?:\/\//.test(s));
  // (GitHub wants a User-Agent, which a Worker does not send; fetch's cache option is the platform's business)
  const ghFetch = (u, init = {}) => { const { cache: _c, ...rest } = init; return fetchImpl(u, { ...rest, headers: { 'user-agent': UA, ...(rest.headers ?? {}) } }); };
  const panelUrl = () => { const p = panels.find((x) => /\.github\.io\//.test(x)) ?? panels[0]; return p ? (p.endsWith('/') ? p : `${p}/`) : null; };
  const selfFetch = (origin) => (u, init) => (self && String(u).startsWith(`${origin}/`) ? self(new Request(String(u), init)) : fetchImpl(u, init));

  // ---- helpers the tools share (H) ----
  const H = {
    lab, now, panelUrl,
    wfFile(w) { const f = fileOf(w); if (!/^[\w.-]{1,100}\.ya?ml$/.test(f)) throw no(`workflow はファイル名で（例 verify.yml）: ${w}`); return f; },
    inputsOf(x) {
      const o = x ?? {};
      if (typeof o !== 'object' || Array.isArray(o)) throw no('inputs は {"名前": "値"} で');
      const e = Object.entries(o);
      if (e.length > 25) throw no('inputs は 25 個まで（GitHub の決まり）');
      return Object.fromEntries(e.map(([k, v]) => { if (!/^[\w-]{1,100}$/.test(k)) throw no(`inputs の名前の形が違います: ${k}`); return [k, typeof v === 'string' ? v : JSON.stringify(v)]; }));
    },
    message: (m, d) => String(m ?? '').replace(/[\u0000-\u001f]/g, ' ').trim().slice(0, 200) || d,
    started: (what, run) => (run ? `${what}を始めました: run ${run.id}（run_detail で様子を）${run.url ? ` ${run.url}` : ''}` : `${what}を始めました（まだ一覧に出ていません: 少しして runs_list で）`),
    /** the contents API's refusal of a stale sha, in words */
    stale: (p) => (e) => { if ((e.status === 409 || e.status === 422) && /does not match|sha|wasn't supplied/i.test(String(e.message))) throw no(`${p}: その間にほかの変更が入りました（sha が古い）: file_read で読み直して、もう一度`, 409); throw e; },
    async listRuns(ctx, { workflow, status, branch, event, limit = 20 } = {}) {
      const q = new URLSearchParams({ per_page: String(Math.min(Math.max(1, Number(limit) || 20), 100)) });
      if (status) q.set('status', String(status)); if (branch) q.set('branch', refOk(branch)); if (event) q.set('event', String(event));
      const j = await ctx.api.call('GET', `/repos/${lab}/actions/${workflow ? `workflows/${encodeURIComponent(H.wfFile(workflow))}/` : ''}runs?${q}`);
      return (j?.workflow_runs ?? []).map(runOf);
    },
    /** a workflow started and its new run found: the run that was not there before, started by hand by this person (or null) */
    async dispatchFind(ctx, file, ref, inputs) {
      const me = String((await ctx.me()).login).toLowerCase(), before = new Set((await H.listRuns(ctx, { workflow: file, limit: 10 })).map((r) => r.id));
      await ctx.api.dispatch(lab, file, ref, inputs);
      for (let i = 0; i < 4; i++) {
        await sleep(i ? 2500 : 1500);
        const run = (await H.listRuns(ctx, { workflow: file, limit: 10 })).find((r) => !before.has(r.id) && r.event === 'workflow_dispatch' && String(r.actor ?? '').toLowerCase() === me);
        if (run) return run;
      }
      return null;
    },
    /** an action on the lab as the panel does it: GitHub's role and the policy's allow it, its confirmation given when the policy
     *  asks, then done and kept in the audit log (when the policy keeps one) → { summary, result, audit } */
    async guarded(ctx, action, a, detail, fn, { audit: auditAction, done, result } = {}) {
      const [me, repo, rule] = await Promise.all([ctx.me(), ctx.repo(), ctx.rule()]);
      if (P.adminsLend(rule.policy) && rule.role?.repoRole === 'admin' && String(me.login).toLowerCase() !== String(repo.owner?.login ?? '').toLowerCase()) throw no(`管理者はまず時間を貸します（${P.POLICY_FILE} の adminsLend）: パネルの「概要」の「フォークで貸す」から。貸しているかをここでは確かめられないので、パネルで操作してください`, 403);
      const actions = [].concat(action);
      for (const x of actions) if (!P.can(rule.policy, rule.role, x)) throw no(`${P.ACTION_WORDS[x] ?? x}は、あなたの役割（${roleName(rule.role)}）には許されていません（${P.POLICY_FILE}）`, 403);
      const ask = actions.find((x) => P.needsConfirm(rule.policy, x));
      if (ask && a.confirm !== true) throw no(`${P.ACTION_WORDS[ask] ?? ask}は、ラボの決まり（${P.POLICY_FILE} の confirm）で確認が要ります: 人に確かめてから confirm: true を付けて、もう一度`, 428);
      const out = await fn();
      let kept = rule.audit === 'issue' ? 'kept' : 'off';
      if (rule.audit === 'issue') {
        try { const x = await AU.record(ctx.api, lab, { actor: me.login, action: auditAction ?? actions[0], target: lab, detail: { ...detail, via: ctx.via === 'mcp' ? 'mcp' : 'api' } }); if (x?.why) kept = `kept: ${x.why}`; }
        catch (e) { kept = `監査ログに書けませんでした（${e.message}）。した操作はそのままです`; }
      }
      return { summary: done ? done(out) : 'しました', result: result ? result(out) : (out && typeof out === 'object' ? out : { ok: true }), audit: kept };
    },
    async panelConfig() {
      const p = panelUrl(); if (!p) return null;
      try { const r = await fetchImpl(`${p}config.json?t=${now()}`, { headers: { 'user-agent': UA } }); return r.ok ? await r.json() : null; } catch { return null; }
    },
    /** the panel's 「準備」 checks, as the panel would make them for this person */
    async checks(ctx) {
      const [me, repo, secrets, workflows, cfg] = await Promise.all([ctx.me(), ctx.repo(), ctx.api.secretNames(lab), ctx.api.workflows(lab).catch(() => []), H.panelConfig()]);
      return S.checks({ api: ctx.api, lab: { slug: lab, repo, role: P.repoRoleOf(repo.permissions), secrets, workflows }, me: { login: me.login }, hosts: [],
        config: { authUrl: cfg ? cfg.authUrl ?? null : ctx.origin, appSlug: cfg?.appSlug ?? null, appClientId: cfg?.appClientId ?? null }, panelUrl: panelUrl() ?? '', signedInWithApp: ctx.signedInWithApp,
        fetchImpl: selfFetch(ctx.origin), wait: { sleep, every: 5000, timeoutMs: 50_000 } });
    },
    row: (c) => ({ key: c.key, label: c.label, ok: c.ok, need: c.need || undefined, fix: c.fix ? { label: c.fix.label, kind: c.fix.manifest ? 'github-app-form' : c.fix.link ? 'link' : (c.fix.inputs ?? []).length ? 'run-with-inputs' : c.fix.run ? 'run' : 'none', ...(c.fix.link ? { link: c.fix.link } : {}), ...((c.fix.inputs ?? []).length ? { inputs: c.fix.inputs.map((i) => ({ name: i.name, label: i.label, secret: Boolean(i.secret) })) } : {}), ...(c.fix.needs ? { needs: c.fix.needs } : {}) } : null, ...(c.next ? { next: c.next.label } : {}) }),
    async setupFix(ctx, a) {
      const cs = await H.checks(ctx), c = cs.find((x) => x.key === a.key);
      if (!c) throw no(`その key の行はありません: ${cs.map((x) => x.key).join(' ')}`, 404);
      const f = c.fix;
      if (!f) throw no(`${c.label}: ${c.ok === true ? 'もう ✅ です' : c.need || 'ここで直すものはありません'}${c.next ? `（先に: ${c.next.label}）` : ''}`, 409);
      if (f.manifest) throw no('GitHub App を作る（作り直す）のは GitHub の画面のボタンで、人がします: 管理パネルの「準備」→「全自動で準備する」', 409);
      if (f.link) return { summary: `${c.label}: 人がこのリンクを開いて直します — ${f.link}`, result: { key: c.key, need: c.need, link: f.link, label: f.label } };
      if (typeof f.run !== 'function') throw no(`${c.label}: ここで直せるものはありません`, 409);
      const values = Object.fromEntries(Object.entries(a.inputs ?? {}).map(([k, v]) => [k, String(v ?? '')]));
      const lacking = (f.inputs ?? []).filter((i) => !values[i.name]?.trim());
      if (lacking.length) throw no(`入れるものが要ります（inputs）: ${lacking.map((i) => `${i.name}（${i.label}${i.secret ? '・秘密' : ''}）`).join('、')}`);
      const steps = [];
      return H.guarded(ctx, f.needs?.length ? f.needs : ['dispatch'], a, {}, async () => {
        try { return { message: await f.run(values, { onStep: (t) => steps.push(t) }) }; } catch (e) { if (/時間内に終わりません/.test(e.message)) return { message: 'まだ動いています: 少しして runs_list（auth-deploy.yml・pages.yml）と setup_checks で', running: true }; throw e; }
      }, { audit: `setup.${c.key}`, done: (r) => r.message, result: (r) => ({ key: c.key, ...r, steps }) });
    },
    async runDetail(ctx, id) {
      const run = await ctx.api.call('GET', `/repos/${lab}/actions/runs/${id}`).catch((e) => { if (e.status === 404) throw no(`run ${id} はありません`, 404); throw e; });
      const jobs = await ctx.api.jobs(lab, id), notes = [];
      for (const j of jobs.filter((x) => FAILED.has(x.conclusion)).slice(0, 5)) {
        try { for (const x of (await ctx.api.annotations(lab, j.id)) ?? []) notes.push({ job: j.name, level: x.annotation_level, title: x.title ?? '', message: clip(x.message, 800), path: x.path, line: x.start_line }); } catch { /* none to read for that job */ }
      }
      const d = FS.summarize({ run, jobs, annotations: notes.map((n) => ({ annotation_level: n.level, title: n.title, message: n.message })) });
      return {
        summary: `${icon(run.status, run.conclusion)} ${run.name} #${run.run_number}（${run.status}${run.conclusion ? `・${run.conclusion}` : ''}）${d ? `\n${d.lines.join('\n')}` : ''}`,
        result: { run: runOf(run), jobs: jobs.map((j) => ({ id: j.id, name: j.name, status: j.status, conclusion: j.conclusion, started: j.started_at, completed: j.completed_at, steps: (j.steps ?? []).map((s) => `${s.number}. ${icon(s.status, s.conclusion)} ${s.name}`) })), annotations: notes, diagnosis: d ? { where: d.where, why: d.why, next: d.next } : null, next: 'run_log（run_id か job_id、grep で絞れます）' },
      };
    },
    async runLog(ctx, a) {
      let jid = a.job_id, job = null;
      if (!jid) {
        if (!a.run_id) throw no('run_id か job_id が要ります');
        const jobs = await ctx.api.jobs(lab, a.run_id);
        job = a.job ? jobs.find((j) => String(j.name).toLowerCase().includes(a.job.toLowerCase())) : jobs.find((j) => FAILED.has(j.conclusion)) ?? jobs.at(-1);
        if (!job) throw no(a.job ? `「${a.job}」という名前のジョブはありません: ${jobs.map((j) => j.name).join(' / ')}` : 'ジョブがありません（まだ始まっていないか、始まる前に落ちました: run_detail で）', 404);
        jid = job.id;
      }
      const raw = await H.jobLog(ctx, jid), shaped = H.shapeLog(raw, a);
      return { summary: `${job ? `ジョブ「${job.name}」（${job.conclusion ?? job.status}）` : `job ${jid}`}: ${shaped.total} 行のうち ${shaped.shown} 行${a.grep ? `（grep ${a.grep}）` : '（最後の部分）'}`, result: { job: job ? { id: job.id, name: job.name, conclusion: job.conclusion } : { id: jid }, lines: shaped.total, shown: shaped.shown }, raw: shaped.text };
    },
    /** a job's log: GitHub answers with a redirect to its storage, followed without the token (it goes to no other host) */
    async jobLog(ctx, jid) {
      const at = `${base}/repos/${lab}/actions/jobs/${encodeURIComponent(jid)}/logs`;
      const r = await ghFetch(at, { headers: { authorization: `Bearer ${ctx.token}`, accept: 'application/vnd.github+json', 'x-github-api-version': '2022-11-28' }, redirect: 'manual' });
      let res = r;
      if (r.status >= 300 && r.status < 400) {
        const loc = r.headers.get('location') ?? '';
        let u; try { u = new URL(loc, at); } catch { throw no('ログの場所が読めません', 502); }
        if (u.protocol !== 'https:' && u.protocol !== new URL(base).protocol) throw no('ログの場所が https ではありません', 502);
        res = await fetchImpl(u.href, { headers: { 'user-agent': UA } });
      }
      if (res.status === 404 || res.status === 410) throw no('ログがありません（まだ動いているか、消えました）: run_detail で様子を', 404);
      if (!res.ok) throw new GhError(res.status, explain(res.status, ''), at);
      return (await res.text()).slice(-3_000_000);
    },
    /** a log as the AI reads it: only its end is looked at (400 KB; 2 MB for a grep), each pass done by the platform's own regular
     *  expressions over the whole text — a Worker's CPU time is short — and the lines numbered as in the whole log */
    shapeLog(raw, { tail = 300, grep, context = 2 } = {}) {
      let src = String(raw), base = 0;
      const scan = grep ? 2_000_000 : 400_000;
      if (src.length > scan) {
        const cut = src.length - scan, nl = src.indexOf('\n', cut), start = nl < 0 ? cut : nl + 1;
        for (let i = src.indexOf('\n'); i !== -1 && i < start; i = src.indexOf('\n', i + 1)) base++;
        src = src.slice(start);
      }
      const lines = src.replace(/\r/g, '').replace(/^\uFEFF?\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z ?/gm, '').replace(/\x1b\[[0-9;]*[A-Za-z]/g, '').split('\n');
      if (lines.at(-1) === '') lines.pop();
      let pick;
      if (grep) {
        let re; try { re = new RegExp(grep, 'i'); } catch (e) { throw no(`grep の正規表現が違います: ${e.message}`); }
        const keep = new Set();
        for (let i = 0; i < lines.length; i++) if (re.test(lines[i])) for (let k = Math.max(0, i - context); k <= Math.min(lines.length - 1, i + context); k++) keep.add(k);
        pick = [...keep].sort((x, y) => x - y);
      } else pick = Array.from({ length: lines.length }, (_, i) => i);
      pick = pick.slice(-Math.min(Math.max(1, Number(tail) || 300), 3000));
      const out = []; let prev = -2;
      for (const i of pick) { if (i !== prev + 1 && out.length) out.push('…'); out.push(`${base + i + 1}: ${lines[i]}`); prev = i; }
      let text = out.join('\n'); if (text.length > LOG_MAX) text = `…${text.slice(-LOG_MAX)}`;
      return { total: base + lines.length, shown: pick.length, text: text || '（合う行はありません）' };
    },
    async readFile(ctx, a) {
      const p = cleanPath(a.path), ref = refOk(a.ref);
      const j = await ctx.api.call('GET', `/repos/${lab}/contents/${encPath(p)}${ref ? `?ref=${encodeURIComponent(ref)}` : ''}`).catch((e) => { if (e.status === 404) throw no(`${p} はありません${ref ? `（${ref}）` : ''}`, 404); throw e; });
      if (Array.isArray(j)) throw no(`${p} はフォルダです: files_list で`);
      if (j.type !== 'file') throw no(`${p} はファイルではありません（${j.type}）`);
      // (over 1 MB the contents API gives no content: the blob of its sha has it)
      const bytes = j.encoding === 'base64' && j.content ? unb64(j.content) : unb64((await ctx.api.call('GET', `/repos/${lab}/git/blobs/${j.sha}`)).content);
      const text = bytes.includes(0) ? null : utf8(bytes);
      if (text === null) return { summary: `${p}: バイナリ（${bytes.length} バイト・sha ${j.sha.slice(0, 7)}）`, result: { path: p, sha: j.sha, size: bytes.length, binary: true, ...(bytes.length <= 300_000 ? { base64: b64(bytes) } : { note: '300 KB を超えるので中身は返しません' }) } };
      const lines = text.split('\n'), from = Math.max(1, a.from ?? 1), to = Math.min(lines.length, Math.max(from, a.to ?? lines.length));
      let body = lines.slice(from - 1, to).join('\n'), cut = false;
      if (body.length > READ_MAX) { body = body.slice(0, READ_MAX); cut = true; }
      return { summary: `${p}（${lines.length} 行・sha ${j.sha}${from > 1 || to < lines.length ? `・${from}〜${to} 行` : ''}）${cut ? ' — 長いので途中まで: from / to で続きを' : ''}`, result: { path: p, sha: j.sha, size: bytes.length, lines: lines.length, from, to, truncated: cut }, raw: body };
    },
    async writeFile(ctx, a) {
      const p = writable(cleanPath(a.path)), branch = refOk(a.branch);
      if ((a.content === undefined) === (a.content_base64 === undefined)) throw no('content（文字）か content_base64（バイナリ）のどちらか 1 つを');
      let content;
      if (a.content !== undefined) {
        if (/(^|\/)manifest\.json$/.test(p)) { try { const m = JSON.parse(String(a.content).replace(/^\uFEFF/, '')); if (!m || typeof m !== 'object' || !m.header) throw new Error('header がありません'); } catch (e) { throw no(`${p} が manifest の JSON として読めません（${e.message}）: 直してから`); } }
        content = b64(enc.encode(String(a.content)));
      } else {
        content = String(a.content_base64).replace(/\s/g, '');
        if (!/^[A-Za-z0-9+/]*={0,2}$/.test(content)) throw no('content_base64 が base64 ではありません');
      }
      if (content.length > FILE_MAX) throw no('1 MB までのファイルだけ書けます');
      if (!a.sha) {
        const cur = await ctx.api.call('GET', `/repos/${lab}/contents/${encPath(p)}${branch ? `?ref=${encodeURIComponent(branch)}` : ''}`).catch((e) => { if (e.status === 404) return null; throw e; });
        if (cur) throw no(`${p} はもうあります（sha ${Array.isArray(cur) ? '—（フォルダ）' : cur.sha}）: file_read で読み、その sha を付けて書き直してください（ほかの人の変更を上書きしないため）`, 409);
      }
      return H.guarded(ctx, 'dispatch', a, { file: p }, () => ctx.api.call('PUT', `/repos/${lab}/contents/${encPath(p)}`, { message: H.message(a.message, `api: ${p} を${a.sha ? '直す' : '作る'}`), content, ...(a.sha ? { sha: a.sha } : {}), ...(branch ? { branch } : {}) }).catch(H.stale(p)),
        { done: (r) => `${p} を${a.sha ? '保存' : '作成'}しました（${String(r?.commit?.sha ?? '').slice(0, 7)}）: 次は unit_run か workflow_run で確かめます`, result: (r) => ({ path: p, sha: r?.content?.sha ?? null, commit: r?.commit?.html_url ?? null }) });
    },
    /** the units: one tree and one GraphQL query for all their files (a Worker may make only so many calls); else the panel's way */
    async units(ctx, q) {
      const repo = await ctx.repo();
      let units;
      try { units = await H.unitsFast(ctx, repo.default_branch); } catch { units = await U.listUnits(ctx.api, lab, { fresh: true }); }
      if (q) units = U.filterUnits(units, q);
      let latest = {}; try { latest = R.latestByUnit(await R.listReleases(ctx.api, lab), units); } catch { /* releases unread: none shown */ }
      const out = units.map((u) => { const l = latest[u.ref]; return { ...u, latest: l ? { tag: l.release.tag_name, file: l.asset?.name ?? null, url: l.asset?.browser_download_url ?? l.release.html_url } : null }; });
      return { summary: out.length ? out.map((u) => `${u.name}（${u.title}${u.version ? ` v${u.version}` : ''}・試験 ${u.tests ?? '?'}）`).join(' ') : 'ユニットはありません', result: { units: out } };
    },
    async unitsFast(ctx, branch) {
      const tree = await ctx.api.call('GET', `/repos/${lab}/git/trees/${encodeURIComponent(branch)}?recursive=1`);
      if (!tree || tree.truncated) throw new Error('tree');
      const kinds = new Map((tree.tree ?? []).map((x) => [x.path, x.type])), found = [];
      for (const k of U.KINDS) for (const [p, type] of kinds) {
        if (type !== 'tree' || !p.startsWith(`${k.dir}/`)) continue;
        const n = p.slice(k.dir.length + 1);
        if (!n.includes('/') && U.isUnitName(n) && found.length < U.UNIT_LIMIT) found.push({ k, name: n });
      }
      const want = found.flatMap(({ k, name }) => [k.manifest, 'TASK.md', 'tests.txt'].filter(Boolean).map((f) => `${k.dir}/${name}/${f}`)).filter((p) => kinds.get(p) === 'blob');
      const texts = new Map(), [owner, repo] = lab.split('/');
      for (let i = 0; i < want.length; i += 60) {
        const part = want.slice(i, i + 60);
        const query = `query($o:String!,$n:String!){repository(owner:$o,name:$n){${part.map((p, k) => `f${k}:object(expression:${JSON.stringify(`${branch}:${p}`)}){... on Blob{text isBinary}}`).join(' ')}}}`;
        const j = await ctx.api.call('POST', '/graphql', { query, variables: { o: owner, n: repo } });
        if (!j?.data?.repository) throw new Error('graphql');
        part.forEach((p, k) => { const b = j.data.repository[`f${k}`]; if (b && !b.isBinary && typeof b.text === 'string') texts.set(p, b.text); });
      }
      const at = (k, name, f) => (f ? texts.get(`${k.dir}/${name}/${f}`) ?? null : null);
      return found.map(({ k, name }) => U.unitSummary({ kind: k.kind, name, manifest: at(k, name, k.manifest), task: at(k, name, 'TASK.md'), tests: at(k, name, 'tests.txt') }));
    },
  };
  const TOOLS = tools(H), BY = Object.fromEntries(TOOLS.map((t) => [t.name, t]));
  const info = (t) => ({ name: t.name, title: t.title, description: t.description, inputSchema: t.input, annotations: { title: t.title, readOnlyHint: Boolean(t.readOnly), destructiveHint: /delete|remove|cancel/.test(t.name), idempotentHint: Boolean(t.readOnly), openWorldHint: false } });

  /** the person behind a token: an access token MCP's sign-in sealed (handler.mjs), or a GitHub token as it is */
  async function who(req, origin) {
    const m = /^Bearer\s+([\x21-\x7e]{10,8192})$/i.exec(String(req.headers.get('authorization') ?? '').trim());
    if (!m) return { error: 'none' };
    const t = m[1];
    if (t.startsWith('bdsl_')) {
      const j = await box.open('access', t);
      return j && j.exp > now() && (!j.aud || j.aud === `${origin}/mcp`) && typeof j.gh === 'string' ? { token: j.gh, via: 'mcp' } : { error: 'invalid' };
    }
    return /^(ghp_|gho_|ghu_|github_pat_)[A-Za-z0-9_]{20,}$/.test(t) ? { token: t, via: 'token' } : { error: 'invalid' };
  }
  /** one request's view of the lab: its GitHub client, and what is read once (the person, the lab, the policy and their role) */
  function context(w, origin) {
    const a = gh({ token: w.token, base, fetchImpl: ghFetch }), memo = new Map();
    const once = (k, f) => { if (!memo.has(k)) memo.set(k, f()); return memo.get(k); };
    const ctx = {
      api: a, token: w.token, via: w.via, origin, signedInWithApp: w.token.startsWith('ghu_'),
      me: () => once('me', () => a.me()),
      repo: () => once('repo', () => a.repo(lab).catch((e) => { if (e.status === 404) throw no(`${lab} がこのアカウントでは見えません: ラボに GitHub App が入っているか（パネルの「準備」）、トークンの対象にラボを入れたかを確かめてください`, 404); throw e; })),
      rule: () => once('rule', async () => {
        const [me, repo] = await Promise.all([ctx.me(), ctx.repo()]), pol = await P.loadPolicy(a, lab), org = repo.owner?.type === 'Organization' ? repo.owner.login : null;
        const teams = org && Object.keys(pol.policy.teams ?? {}).length ? await P.teamsOf(a, org, me.login, pol.policy) : [];
        return { policy: pol.policy, errors: pol.errors, role: P.roleFor({ repoRole: repo.permissions, teams, policy: pol.policy }), audit: P.auditMode(pol.policy, repo.visibility) };
      }),
    };
    return ctx;
  }
  async function call(t, ctx, args) {
    const bad = checkArgs(t.input, args);
    if (bad) return { error: bad, status: 400 };
    try { const r = await t.run(ctx, args); return { summary: r.summary ?? '', result: r.result ?? null, raw: r.raw, audit: r.audit }; }
    catch (e) { return { error: e instanceof GhError ? `${e.message}${e.status ? `（GitHub ${e.status}）` : ''}` : String(e?.message ?? e), status: e instanceof GhError ? (e.status || 502) : e?.status ?? 500 }; }
  }
  const jsonText = (x) => { const t = JSON.stringify(x, null, 1); return t.length > 120_000 ? `${t.slice(0, 120_000)}…` : t; };
  const content = (r) => (r.error ? { content: [{ type: 'text', text: `⛔ ${r.error}` }], isError: true }
    : { content: [{ type: 'text', text: `${r.summary}${r.result ? `\n${jsonText(r.audit && r.audit !== 'off' ? { ...r.result, audit: r.audit } : r.result)}` : ''}` }, ...(typeof r.raw === 'string' ? [{ type: 'text', text: r.raw }] : [])] });
  const ok = (id, result) => ({ jsonrpc: '2.0', id, result }), err = (id, code, message) => ({ jsonrpc: '2.0', id: id ?? null, error: { code, message } });
  async function rpc(m, ctx) {
    if (!m || typeof m !== 'object' || m.jsonrpc !== '2.0' || typeof m.method !== 'string') return err(m?.id, -32600, 'Invalid Request');
    if (!Object.hasOwn(m, 'id')) return null;
    switch (m.method) {
      case 'initialize': return ok(m.id, { protocolVersion: MCP_VERSIONS.includes(m.params?.protocolVersion) ? m.params.protocolVersion : MCP_VERSIONS[0], capabilities: { tools: { listChanged: false } }, serverInfo: { name: 'bds-lab', title: `bds-lab（${lab}）`, version: API_VERSION }, instructions: instructions(lab, panelUrl()) });
      case 'ping': return ok(m.id, {});
      case 'tools/list': return ok(m.id, { tools: TOOLS.map(info) });
      case 'tools/call': {
        const t = BY[m.params?.name];
        if (!t) return err(m.id, -32602, `Unknown tool: ${m.params?.name}`);
        return ok(m.id, content(await call(t, ctx, m.params?.arguments ?? {})));
      }
      case 'resources/list': return ok(m.id, { resources: [] });
      case 'resources/templates/list': return ok(m.id, { resourceTemplates: [] });
      case 'prompts/list': return ok(m.id, { prompts: [] });
      default: return err(m.id, -32601, `Method not found: ${m.method}`);
    }
  }
  const read = async (req) => { if (Number(req.headers.get('content-length') ?? 0) > MAX_BODY) return null; const t = await req.text().catch(() => null); return t !== null && t.length <= MAX_BODY ? t : null; };
  const describe = (origin) => ({ name: 'bds-lab', lab, version: API_VERSION, mcp: `${origin}/mcp`, rest: `${origin}/api/<tool>`, openapi: `${origin}/openapi.json`, panel: panelUrl(),
    auth: { oauth: `${origin}/.well-known/oauth-authorization-server`, ...(device ? { device: `${origin}/device/code` } : {}), bearer: 'Authorization: Bearer <an access token from the OAuth or device sign-in, or a GitHub token: ghu_ / ghp_ / github_pat_>' },
    tools: TOOLS.map((t) => ({ name: t.name, title: t.title, description: t.description, action: t.action ?? null, readOnly: Boolean(t.readOnly), input: t.input })) });

  // ---- what a person or an AI finds at the service's own address: the page, the OpenAPI description, llms.txt ----
  const deviceSteps = (o) => [`POST ${o}/device/code  (client_name=<your name>) → user_code, verification_uri_complete, device_code, client_id, interval`, 'Show the person verification_uri_complete: they press 「許可して GitHub へ」 and Authorize on GitHub', `Every interval seconds: POST ${o}/token  grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=…&client_id=…  → authorization_pending … then access_token (refresh_token: grant_type=refresh_token&client_id=…)`, `Authorization: Bearer <access_token> on POST ${o}/api/<tool> or ${o}/mcp`];
  function openapi(origin) {
    const ok = { type: 'object', properties: { ok: { type: 'boolean' }, summary: { type: 'string' }, result: {}, text: { type: 'string', description: 'a file\'s text or a log, as it is' }, audit: { type: 'string' } } };
    const fail = (d) => ({ description: d, content: { 'application/json': { schema: { type: 'object', properties: { ok: { type: 'boolean' }, error: { type: 'string' } } } } } });
    return {
      openapi: '3.1.0',
      info: { title: `bds-lab API (${lab})`, version: API_VERSION, description: `Operate the bds-lab repository ${lab} as the signed-in GitHub user: the lab's role policy, confirmations (confirm: true) and audit log apply. Never .github/, auto/policy.json, auto/STOP or .env files. Results are mostly Japanese.${device ? ` No browser? The device sign-in: ${deviceSteps(origin).join(' / ')}` : ''}` },
      servers: [{ url: origin }],
      components: { securitySchemes: {
        oauth: { type: 'oauth2', flows: { authorizationCode: { authorizationUrl: `${origin}/authorize`, tokenUrl: `${origin}/token`, refreshUrl: `${origin}/token`, scopes: { lab: `operate ${lab}` } } } },
        bearer: { type: 'http', scheme: 'bearer', description: 'an access token from the OAuth or device sign-in, or a GitHub token (ghu_, ghp_, github_pat_)' },
      } },
      security: [{ oauth: ['lab'] }, { bearer: [] }],
      paths: Object.fromEntries(TOOLS.map((t) => [`/api/${t.name}`, { post: { operationId: t.name, summary: t.title, description: t.description, requestBody: { required: false, content: { 'application/json': { schema: t.input } } },
        responses: { 200: { description: 'done', content: { 'application/json': { schema: ok } } }, 400: fail('the arguments'), 401: fail('no token, or one not taken'), 403: fail('the role or the protected files'), 404: fail('not found'), 409: fail('a stale sha, or something already there'), 428: fail('ask the person, then send confirm: true') } } }])),
    };
  }
  const htmlEsc = (x) => String(x ?? '').replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch]);
  function home(origin) {
    const nonce = btoa(String.fromCharCode(...globalThis.crypto.getRandomValues(new Uint8Array(12)))).replace(/[^A-Za-z0-9]/g, ''), p = panelUrl();
    const css = 'body{font:16px/1.6 system-ui,sans-serif;margin:0;background:#f6f7f9;color:#111}main{max-width:46rem;margin:1.5rem auto;padding:1.25rem 1.5rem;background:#fff;border-radius:12px}h1{font-size:1.35rem}h2{font-size:1.05rem;margin-top:1.5rem}code{font-family:ui-monospace,monospace;background:#eef;padding:.05rem .3rem;border-radius:4px;word-break:break-all}li{margin:.25rem 0}a{color:#2f6fde}@media (prefers-color-scheme:dark){body{background:#111;color:#eee}main{background:#1c1c1f}code{background:#2a2a40}a{color:#8ab4ff}}';
    const body = `<h1>bds-lab（${htmlEsc(lab)}）</h1>
<p>${htmlEsc(lab)} の管理パネルのサインインと、AI がラボを直接操作する API です。AI はつないだ人の GitHub のアカウントで、パネルと同じ権限・ラボの役割の決まり・確認・監査ログのまま動きます。<code>.github/</code>・<code>auto/policy.json</code>・<code>auto/STOP</code>・<code>.env</code> は AI からは変えられません。</p>
${p ? `<p>管理パネル: <a href="${htmlEsc(p)}">${htmlEsc(p)}</a></p>` : ''}
<h2>Claude から</h2><ul><li>パネルの「準備」→「🤖 AI から操作」の「Claude 用プラグイン」を入れる、または Claude の「コネクタ」→「カスタムコネクタを追加」に <code>${htmlEsc(origin)}/mcp</code></li><li>Claude Code: <code>claude mcp add --transport http bds-lab ${htmlEsc(origin)}/mcp</code></li></ul>
${device ? `<h2>ブラウザのない AI から（リンクを開いて許可するだけ）</h2><ol>${deviceSteps(origin).map((x) => `<li><code>${htmlEsc(x)}</code></li>`).join('')}</ol>` : ''}
<h2>ほかの AI・スクリプト</h2><ul><li>道具の一覧: <a href="/api">/api</a> ・ OpenAPI: <a href="/openapi.json">/openapi.json</a> ・ AI 向けの説明: <a href="/llms.txt">/llms.txt</a></li><li><code>POST ${htmlEsc(origin)}/api/&lt;道具&gt;</code>（本文は引数の JSON。読むだけの道具は GET と ?引数= でも）</li></ul>
<h2>道具（${TOOLS.length}）</h2><ul>${TOOLS.map((t) => `<li><code>${htmlEsc(t.name)}</code> ${htmlEsc(t.title)}${t.readOnly ? '' : '（書き込み）'}</li>`).join('')}</ul>`;
    return new Response(`<!doctype html><html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="referrer" content="no-referrer"><title>bds-lab（${htmlEsc(lab)}）</title><style nonce="${nonce}">${css}</style></head><body><main>${body}</main></body></html>`, { status: 200, headers: { ...HEADERS, 'content-type': 'text/html; charset=utf-8', 'content-security-policy': `default-src 'none'; style-src 'nonce-${nonce}'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'` } });
  }
  const llms = (origin) => `# bds-lab (${lab})

> The sign-in service and the API for AI of ${lab}: a bds-lab, where AI makes Minecraft Bedrock addons and GitHub Actions proves them on a real Bedrock Dedicated Server. An AI operates the lab as the GitHub user who connected it — the lab's role policy, confirmations and audit log apply; never .github/, auto/policy.json, auto/STOP or .env files.

- MCP (Streamable HTTP, OAuth 2.1 with dynamic registration and PKCE): ${origin}/mcp
- HTTP: POST ${origin}/api/<tool> with a JSON body (read-only tools also GET with ?args); the tools: ${origin}/api ; OpenAPI 3.1: ${origin}/openapi.json
- Auth: Authorization: Bearer <an access token from the OAuth${device ? ' or device' : ''} sign-in, or a GitHub token>
${device ? `
## No browser? The device sign-in (RFC 8628)

${deviceSteps(origin).map((x, i) => `${i + 1}. ${x}`).join('\n')}
` : ''}
## Tools

${TOOLS.map((t) => `- ${t.name}${t.readOnly ? '' : ' (write)'}: ${t.description}`).join('\n')}

Start with lab_status. To fix a failure: runs_list → run_detail → run_log (grep) → file_read → file_write (with the sha read) → unit_run → run_detail. When a tool says confirmation is needed, ask the person, then send confirm: true.
`;
  /** a read-only tool's arguments from a query string (GET /api/<tool>?k=v), typed by its schema */
  const fromQuery = (t, q) => Object.fromEntries([...q].map(([k, v]) => { const type = t.input.properties?.[k]?.type; if (type === 'boolean') return [k, v === 'true' ? true : v === 'false' ? false : v]; if (type === 'object' || type === 'array') { try { return [k, JSON.parse(v)]; } catch { return [k, v]; } } return [k, v]; }));

  return async function route(req) {
    const url = new URL(req.url), path = url.pathname, origin = url.origin;
    if (req.method === 'GET' && lab && (path === '/' || path === '/openapi.json' || path === '/llms.txt')) {
      if (path === '/') return home(origin);
      if (path === '/openapi.json') return reply(200, openapi(origin));
      return new Response(llms(origin), { status: 200, headers: { ...HEADERS, ...CORS, 'content-type': 'text/plain; charset=utf-8' } });
    }
    if (path !== '/mcp' && path !== '/api' && !path.startsWith('/api/')) return null;
    try {
      if (req.method === 'OPTIONS') return reply(204, null);
      if (path === '/api' && req.method === 'GET') return lab ? reply(200, describe(origin)) : reply(503, { error: 'lab', message: 'LAB_SLUG がありません: auth-deploy.yml でサービスを置き直してください' });
      const getTool = req.method === 'GET' && path.startsWith('/api/') ? BY[path.slice(5)] : null;
      if (req.method !== 'POST' && !(getTool && getTool.readOnly)) return reply(405, { error: 'method', message: getTool ? '書き込む道具は POST で' : 'POST で' }, { allow: getTool ? 'POST, OPTIONS' : 'POST, GET, OPTIONS' });
      // (MCP's version header: a version this server does not speak is refused, as the spec asks)
      const pv = req.headers.get('mcp-protocol-version');
      if (path === '/mcp' && pv && !MCP_VERSIONS.includes(pv)) return reply(400, err(null, -32600, `Unsupported MCP-Protocol-Version: ${pv} (${MCP_VERSIONS.join(', ')})`));
      if (!lab) return reply(503, { error: 'lab', message: 'LAB_SLUG がありません: auth-deploy.yml でサービスを置き直してください' });
      const w = await who(req, origin);
      if (w.error) return reply(401, { error: w.error === 'none' ? 'unauthorized' : 'invalid_token', message: 'Authorization: Bearer <トークン> が要ります（MCP の OAuth で受け取ったもの、または GitHub のトークン）' }, { 'www-authenticate': `Bearer realm="bds-lab", resource_metadata="${origin}/.well-known/oauth-protected-resource"${w.error === 'invalid' ? ', error="invalid_token"' : ''}` });
      const text = req.method === 'GET' ? '' : await read(req);
      if (text === null) return reply(413, path === '/mcp' ? err(null, -32600, 'Request too large') : { ok: false, error: '大きすぎます' });
      const ctx = context(w, origin);
      if (path === '/mcp') {
        let msg; try { msg = JSON.parse(text); } catch { return reply(400, err(null, -32700, 'Parse error')); }
        const batch = Array.isArray(msg), list = batch ? msg : [msg];
        if (!list.length || list.length > 20) return reply(400, err(null, -32600, 'Invalid Request'));
        const out = [];
        for (const m of list) { const r = await rpc(m, ctx); if (r) out.push(r); }
        return out.length ? reply(200, batch ? out : out[0]) : reply(202, null);
      }
      const t = BY[path.slice(5)];
      if (!t) return reply(404, { ok: false, error: `知らない道具です: ${path.slice(5)}（GET /api で一覧）` });
      let args = req.method === 'GET' ? fromQuery(t, url.searchParams) : {};
      if (text.trim()) { try { args = JSON.parse(text); } catch { return reply(400, { ok: false, error: '本文は JSON で' }); } }
      const r = await call(t, ctx, args);
      return r.error ? reply(r.status >= 400 && r.status < 600 ? r.status : 400, { ok: false, error: r.error }) : reply(200, { ok: true, summary: r.summary, result: r.result, ...(typeof r.raw === 'string' ? { text: r.raw } : {}), ...(r.audit ? { audit: r.audit } : {}) });
    } catch (e) { return reply(500, { error: 'internal', message: String(e?.message ?? e).slice(0, 200) }); }
  };
}
