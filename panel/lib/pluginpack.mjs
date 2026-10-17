// pluginpack: the lab's Claude plugin — a .plugin file (a zip) Claude's apps install (Claude Code's plugins too): its MCP server
// (this lab's API for AI: MCP over HTTP at <the sign-in service>/mcp, signed in through the lab's GitHub App on first use) and a
// skill that tells the AI how to work the lab with it. Made for one lab's address, in the browser (the 「準備」 tab's button)
// or in Node (common/claude-plugin.mjs) alike: pure, no compression (a few small text files), names in UTF-8.
export const PLUGIN_NAME = 'bds-lab';
export const PLUGIN_VERSION = '1.1.0';

/** the plugin's files for one lab (pure) → { path: text }. mcpUrl: https://…/mcp; lab: owner/repo; panelUrl: the panel */
export function pluginFiles({ mcpUrl, lab, panelUrl = '' } = {}) {
  const u = String(mcpUrl ?? '');
  if (!/^https:\/\/[A-Za-z0-9.-]+(?::\d{1,5})?\/mcp$/.test(u)) throw new Error('MCP の URL は https://<サインインのサービス>/mcp');
  if (!/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})\/[A-Za-z0-9._-]{1,100}$/.test(String(lab ?? ''))) throw new Error('ラボは owner/リポジトリ');
  const panel = /^https:\/\/[^\s"<>]+$/.test(String(panelUrl)) ? String(panelUrl) : '';
  const manifest = { name: PLUGIN_NAME, version: PLUGIN_VERSION, description: `${lab}（bds-lab: Minecraft 統合版アドオンのラボ）を AI が直接操作します — 実行・ログ・ファイル・試験・仕上げ・秘密・変数・メンバー・予約`, author: { name: 'bds-lab' }, ...(panel ? { homepage: panel } : {}), keywords: ['minecraft', 'bedrock', 'addon', 'github-actions', 'bds-lab'] };
  return {
    '.claude-plugin/plugin.json': `${JSON.stringify(manifest, null, 2)}\n`,
    '.mcp.json': `${JSON.stringify({ mcpServers: { [PLUGIN_NAME]: { type: 'http', url: u } } }, null, 2)}\n`,
    'skills/bds-lab/SKILL.md': skill(lab, panel, u.slice(0, -'/mcp'.length)),
    'README.md': readme(lab, u, panel),
  };
}

function skill(lab, panel, base) {
  return `---
name: bds-lab
description: Use whenever the person talks about their bds-lab or ${lab} — Minecraft Bedrock addons made and proven on a real server by GitHub Actions — to see how it is doing, debug a failed run or test, fix or change an addon, make a new one, run its tests or build its .mcaddon, set secrets or variables, schedule runs, or manage members. Works through the bds-lab tools (MCP).
---

# Working ${lab} through the bds-lab tools

The bds-lab tools act on ${lab} as the person who connected them: GitHub's permissions first, then the lab's role policy (.github/bds-lab-panel.json). Every write goes in the lab's audit log when the lab keeps one. Answers come mostly in Japanese; talk to the person in their language.

## Start

1. Call \`lab_status\`: who the person is in the lab, what they may do, the setup checks, the newest run of each workflow, and what is failing.
2. If a setup row is not ✅, \`setup_checks\` explains it; \`setup_fix\` runs the fixes the lab can do itself. Making or installing the GitHub App needs GitHub's own buttons — send the person to the panel's 「準備」 → 「全自動で準備する」${panel ? ` (${panel})` : ''}.

## Fix something that fails

1. \`runs_list\` (a workflow: verify.yml, unit.yml …) → the failed run's id.
2. \`run_detail\` → where it failed, why, and the next step (the panel's diagnosis), with the failed job's annotations.
3. \`run_log\` with \`grep\` (e.g. \`error|fail|expected\`) → the lines that matter, numbered.
4. \`file_read\` the files involved → keep the \`sha\` it gives.
5. \`file_write\` the whole new text with that \`sha\` (never write blind: a file that exists needs its sha, so nobody's change is lost). One focused change per commit, a clear message.
6. Prove it: \`unit_run\` (job \`test\`) for a unit, or \`workflow_run\` for another workflow → \`run_detail\` until it is green. Then \`unit_run\` job \`go\` builds the .mcaddon (\`releases_list\`).

Never weaken a test to make it pass: fix the addon.

## Units (addons)

A unit lives in \`bds/addons/<name>/\`: \`src/main.ts\` (TypeScript on the Script API, through \`src/kit.ts\` — read it), \`tests.txt\`, \`TASK.md\`, \`bp/\` and \`rp/\` (behaviour and resource packs, \`texts/en_US.lang\` and \`ja_JP.lang\`).

- \`units_list\` shows them; \`unit_new\` makes one (no AI cost); edit its files with \`file_read\` / \`file_write\`.
- tests.txt: one \`## section\` per thing asked; a command line, then expectations for its output: \`= exact\`, \`~ regex\`, \`! absent\`, \`!~ absent regex\`. Players are real clients: \`@A join\`, \`@A cmd /ns:cmd\`, \`@A chat hi\`, \`@A form 1\`, \`@A use\` …
- The lab's \`AGENTS.md\` (\`file_read\`) has the whole method and the kit's API: read it before writing an addon.

## Ask the person first

- A tool that answers that confirmation is needed (\`confirm: true\`): say what will happen, ask, and call again with \`confirm: true\` only after they agree.
- \`ai_make\` and AI workflows spend the lab's AI key: ask first.
- Deleting a secret, removing a member, cancelling a run: ask first.
- Never ask the person to paste a secret into the chat when the panel can take it; if they hand you one to set, use \`secret_set\` and never repeat it.

## When the bds-lab tools are not there

If no bds-lab tool is available (the connector was not added, or it did not connect), the same tools answer over plain HTTPS at ${base} — connect with the device sign-in, one link the person opens:

1. \`POST ${base}/device/code\` (form field \`client_name\`: your name) → \`user_code\`, \`verification_uri_complete\`, \`device_code\`, \`client_id\`, \`interval\`.
2. Give the person the \`verification_uri_complete\` link and the \`user_code\`: they open it, see the same code, press 「許可して GitHub へ」 and GitHub's 「Authorize」.
3. Every \`interval\` seconds \`POST ${base}/token\` (form: \`grant_type=urn:ietf:params:oauth:grant-type:device_code\`, \`device_code\`, \`client_id\`): \`authorization_pending\` → wait; \`access_token\` → connected (handed out once); \`access_denied\` / \`expired_token\` → ask the person and start again. The code lasts 10 minutes.
4. Call \`POST ${base}/api/<tool>\` with \`Authorization: Bearer <access_token>\` and the tool's arguments as a JSON body (read-only tools also \`GET ${base}/api/<tool>?arg=value\`). \`GET ${base}/api\` lists the tools with their input schemas; \`${base}/openapi.json\` and \`${base}/llms.txt\` describe them.

Never show the token. It lasts 8 hours; \`POST ${base}/token\` with \`grant_type=refresh_token\`, \`refresh_token\` and \`client_id\` renews it.

## Never

- \`.github/\` (the lab's CI and policy — the timetable only through \`schedule_set\`), \`auto/policy.json\`, \`auto/STOP\`, \`.env\` files: a person changes those (the tools refuse).
- Guessing a file's content: read it first.
`;
}

function readme(lab, url, panel) {
  return `# bds-lab — Claude プラグイン（${lab}）

Claude が ${lab} を直接操作するためのプラグインです。中身は 2 つ:

- **MCP サーバー** \`${url}\`（ラボのサインインのサービスにある、AI 用の API）
- **スキル** bds-lab（ラボの扱い方: 様子を見る → 落ちた実行を調べる → 直す → 試験 → 仕上げ）

## つなぎ方

1. Claude でこのプラグインを入れます。
2. 最初に道具を使うとき、Claude が「連携」を求めます → 開いた画面で「許可して GitHub へ」→ GitHub の「Authorize」。
3. あとは「ラボの様子は？」「落ちた試験を直して」「新しいアドオンを作って」のように頼むだけです。

コネクタを足せない AI でも、「${url.slice(0, -'/mcp'.length)}/llms.txt を読んで、デバイスのサインインでつないで」と頼めば、AI が出すリンクを開いて
「許可して GitHub へ」→「Authorize」でつながります。

AI はあなたの GitHub のアカウントで動きます。GitHub の権限・ラボの役割の決まり・確認・監査ログは管理パネルと同じで、
\`.github/\`（CI と決まり）、\`auto/policy.json\`・\`auto/STOP\`、\`.env\` は変えられません。

前提: ラボに GitHub App が入っていること（管理パネル${panel ? ` ${panel}` : ''} の「準備」→「全自動で準備する」）。
`;
}

// ---- a zip of stored (uncompressed) files ----
const CRC = (() => { const t = new Uint32Array(256); for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; } return t; })();
/** CRC-32 of bytes (pure) */
export const crc32 = (b) => { let c = 0xffffffff; for (let i = 0; i < b.length; i++) c = CRC[(c ^ b[i]) & 0xff] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; };
/** { path: text | Uint8Array } → the bytes of a zip that stores them (pure; a fixed time: the same files, the same bytes) */
export function zip(files) {
  const enc = new TextEncoder(), parts = [], central = [];
  const TIME = 0, DATE = ((2026 - 1980) << 9) | (1 << 5) | 1;
  let off = 0;
  for (const [name, data] of Object.entries(files)) {
    if (!name || name.startsWith('/') || name.split('/').includes('..')) throw new Error(`zip: ${name}`);
    const n = enc.encode(name), d = typeof data === 'string' ? enc.encode(data) : data, crc = crc32(d);
    const local = new Uint8Array(30 + n.length), lv = new DataView(local.buffer);
    lv.setUint32(0, 0x04034b50, true); lv.setUint16(4, 20, true); lv.setUint16(6, 0x0800, true); lv.setUint16(8, 0, true);
    lv.setUint16(10, TIME, true); lv.setUint16(12, DATE, true); lv.setUint32(14, crc, true); lv.setUint32(18, d.length, true); lv.setUint32(22, d.length, true);
    lv.setUint16(26, n.length, true); lv.setUint16(28, 0, true); local.set(n, 30);
    const c = new Uint8Array(46 + n.length), cv = new DataView(c.buffer);
    cv.setUint32(0, 0x02014b50, true); cv.setUint16(4, 20, true); cv.setUint16(6, 20, true); cv.setUint16(8, 0x0800, true); cv.setUint16(10, 0, true);
    cv.setUint16(12, TIME, true); cv.setUint16(14, DATE, true); cv.setUint32(16, crc, true); cv.setUint32(20, d.length, true); cv.setUint32(24, d.length, true);
    cv.setUint16(28, n.length, true); cv.setUint32(42, off, true); c.set(n, 46);
    parts.push(local, d); central.push(c); off += local.length + d.length;
  }
  const size = central.reduce((s, c) => s + c.length, 0), end = new Uint8Array(22), ev = new DataView(end.buffer);
  ev.setUint32(0, 0x06054b50, true); ev.setUint16(8, central.length, true); ev.setUint16(10, central.length, true); ev.setUint32(12, size, true); ev.setUint32(16, off, true);
  const all = new Uint8Array(off + size + 22);
  let at = 0;
  for (const p of [...parts, ...central, end]) { all.set(p, at); at += p.length; }
  return all;
}
/** the lab's .plugin file's bytes (pure) */
export const pluginZip = (opts) => zip(pluginFiles(opts));
