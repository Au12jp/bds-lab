// node common/claude-plugin.mjs --url <https://…/mcp | the sign-in service's address> --lab <owner/repo> [--panel <url>] [--out <file>]
// The lab's Claude plugin (panel/lib/pluginpack.mjs: its MCP server — the lab's API for AI — and a skill) written as a .plugin
// file Claude's apps install. The 「準備」 tab's 「Claude 用プラグイン」 button makes the same bytes in the browser.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { pluginZip, PLUGIN_NAME } from '../panel/lib/pluginpack.mjs';

/** argv → { url, lab, panel, out } (pure): the service's address alone becomes its /mcp */
export function options(argv) {
  const get = (k) => { const i = argv.indexOf(`--${k}`); return i >= 0 ? argv[i + 1] : undefined; };
  const raw = String(get('url') ?? process.env.BDS_LAB_MCP_URL ?? '').trim().replace(/\/+$/, '');
  const url = raw && !/\/mcp$/.test(raw) ? `${raw}/mcp` : raw;
  return { url, lab: get('lab') ?? process.env.BDS_LAB_SLUG ?? '', panel: get('panel') ?? '', out: get('out') ?? `${PLUGIN_NAME}.plugin` };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const o = options(process.argv.slice(2));
  try {
    const bytes = pluginZip({ mcpUrl: o.url, lab: o.lab, panelUrl: o.panel });
    fs.mkdirSync(path.dirname(path.resolve(o.out)), { recursive: true });
    fs.writeFileSync(o.out, bytes);
    console.log(`OK ${o.out}（${bytes.length} バイト: MCP ${o.url}・ラボ ${o.lab}）: Claude に渡して入れてください`);
  } catch (e) {
    console.log(`だめでした: ${e.message}\n使い方: node common/claude-plugin.mjs --url https://<サインインのサービス> --lab <owner/repo> [--panel <パネルの URL>] [--out bds-lab.plugin]`);
    process.exit(1);
  }
}
