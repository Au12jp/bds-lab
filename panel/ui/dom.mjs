// dom: the panel's few DOM helpers, shared by panel.js and the screens in panel/ui/ (text is always text: never parsed as
// HTML; no inline style attribute — the page's CSP allows none — styles go through the CSSOM).
// (a missing part is nothing, everywhere: the browser's own replaceChildren / append / prepend would write null, undefined
// or false as the words 「null」「undefined」「false」 — the panel passes `cond ? part : null` to them as it does to h(); an
// array is its items, as in h())
export const keep = (kids) => kids.flat(Infinity).filter((c) => c !== null && c !== undefined && c !== false);
for (const P of [globalThis.Element?.prototype, globalThis.DocumentFragment?.prototype, globalThis.Document?.prototype]) {
  if (!P || P.__bdslabKeep) continue;
  for (const m of ['replaceChildren', 'append', 'prepend', 'before', 'after', 'replaceWith']) {
    const own = P[m];
    if (typeof own === 'function') Object.defineProperty(P, m, { configurable: true, writable: true, value: function (...kids) { return own.apply(this, keep(kids)); } });
  }
  Object.defineProperty(P, '__bdslabKeep', { value: true });
}
export const h = (tag, attrs = {}, ...kids) => {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs ?? {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k.startsWith('on') && typeof v === 'function') e.addEventListener(k.slice(2), v);
    else if (k === 'class') e.className = v;
    else if (k === 'value') e.value = v;
    else if (k === 'checked') e.checked = Boolean(v);
    // (styles through the CSSOM: the page's CSP allows no inline style attribute)
    else if (k === 'style' && typeof v === 'object') Object.assign(e.style, v);
    else e.setAttribute(k, v === true ? '' : String(v));
  }
  for (const c of kids.flat(Infinity)) if (c !== null && c !== undefined && c !== false) e.append(c instanceof Node ? c : document.createTextNode(String(c)));
  return e;
};
export const $ = (id) => document.getElementById(id);
export const main = () => $('main');
export const toast = (text, bad = false, more = null) => { const d = h('div', { class: bad ? 'bad' : '' }, text, more ? [' ', more] : null); $('toast').append(d); setTimeout(() => d.remove(), bad ? 9000 : 4500); };
// (what to offer when something fails: the page sets it — onFail(error, retry) → an element: the next step, e.g. GitHub
// refused this sign-in's rights → the way to more; the network → again)
let onFail = null;
export const setOnFail = (fn) => { onFail = fn; };
/** the same way out, drawn in place (a tab that could not load, a row that could not be read): the words of the failure and
 *  the next step — always something, never an empty box. retry: what 「もう一度」 does there */
export const failView = (e, retry = null) => { let more = null; try { more = onFail?.(e, retry) ?? null; } catch { /* the words alone */ } return h('div', { class: 'bad', role: 'alert' }, e?.message ?? String(e ?? '読めませんでした'), more ? [' ', more] : null); };
export const act = async (fn, done) => { try { const r = await fn(); if (done) toast(done); return r; } catch (e) { let more = null; try { more = onFail?.(e, () => act(fn, done)) ?? null; } catch { /* no way out offered */ } toast(e.message ?? String(e), true, more); return undefined; } };
// (an address from GitHub's answers: only https:// ones become links, anything else stays words)
export const link = (href, text) => (/^https:\/\//.test(String(href ?? '')) ? h('a', { href, target: '_blank', rel: 'noopener noreferrer' }, text) : h('span', {}, text));
