// auth/worker.mjs: the sign-in service and the lab's API for AI (api.mjs: /mcp, /api) as one Cloudflare Worker (wrangler.toml).
// Its env is the Worker's own: GITHUB_CLIENT_ID, PANEL_ORIGINS and LAB_SLUG as vars, GITHUB_CLIENT_SECRET and STATE_SECRET as
// secrets, and STORE — a Durable Object (Store, below) that holds the device sign-in's codes for their ten minutes, the one
// thing this service keeps (without it, the device sign-in is simply not offered) (README.md).
import { handler } from './handler.mjs';
import { api } from './api.mjs';

/** the device sign-in's store as a Durable Object: { op: get | put | take, key, value, ttl } → { value }. Each value with its
 *  time; an alarm sweeps what ran out. One instance for the lab (a handful of sign-ins: never busy) */
export class Store {
  constructor(state) { this.state = state; }
  async fetch(req) {
    let o; try { o = await req.json(); } catch { return Response.json({ error: 'body' }, { status: 400 }); }
    const s = this.state.storage, now = Date.now(), key = String(o?.key ?? '');
    if (!/^[du]:[A-Za-z0-9_-]{1,64}$/.test(key) || !['get', 'put', 'take'].includes(o?.op)) return Response.json({ error: 'key' }, { status: 400 });
    if (o.op === 'put') {
      await s.put(key, { v: o.value, exp: now + Math.min(Math.max(Number(o.ttl) || 0, 1000), 3_600_000) });
      if (!(await s.getAlarm())) await s.setAlarm(now + 15 * 60_000);
      return Response.json({ ok: true });
    }
    const x = await s.get(key), v = x && x.exp > now ? x.v : null;
    if (o.op === 'take' || (x && v === null)) await s.delete(key);
    return Response.json({ value: v ?? null });
  }
  async alarm() {
    const s = this.state.storage, now = Date.now();
    for (const [k, x] of await s.list({ limit: 1000 })) if (!(x?.exp > now)) await s.delete(k);
    if ((await s.list({ limit: 1 })).size) await s.setAlarm(now + 15 * 60_000);
  }
}
/** a Durable Object namespace → the store handler.mjs takes ({ get, put, take }) */
export function doStore(ns) {
  const call = async (op, key, value, ttl) => {
    const r = await ns.get(ns.idFromName('bds-lab')).fetch('https://store/', { method: 'POST', body: JSON.stringify({ op, key, value, ttl }) });
    return (await r.json()).value ?? null;
  };
  return { get: (k) => call('get', k), put: (k, v, ttl) => call('put', k, v, ttl), take: (k) => call('take', k) };
}

export default {
  async fetch(req, env) {
    const store = env.STORE ? doStore(env.STORE) : null, auth = handler(env, { store }), lab = api(env, { self: auth, device: Boolean(store) });
    return (await lab(req)) ?? auth(req);
  },
};
