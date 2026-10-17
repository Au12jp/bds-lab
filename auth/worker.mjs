// auth/worker.mjs: the sign-in service and the lab's API for AI (api.mjs: /mcp, /api) as one Cloudflare Worker (wrangler.toml).
// Its env is the Worker's own: GITHUB_CLIENT_ID, PANEL_ORIGINS and LAB_SLUG as vars, GITHUB_CLIENT_SECRET and STATE_SECRET as
// secrets (README.md).
import { handler } from './handler.mjs';
import { api } from './api.mjs';

export default {
  async fetch(req, env) {
    const auth = handler(env), lab = api(env, { self: auth });
    return (await lab(req)) ?? auth(req);
  },
};
