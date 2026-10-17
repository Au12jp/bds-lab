# auth/Dockerfile: the sign-in service and the lab's API for AI on your own server (README.md). Built from the lab's top, but
# only these go in — auth/'s three files and the panel's pure modules the API runs (panel/lib):
#   docker build -f auth/Dockerfile -t bds-lab-auth .
# It speaks plain HTTP on PORT: put it behind TLS (a reverse proxy) at the root of its own https origin, PUBLIC_URL = that origin.
FROM node:22-alpine
WORKDIR /srv
# (root owns the code, the service only reads it)
COPY auth/handler.mjs auth/api.mjs auth/node.mjs ./auth/
COPY panel/lib/ ./panel/lib/
WORKDIR /srv/auth
ENV NODE_ENV=production HOST=0.0.0.0 PORT=8787
EXPOSE 8787
USER node
HEALTHCHECK --interval=60s --timeout=5s CMD ["node", "-e", "fetch('http://127.0.0.1:' + process.env.PORT + '/health').then((r) => process.exit(r.ok ? 0 : 1), () => process.exit(1))"]
CMD ["node", "node.mjs"]
