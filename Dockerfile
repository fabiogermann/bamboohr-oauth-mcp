# syntax=docker/dockerfile:1.7

# ---- Build stage: install deps, compile TypeScript, prune to prod ----
FROM node:22-alpine AS builder

WORKDIR /build

# Install ALL deps (incl. devDependencies needed for tsc) using package.json
# only first, so the layer cache reflects only manifest changes.
COPY adapter/package.json adapter/package-lock.json* ./
# `npm ci` would be ideal but the lockfile is .gitignore'd in dev; fall back
# to `npm install` for now. Replace with `npm ci` once we ship a lockfile.
RUN npm install --no-audit --no-fund

# Copy sources and build.
COPY adapter/tsconfig.json ./
COPY adapter/src ./src
RUN npx tsc

# Prune devDependencies for runtime copy.
RUN npm prune --omit=dev

# ---- Runtime stage: minimal, non-root ----
FROM node:22-alpine AS runtime

# tini handles PID 1 signal forwarding (K8s SIGTERM).
RUN apk add --no-cache tini \
 && addgroup -S app && adduser -S app -G app

WORKDIR /app

COPY --from=builder --chown=app:app /build/node_modules ./node_modules
COPY --from=builder --chown=app:app /build/dist ./dist
COPY --from=builder --chown=app:app /build/package.json ./package.json

# Required env (must be supplied at runtime; do NOT bake secrets in):
#   BAMBOOHR_COMPANY_DOMAIN
#   BAMBOOHR_OAUTH_CLIENT_ID
#   BAMBOOHR_OAUTH_CLIENT_SECRET
#   WRAPPER_ENC_KEY_BASE64
#   PUBLIC_BASE_URL
# Optional:
#   PORT (default 3000)
#   BAMBOOHR_OAUTH_SCOPES (default: offline_access only)
#   WRAPPER_BEARER_TTL_SECONDS (default 3600)
#   WRAPPER_REFRESH_SKEW_SECONDS (default 60)
ENV NODE_ENV=production \
    PORT=3000

USER app
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||3000)+'/healthz').then(r=>{if(r.status!==200)process.exit(1)}).catch(()=>process.exit(1))"

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "/app/dist/index.js"]
