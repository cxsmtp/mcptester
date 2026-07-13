# Hardened image. Pinned digest, non-root, no secrets, production install, healthcheck.
FROM node:20-slim@sha256:0000000000000000000000000000000000000000000000000000000000000000

# Create an unprivileged user.
RUN groupadd -r app && useradd -r -g app app

WORKDIR /app

# Install only production deps with a locked, audited tree.
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

# Copy source (a .dockerignore excludes .env, tests, git, etc.).
COPY --chown=app:app . .

USER app
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s CMD node -e "require('http').get('http://127.0.0.1:3000/health',r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"

# Secrets are injected at runtime via the orchestrator, never baked into layers.
CMD ["node", "src/app.js"]
