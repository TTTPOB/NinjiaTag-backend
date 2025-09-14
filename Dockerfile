# syntax=docker/dockerfile:1
FROM node:22-bookworm

# Set workdir
WORKDIR /app

# Install Python and build toolchain for sqlite3
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-pip ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Python deps used by request_reports.py and pypush_gsa_icloud.py
RUN python3 -m pip install --no-cache-dir \
    aiohttp requests cryptography pycryptodome srp pbkdf2

# Copy package manifests and install Node deps
COPY package*.json ./
RUN npm ci --only=production || npm install --omit=dev

# Copy app sources
COPY . .

# Runtime env
ENV NODE_ENV=production \
    DATA_DIR=/data \
    KEYS_DIR=/app/keys \
    ANISETTE_URL=http://anisette:6969

# Persist db and auth
VOLUME ["/data"]

EXPOSE 3000

# Healthcheck against simple endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:3000/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))" || exit 1

# Default: run combined server + scheduler. Also supports `login` subcommand.
ENTRYPOINT ["node", "cli.mjs"]
CMD ["run"]

