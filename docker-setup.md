**Overview**
- Builds a single container running both the HTTP API and the periodic location fetcher. No pm2 required.
- Persists state under `/data` (SQLite `reports.db` and `auth.json`).
- Adds a `login` command to do the Apple ID + 2FA flow interactively.

**Prereqs**
- Docker installed and running.
- Anisette server available in Docker network (recommended): `dadoum/anisette-v3-server`.

**1) Create a Docker network**
- `docker network create mh-network`

**2) Start Anisette**
- `docker run -d --restart always --name anisette --network mh-network -p 6969:6969 dadoum/anisette-v3-server`

**3) Build the backend image**
- From repo root: `docker build -t ninjia-backend .`

**4) First-time login (interactive)**
- Create a data directory on the host (for persistence): `mkdir -p ninjia-data`
- Run interactive login to generate `/data/auth.json`:
- `docker run --rm -it --network mh-network -v $(pwd)/ninjia-data:/data --name ninjia-login ninjia-backend login`
- Follow prompts: enter Apple ID, password, then SMS code (or use `--trusteddevice`).

Notes:
- If Anisette runs on a different host/port, pass `-e ANISETTE_URL=http://host:port` to the command above.
- Keys: place your `.keys` files under `ninjia-data/keys` or mount a separate path and pass `-e KEYS_DIR=/data/keys`.

**5) Run the backend**
- `docker run -d --restart always --name ninjia-backend --network mh-network -p 3000:3000 -v $(pwd)/ninjia-data:/data ninjia-backend`

What it does:
- Starts `server.mjs` (Express API at `:3000`) and schedules `request_reports.py` every 5 minutes.
- Uses `/data/reports.db` for storage, `/data/auth.json` for credentials. Health endpoint: `GET /health`.

**6) Environment variables**
- `DATA_DIR` (default `/data`): where `reports.db` and `auth.json` live.
- `KEYS_DIR` (default `/app/keys`): directory to recursively discover `*.keys` files.
- `ANISETTE_URL` (default `http://anisette:6969`): anisette server URL.
- Example: `-e DATA_DIR=/data -e KEYS_DIR=/data/keys -e ANISETTE_URL=http://anisette:6969`.

**7) Example: mounting keys from host**
- `mkdir -p ninjia-data/keys`
- Copy your key files to `ninjia-data/keys/`.
- Run: `docker run -d --restart always --name ninjia-backend --network mh-network -p 3000:3000 -v $(pwd)/ninjia-data:/data -e KEYS_DIR=/data/keys ninjia-backend`

**8) Logs and troubleshooting**
- View logs: `docker logs -f ninjia-backend`
- Verify health: `curl http://localhost:3000/health`
- If login fails at 2FA: re-run `login` interactively and ensure Anisette is reachable.

**Why no pm2?**
- In-container process supervision is simplified: the Node process imports both the HTTP server and the scheduler (`app.mjs`). Docker restarts the container if the process exits. This keeps the setup minimal and reliable without a separate process manager.

