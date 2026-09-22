# Deploying the AEGIS demo for $0 (COST.md)

Target: one small always-free VM running `docker-compose.demo.yml` behind Caddy with a free DuckDNS
hostname, so a judge can open a link. Offline snapshot data only; no external SIEM. Nothing here
needs a card.

## 1. Oracle Cloud Always Free ARM VM (primary)

1. Create a **VM.Standard.A1.Flex** instance: 4 OCPU, 24 GB RAM, Ubuntu 24.04 (all within Always Free).
2. Open ports 80 and 443 in the VCN security list. Keep 8000 and 3000 closed; Caddy fronts them.
3. On the VM:

```bash
sudo apt-get update && sudo apt-get install -y docker.io docker-compose-v2 git make
sudo usermod -aG docker $USER && newgrp docker
git clone https://github.com/AmatyaJoshi/AEGIS-Autonomous-Security-Investigation-Agent.git aegis
cd aegis
cp .env.example .env            # set AEGIS_AUTH_SECRET to a long random string
```

4. Build the data once (about 25 minutes, 140 MB download from GitHub; free):

```bash
docker compose -f docker-compose.demo.yml build api
docker compose -f docker-compose.demo.yml run --rm api sh -c \
  "python -m aegis.cli lab load --datasets otrf,evtx && python -m aegis.cli lab noise --days 14 --per-day 12 && \
   python -m aegis.cli lab rules && python -m aegis.cli bench prepare && python -m aegis.cli lab snapshot --name dev && \
   python -m aegis.cli bench build && python -m training.triage.build_dataset --snapshot dev && \
   python -m training.triage.train"
```

5. Start the stack and seed the demo:

```bash
make up                                   # api + web + ollama (+ llama3.1:8b pull, ~4.9 GB, once)
docker compose -f docker-compose.demo.yml exec api python -m aegis.cli demo --ui-url https://<name>.duckdns.org
```

On a 4-OCPU ARM VM an 8B model on CPU answers in roughly 30 to 90 s per call, so the `demo` command
sets a 60 s per-call timeout and falls back to the deterministic reasoner when the model is slow. The
header badge says which reasoner produced each run. For a faster live LLM path set `GROQ_API_KEY` or
`GEMINI_API_KEY` in `.env` (free tiers, no card) and `AEGIS_LLM_PROVIDER=groq` or `gemini`.

## 2. Free hostname + TLS: DuckDNS + Caddy

```bash
# duckdns.org: create <name>.duckdns.org pointing at the VM's public IP (free), then:
sudo apt-get install -y caddy
sudo tee /etc/caddy/Caddyfile >/dev/null <<EOF
<name>.duckdns.org {
    handle /api/* { reverse_proxy 127.0.0.1:8000 }
    handle /health  { reverse_proxy 127.0.0.1:8000 }
    handle          { reverse_proxy 127.0.0.1:3000 }
}
EOF
sudo systemctl reload caddy      # Let's Encrypt certificate is automatic
```

## 3. Backup: Render free tier

Two free web services from the same repo: `api` (Dockerfile at repo root) and `web`
(`web/Dockerfile`, env `AEGIS_API_URL=https://<api>.onrender.com`). Free instances sleep after
15 minutes idle and wake in about a minute; open the link before the demo. There is no Ollama on
Render's free tier, so the API runs the deterministic reasoner unless a Groq/Gemini key is set. The
data build must run in the image (`RUN make data`) because free services have no persistent disk.

## 4. Analytics (optional, free): self-hosted Umami

```bash
docker run -d --name umami -p 3001:3000 -e DATABASE_URL=sqlite:///umami.db ghcr.io/umami-software/umami:postgresql-latest
```

Create a website in Umami, then rebuild the web image with
`NEXT_PUBLIC_UMAMI_SRC=https://<name>.duckdns.org/umami/script.js` and `NEXT_PUBLIC_UMAMI_ID=<id>`
(and add a `handle /umami/*` block to the Caddyfile). Page views only. Numbers in the pitch come from
this dashboard or are not quoted at all.

## 5. Teardown

```bash
make down                 # keep volumes
docker compose -f docker-compose.demo.yml down -v   # also delete the pulled model
```

Delete the VM and the DuckDNS record after the buildathon if they are no longer needed.
