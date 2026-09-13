# AEGIS Review UI (Next.js 15)

Pages (SPEC §6): **Queue**, **Investigation** (hypotheses, evidence drawer, timeline, cited report,
recommend-only playbook with approve/override/annotate), **Labels** (overrides → training labels),
**Metrics** (live accuracy, fast-path rate, cost/alert; Lens embeds here).

## Run
```
# 1) start the API (SQLite-backed, no server needed)
aegis serve                       # http://127.0.0.1:8000
# 2) start the UI (proxies /api to the backend via next.config rewrites)
cd web && npm install && npm run dev   # http://localhost:3000
```
Populate the queue from the UI ("Investigate 15 alerts") or via `POST /api/investigate`.
