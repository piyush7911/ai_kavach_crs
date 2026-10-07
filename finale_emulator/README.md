# Finale VM emulator

Reproduces the finale target environment on `localhost` so the whole offline run can be rehearsed.

| Finale piece | Emulator |
|---|---|
| VM over SSH + password | `ssh root@localhost -p 2222` (password `kavach`) |
| live IP:PORT | `http://localhost:4100` |
| codebase tar.gz | `/root/app.tar.gz` (inside the VM) |
| source path | `/opt/app` |
| restart.sh | `/opt/restart.sh` |

Wrapped app: **NodeGoat** (+ Mongo). Swap the app by changing the `COPY` in `Dockerfile` and the
start/seed lines in `restart.sh`.

```bash
# from the repo root
./finale_emulator/up.sh      # build (first run, needs internet) + start, prints coordinates
./finale_emulator/down.sh    # stop + remove
```

Full step-by-step (offline): see **[docs/FINALE_RUNBOOK.md](../docs/FINALE_RUNBOOK.md)**.
