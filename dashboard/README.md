# AI Kavach — live dashboard

One FastAPI server and one static page. No node, no build step, no database.

```bash
python -m dashboard                # http://127.0.0.1:8000
python -m dashboard --port 9000
```

Binding a network interface requires a token, because the server can start jobs
and accept uploads:

```bash
export KAVACH_DASH_TOKEN=<something-long>
python -m dashboard --host 0.0.0.0     # then open  /?token=<it>
```

## What it shows

| Tab | Contents |
|---|---|
| **Overview** | Headline figures with their 95% interval, toolchain health, model backend (cloud or local), what was not measured |
| **Results** | Any run on disk: per-target gates, hardening, formal result, cost and time. Filter and drill down |
| **Run benchmark** | Choose suite, flags and backend (cloud or local model); live progress and log; stop button |
| **Special cases** | Cheat detector, PoV pre-flight, model check, unit tests, real-defect suite |
| **Drop a repo** | Drag in a zip or a folder; it is described (files, lines, build system) before anything runs |
| **How it works** | The pipeline and the rules the system keeps |

## Rules

- **It displays only what a run produced.** Results are read from `reports/`,
  progress from the event stream, memory from the OS and from Ollama. A missing
  result is an empty state, never a placeholder.
- **One heavy job at a time.** Timing and memory are published figures, and two
  concurrent jobs would corrupt both.
- **Browser input never reaches a shell.** Jobs are argument lists built from
  whitelisted choices; free-text fields are validated against a strict pattern.
- **Uploads are untrusted.** Zip-slip paths, absolute paths, backslashes,
  symlinks, oversized files and zip bombs are rejected before anything is written,
  and a rejected upload leaves nothing behind. Nothing is built or run on upload.
- **Local-model memory is asked of Ollama, not read from `ps`.** On Apple Silicon
  the weights live in GPU-visible memory and do not appear in a process's RSS.
  Measured here: `ps` showed 24 MB for a model Ollama reports as 4.77 GiB.

## Layout

```
app.py          routes, request validation, SSE streaming
jobs.py         one-at-a-time job manager, resource sampling, event-derived progress
results.py      reads run artefacts; computes the headline and intervals
health.py       tool probes, machine info, Ollama status and memory
uploads.py      safe archive extraction, dropped-folder handling, census
tasks/          preflight.py (PoV validity for every target), modelcheck.py
static/         index.html + kavach.css (design tokens shared with design/ui-concept)
runs/           per-job log, events and metadata   (gitignored)
uploads/        dropped repositories               (gitignored)
```

Tests: `tests/unit/test_dashboard.py` (56 tests, no network, no model).

## Status

Autonomous analysis of a dropped repository is **not built yet** (workstream A in
`FINALE_PLAN.md`). Uploads are stored and described; the "Start analysis" button
stays disabled and says why.
