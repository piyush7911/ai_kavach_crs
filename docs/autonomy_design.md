# Autonomous mode — design note

`python -m src.main --target <repo> --mode auto`

## What it does today

| Stage | Module | Status |
|---|---|---|
| Ingest: snapshot (sha256), census, build detection | `src/autonomy/ingest.py` | written, not yet run on the Mac |
| Static scan, findings mapped to their enclosing function | `src/autonomy/runner.py` + Semgrep | written, not yet run |
| Code index: functions, parameters, call sites, caller array sizes, declaring header | `src/autonomy/codeindex.py` | written, not yet run |
| Harness synthesis: entry point, caller-derived preconditions, templates, LLM fallback, fairness check | `src/autonomy/harness.py` | written, not yet run |
| Build with sanitizers, reach judge, campaign, triage, PoV pre-flight, repair, hardening | — | **not in this build** |

Every finding ends in `evidence.json` with a status and a written reason. In this
build the best status is `harness_ready`, with the reason saying that the build and
fuzz stage is pending. Nothing is reported as proven.

## Principles (from our own failures, not borrowed)

1. **Finding-driven.** The scan says which function is suspect; the harness is
   built for that function, not for a library's public API in general.
2. **Preconditions come from real callers.** Three of our own targets were
   unfixable "by contract" because a harness broke a rule no real caller breaks.
   So the builder reads every call site: arguments that are always literals become
   a closed set; local arrays of literal size fix buffer sizes; `sizeof(x)` ties a
   length to a buffer.
3. **Reaching the function is the success criterion** (reach judge, pending), not
   "gained some coverage".
4. **Deterministic first, model second.** `(buf, len)`, C strings, integers and
   caller-sized output buffers are template-filled. Other shapes are drafted by the
   model and then judged; the model's text is never trusted on its own.
5. **No silent skips.** If no fair harness exists, the reason is written down.

## Static functions

A `static` function cannot be called from a harness. The builder walks callers
upward (breadth-first, three levels) to the nearest externally visible function
and records the call path.

## Fairness check

Applied to every harness, template or drafted:
- the harness calls the entry point and defines `LLVMFuzzerTestOneInput`;
- literal-only parameters receive one of the callers' literals;
- a buffer is never smaller than the smallest one a real caller passes;
- a buffer is never filled with more bytes than were allocated.

## Prior art

Using a language model to help write fuzz harnesses is established public practice;
Google's OSS-Fuzz-Gen is the best-known example. This design is built from our own
pipeline and from the failures listed above: finding-driven targeting,
preconditions read from callers, and a reach judge rather than a coverage target.

## Safety

The dashboard accepts the upload by id only; no free-text command from the browser
reaches a shell. In this build nothing from an upload is compiled or executed, only
read and scanned. When the build and fuzz stage lands, it must run under
`KAVACH_SANDBOX=required` (see `src/patch_validator/sandbox.py`).
