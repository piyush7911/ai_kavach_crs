# Held-out validation — pre-registration

This file is written **before** anything is run on the held-out libraries, and
committed with its date. Once a library is listed here it may not be swapped for
another because it did badly.

## Rules

1. Four C libraries, each: under ~50k lines, flat or Makefile build, with a
   published memory-safety fix in its git history.
2. Each entry is **verified before it is listed**: the repository clones, the
   vulnerable ref and the fixed ref both exist, and the library builds. A CVE
   identifier is written only after checking it against the upstream advisory
   or commit message.
3. No tuning on these libraries. A failure found here is fixed at its cause; the
   fix must also pass the 44-target regression suite, and no target-specific
   code is allowed.
4. Results are reported separately from the main corpus, including every failure
   and its reason.
5. Success is: no unhandled exception, no silently skipped gate, and a written
   reason for every case not proven.

## Registered libraries

Status: **not yet registered.** Fill in on the Mac after verification (rule 2),
then commit, then run. `heldout.json` holds the same list in machine-readable
form for `run_heldout.py`.

| # | Library | Repository | Vulnerable ref | Fixed ref | Defect (verified id) | Build | Verified on (date) |
|---|---|---|---|---|---|---|---|
| 1 | | | | | | | |
| 2 | | | | | | | |
| 3 | | | | | | | |
| 4 | | | | | | | |

## Registration date

(to be filled when the table above is committed)
