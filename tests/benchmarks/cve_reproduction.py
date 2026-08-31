"""
AI Kavach CRS — historical-CVE reproduction harness.

SUPERSEDED. Do not use. Kept only so the reason is on record.

The previous version of this file defined two real CVE identifiers
(CVE-2015-8126 in libpng, CVE-2017-9048 in libxml2) and ran the pipeline
against them. It could not honestly report anything about either:

  * It declared a `pov_command` on each entry and then **never passed it** to
    `run_pipeline`, so the proof-of-vulnerability gate was SKIPPED. A "patched"
    result therefore meant only "the code still compiles and `make check`
    passes" — no exploit was ever replayed, before or after the patch.
  * The two PoV inputs it named, `bad_palette.png` and `bad_xml.xml`, do not
    exist anywhere in this repository and never did.
  * The vulnerable commits were 7-character abbreviations annotated by hand and
    were never verified to be the commit preceding the fix.

Publishing "we fixed CVE-2015-8126" on that basis would be a fabricated result,
which is the one thing this project does not do.

Where the real work lives
-------------------------
Published CVEs in unmodified upstream source are evaluated by
`tests/real_cve_suite/`, which does what this file only claimed to:

  * checks out the commit immediately BEFORE the upstream security fix,
  * pre-flights the PoV against the unpatched build, so the gate is known to
    detect the real bug before it may decide anything,
  * verifies each PoV in BOTH directions — it must reproduce on the vulnerable
    commit and stop reproducing on the upstream fix — before the target is
    admitted to the suite,
  * replays that exact input against the rebuilt patched binary,
  * then tries to falsify the resulting patch.

Run it with:

    sh tests/real_cve_suite/setup.sh
    python -m tests.real_cve_suite.run_real_cve

or through the main harness:

    python benchmark.py --suite real_cve --harden
"""

import sys

if __name__ == "__main__":
    print(__doc__)
    sys.exit(1)
