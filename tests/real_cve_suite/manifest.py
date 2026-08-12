"""
Real-CVE suite — published vulnerabilities in unmodified upstream source.

Every other corpus in this project is code we wrote. This one is not: each
target is upstream cJSON checked out at the commit immediately **before** the
security fix landed, so the defect is the one that actually shipped.

Run `sh tests/real_cve_suite/setup.sh` to materialise the trees. Targets whose
tree is missing are omitted from the suite rather than reported as failures, so
a fresh checkout degrades to "not evaluated".

Each entry below was validated in both directions before being added — the PoV
reproduces on the vulnerable commit, and the upstream fix resolves it:

    CVE-2019-11835  cJSON_Minify   '/*'    -> heap-buffer-overflow READ cJSON.c:2642
    CVE-2019-11834  parse_string   '"abc'  -> heap-buffer-overflow READ cJSON.c:660
                                   fixed commit a167d9e: parses to null, no crash
    GH-800          parse_object   '{"1":1,' (exact-size, unterminated buffer)
                                   -> heap-buffer-overflow READ
                                   fixed commit 3ef4e4e: parses to null, no crash

Not every entry has a CVE identifier. GH-800 is a real upstream security fix
with no assigned CVE, and is named for the issue rather than given an invented
CVE number.
"""

import shlex
from pathlib import Path

from tests.benchmarks.targets import Target, SAN_CFLAGS, HARNESS

SUITE_DIR = Path(__file__).parent
DRIVERS = SUITE_DIR / "drivers"
TREES = Path("benchmark_workspace/real_cve_trees")


# shlex.quote, not f'"{a}"': JSON payloads contain double quotes, and wrapping
# them in double quotes lets the shell collapse {"a":1} to {a:1} — which parses
# as invalid JSON and silently breaks the regression baseline.
def _pov(*args: str) -> str:
    quoted = " ".join(shlex.quote(a) for a in args)
    return f'sh "{HARNESS}/pov_run.sh" "{{bin}}" {quoted}'.rstrip()


def _regress(expect: str, *args: str) -> str:
    quoted = " ".join(shlex.quote(a) for a in args)
    return (
        f'sh "{HARNESS}/regress_run.sh" "{{bin}}" '
        f'{shlex.quote(expect)} {quoted}'
    ).rstrip()


def _build(driver: str) -> str:
    """Compile the patched library together with the CVE's driver."""
    return (
        f'clang {SAN_CFLAGS} -I"{{srcdir}}" "{{srcdir}}/cJSON.c" '
        f'"{DRIVERS / driver}" -o "{{bin}}"'
    )


_CANDIDATES = [
    dict(
        id="CVE-2019-11835-CJSON-MINIFY",
        tree="cjson_minify_oob",
        line_number=2642,
        cwe_id="CWE-125",
        description=(
            "CVE-2019-11835: out-of-bounds read in cJSON_Minify. On an "
            "unterminated /* comment the scan loop halts at the NUL terminator "
            "and the following `json += 2` steps past it, so the enclosing "
            "`while (*json)` reads beyond the buffer. Upstream cJSON v1.7.10; "
            "fixed in 1.7.11 by rewriting the comment skipping."
        ),
        driver="cjson_minify_driver.c",
        pov=_pov("/*"),
        regression=_regress('minified: {"a":1}', '{ "a" : 1 }'),
    ),
    dict(
        id="CVE-2019-11834-CJSON-PARSE-STRING",
        tree="cjson_parse_string_oob",
        line_number=660,
        cwe_id="CWE-125",
        description=(
            "CVE-2019-11834: heap over-read in parse_string. The loop tested "
            "`*input_end != '\"'` BEFORE checking the offset against the buffer "
            "length, dereferencing one byte past the allocation on an "
            "unterminated string literal. Upstream cJSON at commit b537ca7; "
            "fixed in a167d9e by reordering the two conditions."
        ),
        driver="cjson_parse_driver.c",
        pov=_pov('"abc'),
        regression=_regress("parsed: ok", '{"a":1}'),
    ),
    dict(
        id="GH800-CJSON-PARSE-OBJECT-OOB",
        tree="cjson_parse_object_oob",
        line_number=1660,
        cwe_id="CWE-125",
        description=(
            "Heap over-read in parse_object: after consuming a comma the parser "
            "did not check that anything follows it, so a trailing comma in a "
            "length-bounded buffer reads past the allocation. Upstream cJSON at "
            "commit 826cd6f; fixed by 3ef4e4e, which added the missing "
            "`cannot_access_at_index(input_buffer, 1)` guard. "
            "NOTE: no CVE identifier is assigned to this one — the upstream "
            "commit references GitHub issue #800. It is a real published "
            "security fix, not a catalogued CVE, and is named accordingly."
        ),
        driver="cjson_parselen_driver.c",
        pov=_pov('{"1":1,'),
        regression=_regress("parsed: ok", '{"a":1}'),
    ),
]


REAL_CVE: list[Target] = []

for _c in _CANDIDATES:
    _tree = TREES / _c["tree"]
    if not (_tree / "cJSON.c").exists():
        continue                      # tree not materialised; see setup.sh
    REAL_CVE.append(Target(
        id=_c["id"],
        suite="Real CVE (published)",
        file_path=str(_tree / "cJSON.c"),
        line_number=_c["line_number"],
        cwe_id=_c["cwe_id"],
        complexity="hard",
        description=_c["description"],
        source_dir=str(_tree),
        build_command=_build(_c["driver"]),
        pov_command=_c["pov"],
        regression_command=_c["regression"],
        source="published_cve",
    ))


def missing_trees() -> list[str]:
    """Candidates whose source tree has not been materialised."""
    return [
        c["id"] for c in _CANDIDATES
        if not (TREES / c["tree"] / "cJSON.c").exists()
    ]
