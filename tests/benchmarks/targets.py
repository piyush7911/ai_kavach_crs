"""
AI Kavach CRS — Benchmark target manifest.

Every entry declares exactly how a target is verified. There are three
independent gates and each one is either a real executable command or an
explicit, documented N/A — nothing is assumed to pass.

    build       Compile the PATCHED source with ASan + UBSan (fatal).
    pov         Run the exact input that makes the ORIGINAL binary crash.
                A patch passes only if that input no longer trips a sanitizer.
    regression  Run a BENIGN input and assert the program still behaves.

`pov` is None for targets whose weakness has no deterministic runtime
manifestation on this platform. The reason is recorded in `pov_na_reason`
and is printed verbatim in the reports — a target without a PoV is never
counted as "PoV verified".

Command templates support exactly these placeholders, and no others:
    {src}        absolute path to the patched source file in the workspace
    {srcdir}     directory containing {src}
    {bin}        absolute path the build should produce
    {workspace}  workspace root

`DRVLoop.expand` substitutes those four by literal replacement and deliberately
leaves every other brace alone, so shell brace expansion, awk programs and
`${arr[1]}` survive intact. The consequence worth knowing: an invented
placeholder is NOT an error — it is passed through verbatim and the command
fails later for a confusing reason. The path to the runner scripts is therefore
baked in by the `_pov` / `_regress` helpers below rather than templated.
"""

import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

HARNESS = Path(__file__).parent / "harness"

# Sanitizers are made fatal (-fno-sanitize-recover=all) so that a UBSan
# report is an abort, not a printed warning that leaves the exit code at 0.
SAN_CFLAGS = (
    "-fsanitize=address,undefined -fno-sanitize-recover=all "
    "-fno-omit-frame-pointer -g -O0"
)

SINGLE_FILE_BUILD = f'clang {SAN_CFLAGS} "{{src}}" -o "{{bin}}"'

# LeakSanitizer is absent from APPLE's AddressSanitizer runtime — a binary built
# with /usr/bin/clang answers `detect_leaks=1` with "detect_leaks is not
# supported on this platform". Homebrew LLVM's runtime does support it, on this
# same arm64 host. Measured, not assumed.
#
# This project recorded the blanket claim "LeakSanitizer is unsupported on
# darwin-arm64", which is why CWE-401 had no runtime gate. The toolchain was the
# variable, not the platform. Targets whose weakness IS a leak build with the
# runtime that can observe it; if that toolchain is absent the gate is skipped
# with a written reason rather than silently passing.
_LSAN_CLANG = next(
    (p for p in ("/opt/homebrew/opt/llvm/bin/clang", "/usr/local/opt/llvm/bin/clang")
     if Path(p).exists()),
    None,
)
LEAK_BUILD = (
    f'"{_LSAN_CLANG}" {SAN_CFLAGS} "{{src}}" -o "{{bin}}"'
    if _LSAN_CLANG else SINGLE_FILE_BUILD
)


def _pov_leak(*args: str) -> str:
    """Leak PoV: LeakSanitizer must report nothing on the patched binary."""
    quoted = " ".join(shlex.quote(a) for a in args)
    return f'sh "{HARNESS}/pov_leak.sh" "{{bin}}" {quoted}'.rstrip()


@dataclass
class Target:
    """One benchmark target and its complete verification contract."""

    id: str
    suite: str
    file_path: str
    line_number: int
    cwe_id: str
    description: str
    complexity: str                      # easy | medium | hard | ast-dependent
    build_command: str
    pov_command: Optional[str] = None
    pov_na_reason: str = ""
    regression_command: Optional[str] = None
    regression_na_reason: str = ""
    source_dir: Optional[str] = None     # copy this whole tree into workspace
    # Behavioural contract used by patch hardening:
    #   "preserve" — a memory-safety fix must not change what the program does
    #                for inputs the original handled correctly.
    #   "restrict" — an input-validation fix (injection, traversal) legitimately
    #                NARROWS the accepted input domain. Rejecting inputs the
    #                original accepted is the remediation, not a regression, so
    #                differential testing on arbitrary inputs cannot judge it.
    #                The manifest's regression command is the contract instead.
    behaviour_contract: str = "preserve"
    # Optional hardening check for input-validation fixes: a script that tries
    # bypass variants against the PATCHED build. Re-fuzzing cannot falsify such
    # a fix (there is no crash to find), so without this they go unhardened.
    evasion_command: Optional[str] = None
    # Loop unwind bound for CBMC. A proof is only as strong as this bound, so it
    # is declared per target rather than guessed globally; a target with a
    # harness in tests/benchmarks/cbmc_harnesses/ is formally verified.
    cbmc_unwind: int = 16
    severity: str = "critical"
    source: str = "sanitizer_crash"      # sanitizer_crash | semgrep | side_effect

    def __post_init__(self):
        if self.pov_command is None and not self.pov_na_reason:
            raise ValueError(f"{self.id}: pov_command=None requires pov_na_reason")
        if self.regression_command is None and not self.regression_na_reason:
            raise ValueError(
                f"{self.id}: regression_command=None requires regression_na_reason"
            )


def _pov(*args: str) -> str:
    """Sanitizer PoV: run {bin} on the crashing input, fail if a sanitizer fires."""
    # shlex.quote: an argument containing a double quote would otherwise break
    # the shell wrapping and silently change the input under test.
    quoted = " ".join(shlex.quote(a) for a in args)
    return f'sh "{HARNESS}/pov_run.sh" "{{bin}}" {quoted}'.rstrip()


def _regress(expect: str, *args: str) -> str:
    """Regression: benign input must exit 0, stay sanitizer-clean, and still print `expect`."""
    quoted = " ".join(shlex.quote(a) for a in args)
    return f'sh "{HARNESS}/regress_run.sh" "{{bin}}" {shlex.quote(expect)} {quoted}'.rstrip()


D = "tests/demo_vulns"
J = "tests/benchmarks/juliet_subset"

# ---------------------------------------------------------------------------
# Suite 1 — synthetic memory-safety / logic corpus
#
# Every pov_command below was verified to actually reproduce on the unpatched
# original before being added here; the benchmark re-verifies this at runtime
# and refuses to score a PoV gate it could not first reproduce.
# ---------------------------------------------------------------------------

SYNTHETIC: list[Target] = [
    Target(
        id="SYN-01-MAGIC-BYTES", suite="Synthetic", complexity="hard",
        file_path=f"{D}/01_complex_magic_bytes.c", line_number=27,
        cwe_id="CWE-190", description="Integer overflow in allocation size computation",
        build_command=SINGLE_FILE_BUILD,
        pov_command=None,
        pov_na_reason=(
            "The overflow path is unreachable from the program entrypoint: the "
            "header's version field (0x0100) contains a NUL byte, so no argv "
            "string can satisfy the magic/version/checksum guards."
        ),
        regression_command=_regress("-", "AAAA"),
    ),
    Target(
        id="SYN-02-DEEP-TYPEDEF", suite="Synthetic", complexity="ast-dependent",
        file_path=f"{D}/02_deep_typedef_confusion.c", line_number=24,
        cwe_id="CWE-787", description="Stack buffer overflow via three-level typedef chain",
        build_command=SINGLE_FILE_BUILD,
        pov_command=_pov("A" * 200),
        regression_command=_regress("User crypto initialized", "ABCD"),
    ),
    Target(
        id="SYN-03-INT-OVERFLOW", suite="Synthetic", complexity="medium",
        file_path=f"{D}/03_silent_integer_overflow.c", line_number=11,
        cwe_id="CWE-190", description="Multiplication overflow undersizes heap allocation",
        build_command=SINGLE_FILE_BUILD,
        pov_command=_pov("134217729"),
        regression_command=_regress("Processed event", "5"),
    ),
    Target(
        id="SYN-04-TRUNCATION", suite="Synthetic", complexity="hard",
        file_path=f"{D}/04_extreme_integer_truncation.c", line_number=15,
        cwe_id="CWE-197", description="size_t truncated to uint32 undersizes allocation",
        build_command=SINGLE_FILE_BUILD,
        pov_command=_pov("4294967396"),
        regression_command=_regress("Parsed legacy object", "50"),
    ),
    Target(
        id="SYN-05-DOUBLE-FREE", suite="Synthetic", complexity="medium",
        file_path=f"{D}/05_double_free_conditional.c", line_number=12,
        cwe_id="CWE-415", description="Conditional double free on the error path",
        build_command=SINGLE_FILE_BUILD,
        pov_command=_pov("ERROR"),
        regression_command=_regress("Processing complete", "NORMAL"),
    ),
    Target(
        id="SYN-06-OFF-BY-ONE", suite="Synthetic", complexity="easy",
        file_path=f"{D}/06_off_by_one_loop.c", line_number=8,
        cwe_id="CWE-193", description="Off-by-one heap write in NUL-termination loop",
        build_command=SINGLE_FILE_BUILD,
        pov_command=_pov("AAAA"),
        regression_command=_regress("Copied string: hi", "hi"),
        cbmc_unwind=70,          # loop runs up to the 64-byte harness buffer + 1
    ),
    Target(
        id="SYN-07-FORMAT-STRING", suite="Synthetic", complexity="easy",
        file_path=f"{D}/07_format_string_vuln.c", line_number=7,
        cwe_id="CWE-134", description="Attacker-controlled format string passed to printf",
        build_command=SINGLE_FILE_BUILD,
        pov_command=_pov("%s%s%s%s%s%s%s%s%n"),
        regression_command=_regress("User logged in: alice", "alice"),
    ),
    Target(
        id="SYN-08-PATH-TRAVERSAL", suite="Synthetic", complexity="easy",
        file_path=f"{D}/08_path_traversal.c", line_number=7,
        cwe_id="CWE-22", description="Unsanitised filename concatenated into a base path",
        build_command=SINGLE_FILE_BUILD, source="static",
        behaviour_contract="restrict",
        pov_command=None,
        pov_na_reason=(
            "Exploitation cannot be demonstrated on this host: the hardcoded base "
            "directory /var/www/html/users does not exist, so traversal and benign "
            "inputs both fail to open. Creating it requires root."
        ),
        regression_command=_regress("Failed to open", "profile.txt"),
    ),
    Target(
        id="SYN-09-CMD-INJECTION", suite="Synthetic", complexity="medium",
        file_path=f"{D}/09_command_injection_shell.c", line_number=7,
        cwe_id="CWE-78", description="Unsanitised argument interpolated into system()",
        build_command=f'clang -g -O0 "{{src}}" -o "{{bin}}"',
        source="side_effect",
        behaviour_contract="restrict",
        # Side-effect PoV: the payload creates a marker file if the shell
        # metacharacters are honoured.
        pov_command=f'sh "{HARNESS}/pov_injection.sh" "{{bin}}"',
        regression_command=_regress("Executing: ping -c 1 127.0.0.1", "127.0.0.1"),
    ),
    Target(
        id="SYN-10-NULL-DEREF", suite="Synthetic", complexity="medium",
        file_path=f"{D}/10_null_deref_complex.c", line_number=9,
        cwe_id="CWE-476", description="malloc return value dereferenced without a NULL check",
        build_command=SINGLE_FILE_BUILD, source="static",
        pov_command=None,
        pov_na_reason=(
            "Not reachable: the 800 KB allocation does not fail under normal "
            "conditions, so the missing NULL check never manifests at runtime. "
            "This is a real defect but only statically observable."
        ),
        regression_command=_regress("Context status set to 1", "1"),
    ),
    Target(
        id="SYN-11-OOB-MULTIDIM", suite="Synthetic", complexity="easy",
        file_path=f"{D}/11_oob_multidim_array.c", line_number=8,
        cwe_id="CWE-125", description="Column index unchecked on a 2-D global array",
        build_command=SINGLE_FILE_BUILD,
        pov_command=_pov("0", "1000000"),
        regression_command=_regress("Value: 0", "2", "3"),
    ),
    Target(
        id="SYN-12-INT-UNDERFLOW", suite="Synthetic", complexity="medium",
        file_path=f"{D}/12_integer_underflow.c", line_number=5,
        cwe_id="CWE-191", description="size_t subtraction underflows to a huge length",
        build_command=SINGLE_FILE_BUILD,
        pov_command=_pov("5", "10", "AAAA"),
        regression_command=_regress("Processed chunk", "10", "5", "AAAA"),
        cbmc_unwind=20,
    ),
    Target(
        id="SYN-13-TOCTOU", suite="Synthetic", complexity="hard",
        file_path=f"{D}/13_toctou_race.c", line_number=5,
        cwe_id="CWE-367", description="access() check followed by fopen() (TOCTOU window)",
        build_command=SINGLE_FILE_BUILD, source="static",
        pov_command=None,
        pov_na_reason=(
            "Winning the race requires a concurrent attacker replacing the path "
            "between access() and fopen(); this is not deterministically "
            "reproducible in a single-process benchmark run."
        ),
        regression_command=_regress("-", "/etc/hosts"),
    ),
    Target(
        id="SYN-14-UNINIT-MEM", suite="Synthetic", complexity="ast-dependent",
        file_path=f"{D}/14_uninitialized_memory.c", line_number=9,
        cwe_id="CWE-457", description="Uninitialised struct field used as an array index",
        build_command=SINGLE_FILE_BUILD, source="static",
        pov_command=None,
        pov_na_reason=(
            "Detecting an uninitialised stack read requires MemorySanitizer, "
            "which is Linux/x86-64 only and unavailable on this darwin-arm64 host. "
            "ASan does not model uninitialised memory."
        ),
        regression_command=_regress("-", "1"),
    ),
    Target(
        id="SYN-15-HARDCODED-KEY", suite="Synthetic", complexity="easy",
        file_path=f"{D}/15_hardcoded_key.c", line_number=5,
        cwe_id="CWE-321", description="Hardcoded cryptographic key in source",
        build_command=SINGLE_FILE_BUILD, source="static",
        # A PoV does not have to be a crash. The contract is "exit 0 only when
        # the weakness is absent", and for a hardcoded secret that is decidable:
        # `strings` the built binary for the literal. It fails on the unpatched
        # original and passes only once the value stops being compiled in, so
        # pre-flight validates it like any other PoV.
        #
        # Without this gate nothing in the repair loop tested the actual
        # weakness — build and regression both pass a patch that ignores it, and
        # one duly "validated" at iteration 1 by adding an unrelated NULL check
        # and leaving the key in place. The gate gives the agent the feedback it
        # needs to iterate.
        pov_command=(
            f'sh "{HARNESS}/secret_scan.sh" "{{bin}}" '
            f'{shlex.quote("SUPER_SECRET_AES_KEY_12345")} '
            f'{shlex.quote("Encrypting data")} hello'
        ),
        regression_command=_regress("Encrypting data", "hello"),
        # The program PRINTS the key, so removing the hardcoded literal must
        # change stdout. Holding this to `preserve` demands behavioural
        # equivalence with the vulnerable original, which is unsatisfiable while
        # actually fixing CWE-321 — a correct patch was falsified for exactly
        # this reason ("output changed on benign input '42'").
        #
        # No evasion_command: the only discriminator we have is the one the PoV
        # gate already applies, and re-running it post-hoc would manufacture a
        # hardening pass out of evidence already counted. This target is
        # PoV-proven and honestly reports as NOT HARDENED.
        behaviour_contract="replace",
    ),
    Target(
        id="SYN-16-TYPE-CONFUSION", suite="Synthetic", complexity="hard",
        file_path=f"{D}/16_type_confusion.c", line_number=10,
        cwe_id="CWE-843",
        description=(
            "Union member written as int (uid.id = atoi(raw)) and then read as "
            "char* by the very next statement, dereferencing an integer as a "
            "pointer"
        ),
        build_command=SINGLE_FILE_BUILD,
        pov_command=_pov(),
        # The confusion is created and consumed inside render_user, so the
        # labelled line, the PoV path and the fuzz harness all address the same
        # function and a patch confined to it can succeed. Previously the label
        # pointed at one copy of the bug while the harness attacked another
        # function entirely, and re-fuzzing blamed the agent for a defect
        # outside the scope it was given.
        regression_command=_regress("-", "42"),
    ),
    Target(
        id="SYN-17-MEMORY-LEAK", suite="Synthetic", complexity="easy",
        file_path=f"{D}/17_memory_leak_error_path.c", line_number=9,
        cwe_id="CWE-401", description="Allocation leaked on the early-return error path",
        # Built with the Homebrew LLVM runtime, which ships LeakSanitizer;
        # Apple's does not. See LEAK_BUILD above.
        build_command=LEAK_BUILD, source="static",
        # `-1` takes the error path that returns without freeing log_msg.
        # Verified in all four directions before being trusted: the original
        # leaks on -1 and is clean on 10, and a patch that frees before the early
        # return is clean on both — so the gate discriminates the weakness, not
        # the binary.
        pov_command=_pov_leak("-1") if _LSAN_CLANG else None,
        pov_na_reason=(
            ""
            if _LSAN_CLANG else
            "Leak detection needs a LeakSanitizer-capable runtime. Apple's clang "
            "ships none and no Homebrew LLVM was found at "
            "/opt/homebrew/opt/llvm or /usr/local/opt/llvm, so the leak cannot "
            "be gated at runtime on this host."
        ),
        regression_command=_regress("-", "10"),
    ),
    Target(
        id="SYN-18-AST-DEEP-STRUCT", suite="Synthetic", complexity="ast-dependent",
        file_path=f"{D}/18_ast_deep_struct.c", line_number=13,
        cwe_id="CWE-787", description="memcpy overruns a nested struct member",
        build_command=SINGLE_FILE_BUILD, source="static",
        pov_command=None,
        pov_na_reason=(
            "The 100-byte copy overruns secret_key[64] but stays inside the "
            "enclosing 100-byte UserSession object. ASan tracks allocation "
            "boundaries, not intra-object ones, so it cannot fire here."
        ),
        regression_command=_regress("-"),
    ),
    Target(
        id="SYN-19-AST-MACRO-UAF", suite="Synthetic", complexity="ast-dependent",
        file_path=f"{D}/19_ast_macro_expansion.c", line_number=11,
        cwe_id="CWE-416", description="Use-after-free hidden behind a SAFE_FREE macro",
        build_command=SINGLE_FILE_BUILD, source="static",
        pov_command=None,
        pov_na_reason=(
            "No live use-after-free at runtime: SAFE_FREE nullifies the local "
            "pointer and the following guard short-circuits. The caller's copy "
            "of the pointer dangles, which is a latent defect, not a reproducible "
            "crash."
        ),
        regression_command=_regress("-"),
    ),
    Target(
        id="SYN-20-AST-OPAQUE-PTR", suite="Synthetic", complexity="ast-dependent",
        file_path=f"{D}/20_ast_opaque_pointer.c", line_number=10,
        cwe_id="CWE-457", description="Uninitialised heap buffer behind an opaque handle",
        build_command=SINGLE_FILE_BUILD, source="static",
        pov_command=None,
        pov_na_reason=(
            "Reading the uninitialised heap buffer needs MemorySanitizer "
            "(Linux-only). ASan reports nothing because the read stays inside "
            "the allocation."
        ),
        regression_command=_regress("-"),
    ),
]

# ---------------------------------------------------------------------------
# Suite 2 — NIST SARD Juliet subset
# ---------------------------------------------------------------------------

JULIET: list[Target] = [
    Target(
        id="JULIET-CWE121", suite="NIST Juliet", complexity="medium",
        file_path=f"{J}/CWE121_Stack_Based_Buffer_Overflow/CWE121.c",
        line_number=16, cwe_id="CWE-121",
        description="Stack buffer overrun: memcpy sizeof(struct) into a 16-byte member",
        build_command=SINGLE_FILE_BUILD,
        pov_command=_pov(),
        regression_command=None,
        regression_na_reason=(
            "Juliet 'bad' testcases expose only the vulnerable sink; there is no "
            "benign input path to regress."
        ),
    ),
    Target(
        id="JULIET-CWE416", suite="NIST Juliet", complexity="medium",
        file_path=f"{J}/CWE416_Use_After_Free/CWE416.c",
        line_number=12, cwe_id="CWE-416",
        description="Use-after-free: buffer printed after free()",
        build_command=SINGLE_FILE_BUILD,
        pov_command=_pov(),
        regression_command=None,
        regression_na_reason=(
            "Juliet 'bad' testcases expose only the vulnerable sink; there is no "
            "benign input path to regress."
        ),
    ),
]

# ---------------------------------------------------------------------------
# Suite 3 — real-world repository (cJSON)
#
# These are ACTUAL Semgrep p/security-audit findings, not a CVE. cJSON has no
# confirmed unpatched CVE at these lines and we do not claim one. The value of
# the suite is the verification bar: any patch must compile the whole library
# and keep cJSON's own upstream test suite passing under ASan + UBSan.
# ---------------------------------------------------------------------------

_CJSON_REPO = "benchmark_workspace/cJSON"
_CJSON_BUILD = (
    f'clang {SAN_CFLAGS} -I"{{srcdir}}" '
    f'"{{srcdir}}/cJSON.c" "{{srcdir}}/cJSON_Utils.c" "{{srcdir}}/test.c" -o "{{bin}}"'
)
_CJSON_REGRESS = f'sh "{HARNESS}/regress_run.sh" "{{bin}}" "-"'
_CJSON_POV_NA = (
    "No proof-of-vulnerability exists: this is a static Semgrep finding "
    "(unsafe string-copy API in use), not a reproducible crash, and no "
    "unpatched CVE is confirmed at this location."
)

REAL_WORLD: list[Target] = [
    Target(
        id=f"CJSON-SEMGREP-{line}", suite="Real World (cJSON)", complexity="hard",
        file_path=f"{_CJSON_REPO}/{fname}", line_number=line,
        cwe_id="CWE-676", source="semgrep",
        description=(
            f"Semgrep p/security-audit: {rule} at {fname}:{line} "
            "(unbounded string copy API)"
        ),
        build_command=_CJSON_BUILD,
        pov_command=None, pov_na_reason=_CJSON_POV_NA,
        regression_command=_CJSON_REGRESS,
        source_dir=_CJSON_REPO,
    )
    for fname, line, rule in [
        ("cJSON.c", 461, "insecure-use-string-copy-fn"),
        ("cJSON.c", 976, "insecure-use-string-copy-fn"),
        ("cJSON.c", 1440, "insecure-use-string-copy-fn"),
        ("cJSON.c", 1449, "insecure-use-string-copy-fn"),
        ("cJSON.c", 1458, "insecure-use-string-copy-fn"),
        ("cJSON_Utils.c", 245, "insecure-use-strcat-fn"),
    ]
]



ALL_TARGETS = SYNTHETIC + JULIET + REAL_WORLD


def real_cve_targets() -> list[Target]:
    """
    Published CVEs in unmodified upstream source.

    Imported lazily: tests/real_cve_suite/manifest.py imports Target and
    SAN_CFLAGS from this module, so a top-level import here would be circular.
    Returns [] when the vulnerable trees have not been materialised — run
    `sh tests/real_cve_suite/setup.sh` to create them.
    """
    try:
        from tests.real_cve_suite.manifest import REAL_CVE
        return REAL_CVE
    except Exception:
        return []


def get_suite(name: str) -> list[Target]:
    if name == "real_cve":
        return real_cve_targets()
    if name == "all":
        return ALL_TARGETS + real_cve_targets()
    return {
        "synthetic": SYNTHETIC,
        "juliet": JULIET,
        "real_world": REAL_WORLD,
    }[name]
