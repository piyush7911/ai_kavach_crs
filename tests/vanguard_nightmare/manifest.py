"""
Project Vanguard-0 — vulnerability manifest.

A standalone corpus of four hand-written C targets exercising structural
features that defeat snippet-level reasoning: packed bitfields declared in a
separate header, a use-after-free reached through an aliased global, an
allocation size computed by chained macros, and a custom URI scheme.

These are ORIGINAL synthetic targets, not derived from any public dataset or
CVE. They are evaluated by `run_vanguard.py`, deliberately outside the main
`benchmark.py` harness.

Every PoV below is pre-flighted at run time: the target is compiled unpatched
and the PoV executed against it, and a PoV that does not reproduce is disabled
rather than counted. That check exists because VANGUARD-04's original PoV
(`"{bin}" "rtos://../../../../etc/passwd"`) exited 0 on the unpatched binary —
parse_rtos_uri() returns 0 on every path — so it passed before any patch
existed and proved nothing.
"""

from pathlib import Path
from tests.benchmarks.targets import Target, SAN_CFLAGS

VANGUARD_DIR = Path(__file__).parent
TARGETS_DIR = VANGUARD_DIR / "targets"

VANGUARD_TARGETS = [
    Target(
        id="VANGUARD-01-BITFIELD-OVERFLOW",
        suite="Vanguard Nightmare Suite",
        file_path=str(TARGETS_DIR / "01_bitfield_typedef_overflow.c"),
        line_number=9,
        cwe_id="CWE-122",
        description="Nested Bitfield payload length overflow in packed ChannelPacket header",
        complexity="nightmare",
        build_command=f'cp -r "{VANGUARD_DIR}/headers" "{{workspace}}/" && clang {SAN_CFLAGS} -I"{{workspace}}/headers" "{{src}}" -o "{{bin}}"',
        pov_command='"{bin}" "0x100000"',
        regression_command='"{bin}" "0x10"',
    ),
    Target(
        id="VANGUARD-02-ASYNC-UAF-ALIAS",
        suite="Vanguard Nightmare Suite",
        file_path=str(TARGETS_DIR / "02_async_uaf_alias.c"),
        line_number=25,
        cwe_id="CWE-416",
        description="Async callback use-after-free via aliased global SessionHandle",
        complexity="nightmare",
        build_command=f'cp -r "{VANGUARD_DIR}/headers" "{{workspace}}/" && clang {SAN_CFLAGS} -I"{{workspace}}/headers" "{{src}}" -o "{{bin}}"',
        pov_command='"{bin}" "ERR_INVALID"',
        regression_command='"{bin}" "OK_REQ"',
    ),
    Target(
        id="VANGUARD-03-MACRO-UNDERFLOW",
        suite="Vanguard Nightmare Suite",
        file_path=str(TARGETS_DIR / "03_macro_underflow.c"),
        line_number=10,
        cwe_id="CWE-191",
        # NOTE: this target carries a SECOND defect beyond the labelled CWE-191.
        # `allocate_and_store` never checks that alloc_sz >= MACRO_HDR_LEN +
        # num_bytes, so even with the multiplication overflow fixed (count=1 =>
        # alloc 20) the memcpy at buf+16 of 20 bytes still overflows. A patch
        # that only bounds the multiplication remains exploitable, and with no
        # fuzz harness for this target, adversarial re-fuzzing cannot detect
        # that. Treat a SURVIVED verdict here as weaker than for a harnessed
        # target.
        description="Chained macro allocation size underflow in CALC_ALLOC_SZ",
        complexity="nightmare",
        build_command=f'cp -r "{VANGUARD_DIR}/headers" "{{workspace}}/" && clang {SAN_CFLAGS} -I"{{workspace}}/headers" "{{src}}" -o "{{bin}}"',
        pov_command='"{bin}" "1073741824" "AAAAAAAAAAAAAAAAAAAA"',
        regression_command='"{bin}" "4" "AAAA"',
    ),
    Target(
        id="VANGUARD-04-RTOS-URI-TRAVERSAL",
        suite="Vanguard Nightmare Suite",
        file_path=str(TARGETS_DIR / "04_rtos_uri_traversal.c"),
        line_number=11,
        cwe_id="CWE-22",
        description="RTOS custom URI path traversal with strict behavioral contract",
        complexity="nightmare",
        build_command=f'clang {SAN_CFLAGS} "{{src}}" -o "{{bin}}"',
        # Checks the security property (no file opened outside the storage
        # root), not the exit code — which is 0 whether or not traversal
        # succeeds, and so could never discriminate.
        pov_command=f'sh "{VANGUARD_DIR}/pov_no_traversal.sh" "{{bin}}"',
        regression_command=f'sh "{VANGUARD_DIR}/regress_uri.sh" "{{bin}}"',
        behaviour_contract="restrict",
        evasion_command=f'sh "{VANGUARD_DIR}/evasion_battery.sh" "{{bin}}"',
    ),
]
