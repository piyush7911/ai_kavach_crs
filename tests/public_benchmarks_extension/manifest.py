"""
Extension suite — CVE-*inspired* synthetic reproductions.

**Provenance, stated plainly.** Neither target is the artifact its subject
matter suggests:

  * `synth_tiff_crop_oob.c` is a ~50-line hand-written program that reproduces
    the *shape* of the LibTIFF crop-box out-of-bounds bug (CVE-2016-5321). It
    is **not** LibTIFF source and **not** that CVE. Patching it says nothing
    about whether the system could fix the real LibTIFF.
  * `synth_service_stack_overflow.c` is a ~30-line `strcpy` overflow in the
    style of a DARPA CGC service. It is **not** the CGC CADET_00001 challenge
    binary and was not taken from the CGC corpus.

They were previously named `CVE-2016-5321-LIBTIFF` and `CGC-CADET-00001` and
reported under a "Historical CVE Dataset" / "DARPA CGC MultiOS" heading, which
claimed provenance the files do not have. The bugs are genuine; the pedigree
was not. Renamed so no report can imply otherwise.

Evaluating against the real datasets remains open work — it requires the actual
LibTIFF tree at the vulnerable commit and the CGC binaries, neither of which is
vendored here.
"""

from pathlib import Path

from tests.benchmarks.targets import Target, SAN_CFLAGS

EXTENSION_DIR = Path(__file__).parent

PUBLIC_EXTENSION_TARGETS = [
    Target(
        id="SYNTH-TIFF-CROP-OOB",
        suite="CVE-inspired synthetic",
        file_path=str(EXTENSION_DIR / "historical_cve" / "synth_tiff_crop_oob.c"),
        line_number=18,
        cwe_id="CWE-125",
        description=(
            "Crop-box out-of-bounds read: the copy loop indexes the source image "
            "by the requested box dimensions without checking them against the "
            "image's own width/height. Modelled on the shape of CVE-2016-5321 "
            "(LibTIFF); NOT LibTIFF code and NOT that CVE."
        ),
        complexity="hard",
        build_command=f'clang {SAN_CFLAGS} "{{src}}" -o "{{bin}}"',
        pov_command='"{bin}" "20" "20"',
        regression_command='"{bin}" "5" "5"',
        # The remediation validates the crop box against the image's real
        # extent, which necessarily REJECTS dimensions the original accepted
        # (e.g. 16x2 on a 10x10 image stayed in bounds only by accident).
        # Behaviour-equivalence is therefore the wrong contract; hardening for
        # this target comes from adversarial re-fuzzing instead, using the
        # harness in fuzz_harnesses/.
        behaviour_contract="restrict",
    ),
    Target(
        id="SYNTH-SERVICE-STACK-OVERFLOW",
        suite="CVE-inspired synthetic",
        file_path=str(EXTENSION_DIR / "cgc_multios" / "synth_service_stack_overflow.c"),
        line_number=14,
        cwe_id="CWE-121",
        description=(
            "Unbounded strcpy of attacker input into a fixed 64-byte packet body, "
            "overflowing the enclosing stack struct. Written in the style of a "
            "DARPA CGC service; NOT the CGC CADET_00001 challenge binary."
        ),
        complexity="medium",
        build_command=f'clang {SAN_CFLAGS} "{{src}}" -o "{{bin}}"',
        pov_command='"{bin}" "' + "A" * 100 + '"',
        regression_command='"{bin}" "HELLO"',
    ),
]
