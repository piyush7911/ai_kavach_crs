"""
AI Kavach CRS — CASR triage (SUPERSEDED).

This module required `casr-san`/`casr-cluster` on PATH and, when they were
absent, fell back to code whose own comments described it as mocked. It has
been replaced by `src.analysis_engine.crash_triage.CrashTriage`, which:

  * works with or without CASR (using CASR automatically when it is installed),
  * actually replays each crash input and parses the sanitizer report,
  * deduplicates by root cause using the crash class plus target-only stack
    frames, and
  * drops inputs that do not reproduce instead of reporting them as findings.

Import the new class instead:

    from src.analysis_engine.crash_triage import CrashTriage

`CasrTriage` is kept as a thin alias so older call sites keep working.
"""

import warnings

from src.analysis_engine.crash_triage import CrashTriage, CrashCluster, CrashSignature

__all__ = ["CasrTriage", "CrashTriage", "CrashCluster", "CrashSignature"]


class CasrTriage(CrashTriage):
    """Deprecated alias for :class:`CrashTriage`."""

    def __init__(self, *args, **kwargs):
        warnings.warn(
            "CasrTriage is superseded by CrashTriage "
            "(src.analysis_engine.crash_triage); it now delegates to it.",
            DeprecationWarning,
            stacklevel=2,
        )
        super().__init__(*args, **kwargs)
