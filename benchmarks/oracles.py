"""Target-neutral alias for the language-neutral HTTP oracle engine.

The oracles (run_exploit / Session / differential / metamorphic / idor / data-exposure) speak HTTP,
not any one app or language. They physically live beside the first app they were written against, but
engine code (src/) must import them by their neutral name so no backend hard-codes a benchmark target.
Import from here, not from the app-named module.
"""
from benchmarks.nodegoat.exploit import (  # noqa: F401
    Response, Session, _denied, run_exploit,
)
