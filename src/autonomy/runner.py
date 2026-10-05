"""
Autonomous mode — stage orchestration.

    python -m src.main --target <repo> --mode auto [--build-cmd CMD] [--events PATH]

Stages and what each one records:

  ingest     snapshot the repo into the run directory (sha256), census, build plan
  scan       Semgrep findings, each mapped to its enclosing function
  harness    a fuzz-harness candidate per flagged function: template first, LLM
             draft second, each with the caller-derived preconditions it honours
  build      compile the snapshot + harness with sanitizers, under the sandbox
  reach      a coverage build must EXECUTE the flagged function, else the finding
             is "not_reached" (a harness that never gets there proves nothing)
  fuzz       time-boxed libFuzzer campaign (only with --fuzz-seconds > 0)
  triage     reproduce each crash, keep those inside the repository, cluster
  repair     agents patch; gates: policy, build, PoV (the fuzzer's own input),
             behaviour replay (needs --repair and a model)
  harden     re-fuzz the patched build + differential against the original

Rule: nothing is skipped silently. Every finding ends in `evidence.json` with a
status and a reason.
"""

import json
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from src.autonomy import build as build_mod
from src.autonomy import campaign, execute
from src.autonomy import ingest as ingest_mod
from src.autonomy.codeindex import CodeIndex
from src.autonomy.harness import HarnessUnavailable, draft_with_llm, synthesize
from src.events import EventSink, NULL_SINK

logger = logging.getLogger(__name__)

LLM_BUILD_ATTEMPTS = 3
_PRELUDE = "#include <stdbool.h>\n#include <stddef.h>\n#include <stdint.h>\n#include <stdlib.h>\n#include <string.h>\n"


_RENAME = "#define LLVMFuzzerTestOneInput kavach_model_harness\n"
_WRAPPER = r"""
#undef LLVMFuzzerTestOneInput
/* The fuzzer's buffer is not NUL-terminated. Models routinely pass it to string APIs, which
   makes the harness itself over-read. Hand the drafted harness a copy with a terminator
   after the last byte; `size` still excludes it, so byte-oriented code is unaffected. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    uint8_t *copy = (uint8_t *)malloc(size + 1);
    if (!copy) return 0;
    if (size) memcpy(copy, data, size);
    copy[size] = 0;
    int rc = kavach_model_harness(copy, size);
    free(copy);
    return rc;
}
"""


def with_prelude(source: str, terminate: bool = False) -> str:
    """
    Standard headers every harness needs; adding them is not a decision for the model.
    `terminate` (model-drafted harnesses only) also guarantees a NUL after the input.
    """
    body = source if source.startswith(_PRELUDE) else _PRELUDE + source
    if terminate and "kavach_model_harness" not in body:
        body = _PRELUDE + _RENAME + source + _WRAPPER
    return body


NOT_EXECUTED_REASON = ("harness written but not compiled or run: execution is off "
                       "(pass --fuzz-seconds N to build, judge reach and fuzz)")


@dataclass
class FindingOutcome:
    id: str
    file: str
    line: int
    rule: str
    function: str = ""
    # unproven | harness_ready | build_failed | not_reached | no_crash | crash_confirmed
    # | crash_unattributed | proven | patched_unhardened | falsified | unresolved
    status: str = "unproven"
    reason: str = ""
    harness: str = ""                 # path, relative to the run dir
    harness_method: str = ""
    call_path: list[str] = field(default_factory=list)
    preconditions: list[str] = field(default_factory=list)
    harness_attempts: int = 1
    build: dict = field(default_factory=dict)
    reach: dict = field(default_factory=dict)
    fuzz: dict = field(default_factory=dict)
    crash: dict = field(default_factory=dict)
    repair: dict = field(default_factory=dict)


@dataclass
class AutoResult:
    run_dir: Path
    snapshot_sha256: str = ""
    build_plan: dict = field(default_factory=dict)
    census: dict = field(default_factory=dict)
    findings: list[FindingOutcome] = field(default_factory=list)
    error: str = ""
    seconds: float = 0.0

    def to_dict(self) -> dict:
        return {
            "run_dir": str(self.run_dir), "snapshot_sha256": self.snapshot_sha256,
            "build_plan": self.build_plan, "census": self.census, "error": self.error,
            "seconds": self.seconds,
            "findings": [f.__dict__ for f in self.findings],
            "summary": {
                "findings": len(self.findings),
                "by_status": {st: sum(1 for f in self.findings if f.status == st)
                              for st in sorted({f.status for f in self.findings})},
                "harness_ready": sum(1 for f in self.findings if f.status == "harness_ready"),
                "unproven": sum(1 for f in self.findings if f.status == "unproven"),
                "crashes_confirmed": sum(1 for f in self.findings if f.crash),
                "proven": sum(1 for f in self.findings if f.status == "proven"),
            },
        }


class AutoRunner:
    def __init__(self, run_dir: Path, events: EventSink = NULL_SINK, llm=None,
                 semgrep_rules: str = "p/security-audit", max_functions: int = 5,
                 fuzz_seconds: int = 0, repair: bool = False, orchestrator=None,
                 surface: int = 0):
        self.surface = surface                  # also fuzz up to N public input-parsing functions
        self.run_dir = Path(run_dir).resolve()
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.events = events
        self.llm = llm
        self.semgrep_rules = semgrep_rules
        self.max_functions = max_functions
        self.fuzz_seconds = fuzz_seconds
        self.repair = repair
        self.orchestrator = orchestrator
        self._tools = None
        self.index_for_retry = None

    def run(self, target: str, build_cmd: str = "") -> AutoResult:
        started = time.time()
        result = AutoResult(run_dir=self.run_dir)
        ev = self.events
        ev.emit("run_start", stage="auto", status="info", message=f"auto mode on {target}")
        try:
            self._run(target, build_cmd, result)
        except ingest_mod.IngestError as e:
            result.error = str(e)
            ev.emit("stage_done", stage="ingest", status="fail", message=str(e))
        except Exception as e:                       # recorded, never swallowed
            result.error = f"{type(e).__name__}: {e}"
            logger.exception("auto mode failed")
            ev.emit("stage_done", stage="auto", status="fail", message=result.error)
        result.seconds = round(time.time() - started, 2)
        (self.run_dir / "evidence.json").write_text(json.dumps(result.to_dict(), indent=2))
        ev.emit("run_done", stage="run", status="fail" if result.error else "ok",
                message=result.error or "evidence written", **result.to_dict()["summary"])
        return result

    def _run(self, target: str, build_cmd: str, result: AutoResult) -> None:
        ev = self.events

        ev.emit("stage_start", stage="ingest", status="info", message="snapshot + census")
        snap = ingest_mod.ingest(target, self.run_dir, build_cmd)
        result.snapshot_sha256 = snap.sha256
        result.census = snap.census.to_dict()
        result.build_plan = snap.plan.to_dict()
        ev.emit("stage_done", stage="ingest", status="ok",
                message=f"{snap.census.c_files} C files, build: {snap.plan.kind}",
                sha256=snap.sha256, build=snap.plan.kind)

        ev.emit("stage_start", stage="scan", status="info", message="static scan")
        from src.analysis_engine.semgrep_runner import SemgrepRunner
        findings = SemgrepRunner(rules=self.semgrep_rules).scan(str(snap.root))
        index = CodeIndex(snap.root, snap.plan.sources)
        ev.emit("stage_done", stage="scan", status="ok",
                message=f"{len(findings)} finding(s)", findings=len(findings))

        seen_functions = set()
        harness_dir = self.run_dir / "harnesses"
        harness_dir.mkdir(exist_ok=True)
        for n, f in enumerate(findings, 1):
            rel = self._relative(f.file_path, snap.root)
            out = FindingOutcome(id=f"AUTO-{n:03d}", file=rel, line=f.start_line, rule=f.rule_id)
            result.findings.append(out)
            fn = index.function_at(rel, f.start_line) if rel else None
            if fn is None:
                out.reason = "finding is not inside a C function definition"
                continue
            out.function = fn.name
            if rel not in snap.plan.library_sources:
                out.reason = "finding is in a test, tool or port file, not the library"
                continue
            if fn.name in seen_functions:
                out.reason = "same function as an earlier finding"
                continue
            if len(seen_functions) >= self.max_functions:
                out.reason = f"function budget ({self.max_functions}) reached"
                continue
            seen_functions.add(fn.name)
            self._harness_one(out, fn, index, snap, harness_dir)

        # The static scan only names code that LOOKS risky. A library's own input
        # parsers are where untrusted bytes first arrive, so they are fuzzed
        # directly whether or not a rule flagged them.
        if self.surface > 0:
            for fn in self._public_surface(index, snap, seen_functions)[: self.surface]:
                seen_functions.add(fn.name)
                out = FindingOutcome(id=f"SURF-{len(result.findings) + 1:03d}", file=fn.file,
                                     line=fn.start_line, rule="public-entry-point", function=fn.name)
                result.findings.append(out)
                self._harness_one(out, fn, index, snap, harness_dir)

    # Names of functions that take untrusted input. A heuristic for ORDERING the
    # surface only: every candidate still has to get a fair harness and be reached.
    _INPUT_FN = re.compile(r"(pars|decod|read|load|deseri|unpack|inflat|decompress|scan|import|"
                           r"token|lex|from_|input|open|uncompress|minif|sanit|process|handle|eval|compile|match)", re.I)

    def _public_surface(self, index, snap, already: set) -> list:
        lib = set(snap.plan.library_sources)
        cands = [f for funcs in index.functions.values() for f in funcs
                 if not f.is_static and f.file in lib and f.name not in already
                 and f.params and self._INPUT_FN.search(f.name)]
        # fewest parameters first: simplest to drive from raw bytes
        return sorted(cands, key=lambda f: (len(f.params), f.name))

    def _harness_one(self, out: FindingOutcome, fn, index, snap, harness_dir: Path) -> None:
        ev = self.events
        out.function = fn.name
        ev.emit("stage_start", stage="harness", status="info", message=fn.name, id=out.id)
        try:
            candidates = synthesize(index, fn, llm=self.llm)
        except HarnessUnavailable as e:
            out.reason = f"no fair harness: {e}"
            ev.emit("stage_done", stage="harness", status="fail", message=out.reason, id=out.id)
            return
        h = candidates[0]
        if h.method == "llm":
            try:
                h.source = draft_with_llm(index, h, self.llm)
            except Exception as e:
                out.reason = f"harness draft failed: {type(e).__name__}: {e}"
                return
        path = harness_dir / f"{out.id}_{fn.name}.c"
        path.write_text(with_prelude(h.source, terminate=h.method == "llm"))
        self.index_for_retry = index
        out.harness = str(path.relative_to(self.run_dir))
        out.harness_method = h.method
        out.call_path = h.call_path
        out.preconditions = h.notes
        out.status = "harness_ready"
        out.reason = NOT_EXECUTED_REASON
        ev.emit("stage_done", stage="harness", status="ok",
                message=f"{fn.name}: {h.method} harness", id=out.id)
        if self.fuzz_seconds > 0:
            self._prove(out, h, path, snap, fn)

    @staticmethod
    def _relative(path: str, root: Path) -> str:
        p = Path(path)
        try:
            return (p if p.is_absolute() else (root / p)).resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            # Semgrep reports paths relative to its cwd; try by suffix.
            for cand in root.rglob(p.name):
                if cand.as_posix().endswith(p.as_posix().lstrip("./")):
                    return cand.relative_to(root).as_posix()
            return ""

    # -- build, reach, fuzz, triage, repair ---------------------------------------------------

    def _prove(self, out: FindingOutcome, h, harness_path: Path, snap, fn) -> None:
        """Take one harnessed finding as far as it will go. Every exit writes a status and reason."""
        ev = self.events
        execute.default_to_required()
        work = self.run_dir / "work" / out.id
        work.mkdir(parents=True, exist_ok=True)
        try:
            clang = build_mod.fuzz_clang()
        except build_mod.BuildError as e:
            out.status, out.reason = "build_failed", str(e)
            return

        script = build_mod.write_script(
            self.run_dir / "build" / f"{out.id}_build.sh",
            build_mod.render_script(clang=clang, sources=snap.plan.library_sources or snap.plan.sources,
                                    include_dirs=snap.plan.include_dirs, defines=snap.plan.defines,
                                    harness=harness_path.resolve(), target_file=out.file))

        ev.emit("stage_start", stage="build", status="info", message=fn.name, id=out.id)
        orig = build_mod.build(script, snap.root, work / "bin" / "original", work)
        # A model-drafted harness usually needs a round or two with the compiler.
        # Each retry shows it the real error; the number of attempts is recorded.
        attempts = 1
        while not orig.ok and h.method == "llm" and self.llm is not None and attempts < LLM_BUILD_ATTEMPTS:
            attempts += 1
            ev.emit("stage_progress", stage="build", status="info",
                    message=f"redrafting the harness (attempt {attempts}) after: {orig.error[-120:]}", id=out.id)
            try:
                h.source = draft_with_llm(self.index_for_retry, h, self.llm, compile_error=orig.error)
            except Exception as e:
                break
            harness_path.write_text(with_prelude(h.source, terminate=True))
            orig = build_mod.build(script, snap.root, work / "bin" / "original", work)
        out.harness_attempts = attempts
        out.build = orig.to_dict()
        if not orig.ok:
            out.status, out.reason = "build_failed", orig.error
            ev.emit("stage_done", stage="build", status="fail", message=orig.error[:160], id=out.id)
            return
        ev.emit("stage_done", stage="build", status="ok",
                message=f"built in {orig.seconds}s ({len(orig.skipped_files)} file(s) skipped)", id=out.id)

        seeds = work / "seeds"
        campaign.write_seeds(seeds, h.seeds, extra_dirs=[snap.root])

        # Reach: the flagged function must actually execute under this harness. A
        # model-drafted harness that crashes BEFORE reaching it is the harness's bug,
        # so the sanitizer report goes back to the model for a redraft.
        ev.emit("stage_start", stage="reach", status="info", message=fn.name, id=out.id)
        while True:
            cov = build_mod.build(script, snap.root, work / "bin" / "coverage", work,
                                  env={"KAVACH_COVERAGE": "1"})
            if cov.ok:
                if self._tools is None:
                    self._tools = campaign.llvm_tools(clang) or False
                reach = campaign.reach_check(cov.binary, fn.name, work, seeds, self._tools or None)
            else:
                reach = campaign.ReachResult(False, judged=False,
                                             detail="the coverage build failed: " + cov.error[:160])
            harness_bug = reach.crashed and not reach.reached
            if not (harness_bug and h.method == "llm" and self.llm is not None
                    and attempts < LLM_BUILD_ATTEMPTS):
                break
            attempts += 1
            ev.emit("stage_progress", stage="reach", status="info",
                    message=f"harness crashed before reaching {fn.name}; redrafting (attempt {attempts})", id=out.id)
            try:
                h.source = draft_with_llm(
                    self.index_for_retry, h, self.llm,
                    compile_error=f"The harness crashed before the flagged function {fn.name} ran, "
                                  f"so the crash is in the harness. Sanitizer report:\n{reach.output_tail}")
            except Exception:
                break
            harness_path.write_text(with_prelude(h.source, terminate=True))
            rebuilt = build_mod.build(script, snap.root, work / "bin" / "original", work)
            if not rebuilt.ok:
                out.status, out.reason = "build_failed", rebuilt.error
                out.harness_attempts = attempts
                return
            orig = rebuilt
        out.harness_attempts = attempts
        out.reach = reach.to_dict()
        if reach.judged and not reach.reached:
            out.status, out.reason = "not_reached", reach.detail
            ev.emit("stage_done", stage="reach", status="fail", message=reach.detail, id=out.id)
            return
        ev.emit("stage_done", stage="reach", status="ok" if reach.reached else "info",
                message=reach.detail, id=out.id)
        # A crash during the reach check is already a finding; an unjudged reach is
        # recorded but does not stop the campaign (the stack decides attribution).

        ev.emit("stage_start", stage="fuzz", status="info", message=f"{self.fuzz_seconds}s", id=out.id)
        fz = campaign.fuzz(orig.binary, work, self.fuzz_seconds, seeds)
        out.fuzz = fz.to_dict()
        crashes = list(fz.crashes) + ([Path(reach.crash_input)] if reach.crash_input else [])
        if not fz.ran:
            out.status, out.reason = "unproven", f"the fuzzer did not run: {fz.note}"
            ev.emit("stage_done", stage="fuzz", status="fail", message=out.reason, id=out.id)
            return
        ev.emit("stage_done", stage="fuzz", status="ok",
                message=f"{fz.runs} runs, {len(crashes)} crash file(s)", id=out.id)
        if not crashes:
            note = "" if reach.reached else " (reach was not judged, so this is weaker)"
            out.status = "no_crash"
            out.reason = (f"{fz.runs} runs in {fz.seconds}s with {fz.coverage} coverage points found "
                          f"no crash{note}; this is absence of evidence, not a proof of safety")
            return

        from src.analysis_engine.crash_triage import CrashTriage
        triage = CrashTriage(str(work / "triage"), source_root=str(snap.root))
        clusters = triage.triage(str(orig.binary), [str(c) for c in crashes])
        reports = triage.to_vulnerability_reports(clusters)
        if not reports:
            out.status = "crash_unattributed"
            out.reason = "crash files did not reproduce under triage, or no frame lies in the repository"
            return
        vuln = reports[0]
        out.crash = {"class": vuln.description, "file": vuln.file_path, "line": vuln.line_number,
                     "cwe": vuln.cwe_id, "severity": vuln.severity, "clusters": len(reports),
                     "input": str(crashes[0])}
        out.status = "crash_confirmed"
        out.reason = "the fuzzer's own input reproduces a sanitizer error; no repair attempted"
        ev.emit("finding", stage="triage", status="info", message=vuln.description[:160], id=out.id)

        if not self.repair:
            return
        if self.orchestrator is None:
            out.reason += " (repair requested but no model client was configured)"
            return
        from src.autonomy import repair as repair_mod
        corpus = work / "corpus"
        golden = work / "golden.tsv"
        inputs = [p for p in [*seeds.glob("*"), *corpus.glob("*")] if p.is_file()]
        campaign.write_golden(campaign.capture_golden(orig.binary, inputs, work), golden)
        check = campaign.write_replay_check(work / "replay_check.sh")
        outcome = repair_mod.repair(
            orchestrator=self.orchestrator, extractor=self.orchestrator.context_extractor,
            vuln=vuln, snap_root=snap.root, script=script, original_bin=orig.binary,
            crash_input=crashes[0], replay_check=check, golden=golden, work=work,
            seed_dir=seeds, corpus_dir=corpus, events=ev,
            crash_inputs=[Path(p) for p in clusters[0].inputs])
        out.repair = outcome.to_dict()
        out.status, out.reason = outcome.status, outcome.reason
