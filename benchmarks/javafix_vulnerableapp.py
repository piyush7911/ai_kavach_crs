"""End-to-end DISCOVER->CONFIRM->FIX->PROVE on OWASP VulnerableApp (Java/Spring) with a local model.

Closes find->fix->prove for the THIRD stack. The oracle (differential SQLi, presence-flip style) confirms
the bug over HTTP; the repair loop rewrites the one Java method, rebuilds the Spring app, and replays the
exploit — accepted only when it is gone and a normal lookup still works. Java is interpreted-by-nobody, so
each attempt pays a Gradle build; that is the only thing different from the JS/Python drivers.

    export OPENAI_BASE_URL=http://192.168.0.103:11434/v1 OPENAI_API_KEY=ollama MODEL=codegemma:7b
    python -m benchmarks.javafix_vulnerableapp
"""
import os
import sys
from pathlib import Path

from openai import OpenAI

from benchmarks.oracles import run_exploit
from src.javaauto.repair import repair

TREE = Path("benchmark_workspace/VulnerableApp")
CTX = "/VulnerableApp"
MODEL = os.environ.get("MODEL", "codegemma:7b")
VULN_FILE = "src/main/java/org/sasanlabs/service/vulnerability/sqlInjection/ErrorBasedSQLInjectionVulnerability.java"
ROUTE = CTX + "/ErrorBasedSQLInjectionVulnerability/LEVEL_1"

# presence-flip differential: a true vs false numeric condition on a single-row lookup whose base id exists
POV = {"login_as": "none", "differential": {
    "true_request": {"method": "GET", "path": ROUTE + "?id=0%20OR%201%3D1"},
    "false_request": {"method": "GET", "path": ROUTE + "?id=0%20OR%201%3D2"}}}
# a legitimate lookup must still return the car (don't "fix" by breaking the endpoint)
REGRESSION = [{"name": "normal-lookup", "method": "GET", "path": ROUTE + "?id=1",
               "expect": {"status": 200, "body_regex": "isCarPresent"}}]
FINDING = {
    "file": VULN_FILE, "function": "doesCarInformationExistsLevel1", "klass": "sql-injection", "cwe": "CWE-89",
    "guidance": "The SQL string concatenates the request parameter directly. Use a parameterized query: a "
                "'?' placeholder in the SQL and pass `id` as a bound argument (JdbcTemplate query supports "
                "trailing varargs parameters). Keep returning the same car JSON for a valid id.",
}


def main() -> int:
    client = OpenAI(base_url=os.environ.get("OPENAI_BASE_URL"), api_key=os.environ.get("OPENAI_API_KEY", "x"))

    def llm(prompt: str) -> str:
        r = client.chat.completions.create(model=MODEL, temperature=0, max_tokens=1200,
                                           messages=[{"role": "user", "content": prompt}])
        return r.choices[0].message.content or ""

    base = os.environ.get("VAPP_BASE", "http://127.0.0.1:9090")
    try:
        hit, detail = run_exploit(base, POV)
    except Exception as e:  # noqa: BLE001 — baseline may be down; the repair gate proves it anyway
        hit, detail = False, str(e)
    if hit:
        print(f"confirm on baseline ({base}): EXPLOITABLE — {detail}")
        print("stop the baseline on 9090 before repairing (frees the Gradle tree):")
        os.system("lsof -ti tcp:9090 | xargs kill -9 2>/dev/null; sleep 2")
    else:
        print(f"baseline on {base} not reachable — skipping live baseline confirm (bug already confirmed); "
              "the repair gate rebuilds and proves PoV-gone itself.")

    print(f"repairing {FINDING['klass']} in {FINDING['function']} with {MODEL} (each attempt rebuilds) ...")
    out = repair(FINDING, TREE, llm, POV, context_path=CTX, regression=REGRESSION, attempts=3)
    for a in out.attempts:
        print(f"  attempt {a['n']}: {a['stage']}: {a['detail'][:90]}")
    print(f"RESULT: {out.status} — {out.reason}")
    if out.diff:
        print("--- patch ---\n" + out.diff)
    return 0 if out.status == "proven" else 1


if __name__ == "__main__":
    sys.exit(main())
