# PLAN.md --- Agentic Web Application Security Testing

## Stage 1: Find and Prove Vulnerabilities

**Status:** Stage-1 master plan\
**Primary objective:** Find web-application security vulnerabilities and
prove that they exist.\
**Explicit non-goal:** Automatic patching/remediation. Patching is a
future Stage 2.

------------------------------------------------------------------------

# 1. Product Definition

The system accepts:

1.  A source-code repository for a web application.
2.  An authorized running application endpoint.
3.  Optional authorized test credentials/session material.
4.  Optional application metadata such as OpenAPI/GraphQL
    specifications.

The system must discover security vulnerabilities using both source-code
and runtime evidence.

The central invariant is:

> **No evidence-backed proof = no confirmed vulnerability.**

A scanner warning, LLM hypothesis, static-analysis result, or suspicious
response is only a **candidate** until the system validates it.

## Stage-1 output

A confirmed finding should contain:

-   vulnerability type;
-   severity;
-   endpoint/resource;
-   source location where available;
-   root cause;
-   reproducible test steps;
-   raw evidence references;
-   proof/validation reasoning;
-   CWE/WSTG/ASVS classification where applicable.

## Explicitly out of scope

Do not build:

-   automatic source patching;
-   PR generation;
-   remediation;
-   automatic deployment;
-   autonomous persistence;
-   stealth/evasion;
-   credential theft;
-   malware behavior.

Stage 1 ends at:

``` text
FIND
  ->
TEST
  ->
PROVE
  ->
REPORT
```

------------------------------------------------------------------------

# 2. Core Architecture Decision

## 2.1 Agent framework

Use:

> **LangGraph as the primary workflow/orchestration framework.**

Use:

> **Pydantic/Pydantic models for all agent, tool, state, evidence,
> hypothesis, and finding contracts.**

Use:

> **Our own security engine for source analysis, security graph
> construction, tool execution, evidence handling, validation, and
> finding management.**

Use LangChain components selectively where useful for
model/tool/retrieval integrations, but do not make LangChain the domain
architecture.

## 2.2 Why LangGraph

The workload is a durable stateful investigation:

``` text
INTAKE
  ↓
RECON
  ↓
SOURCE ANALYSIS
  ↓
SECURITY GRAPH
  ↓
CANDIDATES
  ↓
HYPOTHESIS
  ↓
TEST PLAN
  ↓
EXECUTION
  ↓
EVIDENCE
  ↓
VALIDATION
  ↓
CONFIRMED / REJECTED
```

This is better represented as a graph/state machine than as a group of
conversational agents.

Required capabilities:

-   explicit state;
-   branching;
-   bounded loops;
-   retries;
-   checkpoints;
-   durable execution;
-   pause/resume;
-   typed state;
-   validation gates;
-   observability;
-   deterministic transitions.

## 2.3 Do not make everything an LLM agent

Deterministic components should remain deterministic.

### Mostly deterministic

-   repository intake;
-   language detection;
-   framework detection;
-   AST parsing;
-   route extraction;
-   Semgrep;
-   CodeQL where appropriate;
-   ZAP;
-   Nuclei;
-   browser/HTTP mechanics;
-   security graph construction;
-   target scope enforcement;
-   budgets;
-   evidence storage;
-   deduplication.

### LLM reasoning

Initially only:

1.  Source/security-context reasoning.
2.  Vulnerability hypothesis generation.
3.  Test planning.
4.  Runtime observation interpretation.
5.  Proof validation.

This reduces cost and increases reproducibility.

------------------------------------------------------------------------

# 3. Recommended Technology Stack

``` text
Python
FastAPI
LangGraph
Pydantic
PostgreSQL
Object storage
Docker
vLLM
8B-class local model
Playwright
HTTPX
Semgrep
CodeQL where appropriate
OWASP ZAP
Nuclei
tree-sitter
ast-grep
```

Suggested responsibilities:

  Technology       Role
  ---------------- --------------------------------------------------
  Python           Main implementation language
  FastAPI          API/control plane
  LangGraph        Agent/workflow orchestration
  Pydantic         Strongly typed contracts
  PostgreSQL       Scan state/metadata
  Object storage   Raw evidence/artifacts
  Docker           Initial execution isolation
  vLLM             Local model serving
  8B model         Security reasoning
  Playwright       Browser automation
  HTTPX            Controlled HTTP
  Semgrep          Fast SAST/candidate generation
  CodeQL           Deep source/data-flow analysis where appropriate
  ZAP              DAST/runtime testing
  Nuclei           Deterministic known-vulnerability checks
  tree-sitter      Parsing
  ast-grep         Structural source queries

------------------------------------------------------------------------

# 4. Research Workstream

Before implementing major components, research the public ecosystem.

Create:

``` text
research/
  agent-frameworks.md
  agentic-pentesting.md
  source-analysis.md
  runtime-testing.md
  browser-agents.md
  security-knowledge.md
  benchmarks.md
  licenses.md
  model-evaluation.md
  gaps.md
```

For every project record:

``` text
Project
Repository
Official documentation
License
Version/release reviewed
Language
Architecture
Supported languages
Framework support
Agent framework
Model support
Local-model support
Tool system
Sandboxing
State management
Persistence
Observability
Output format
Extensibility
Relevant source files
Useful ideas
Reuse candidates
Limitations
Licensing concerns
```

Do not rely only on README files. Inspect source, tests, dependencies,
recent releases, and license files.

------------------------------------------------------------------------

# 5. Agent Framework Research

## 5.1 LangGraph --- primary choice

Research:

-   StateGraph;
-   typed state;
-   conditional edges;
-   loops;
-   checkpointing;
-   persistence;
-   interrupts;
-   human-in-the-loop;
-   streaming;
-   tracing;
-   retry/error handling;
-   subgraphs;
-   tool nodes;
-   deployment/runtime considerations.

Primary documentation:

-   https://docs.langchain.com/oss/python/langgraph/overview
-   https://github.com/langchain-ai/langgraph

Prototype a minimal workflow:

``` text
START
  ↓
hypothesis
  ↓
plan
  ↓
execute
  ↓
validate
  ↓
END
```

Then prototype a bounded loop:

``` text
plan
  ↓
execute
  ↓
validate
  |
  +-- insufficient evidence --> plan
  |
  +-- confirmed --> report
  |
  +-- rejected --> end
```

------------------------------------------------------------------------

# 6. LangChain Research

Study LangChain only as a supporting library.

Research:

-   model adapters;
-   structured output;
-   tool definitions;
-   retrieval;
-   prompt templates;
-   callbacks/tracing.

Do not make LangChain abstractions the domain model.

Our domain models remain:

``` text
Scan
Target
AttackSurface
SecurityGraph
Candidate
Hypothesis
TestPlan
ToolRequest
ToolResult
Evidence
ValidationResult
Finding
```

------------------------------------------------------------------------

# 7. Pydantic Research

Use Pydantic for every boundary.

Required schemas:

``` text
ScanRequest
TargetPolicy
RepositorySpec
AttackSurface
SecurityGraph
Candidate
Hypothesis
TestPlan
ToolRequest
ToolResult
Evidence
ValidationResult
Finding
ScanState
Budget
```

All LLM responses should use structured outputs where possible.

Never depend on arbitrary free-form LLM prose for control flow.

------------------------------------------------------------------------

# 8. Alternative Frameworks to Evaluate

Research but do not initially adopt unless benchmarking demonstrates a
benefit:

## OpenAI Agents SDK

Research:

-   agents;
-   tools;
-   handoffs;
-   guardrails;
-   sessions;
-   tracing;
-   structured outputs.

Reference:

-   https://openai.github.io/openai-agents-python/

## PydanticAI

Research:

-   typed agents;
-   structured outputs;
-   dependency injection;
-   tools;
-   model abstraction.

Reference:

-   https://ai.pydantic.dev/

## AutoGen

Research only as a comparison for multi-agent conversations.

## CrewAI

Research only as a comparison.

### Decision rule

Do not choose a framework because it makes a demo look more autonomous.

Choose based on:

``` text
state management
+
reliability
+
debuggability
+
typed contracts
+
checkpointing
+
bounded execution
+
observability
+
local model support
```

------------------------------------------------------------------------

# 9. Agentic Security Projects to Study

## Shannon

Repository:

-   https://github.com/KeygraphHQ/shannon

Study:

-   source-to-runtime workflow;
-   reconnaissance;
-   vulnerability candidate generation;
-   exploitation;
-   finding reconciliation;
-   evidence;
-   reporting;
-   agent prompts;
-   model/tool interfaces.

Important:

Shannon is AGPL-3.0. Study and learn from its architecture, but do not
copy code into a proprietary product without legal review.

------------------------------------------------------------------------

## Strix

Repository:

-   https://github.com/usestrix/strix

Study:

-   agent architecture;
-   skills;
-   browser/HTTP/terminal interaction;
-   Docker isolation;
-   finding generation;
-   autonomous runtime testing;
-   local model support.

The public project is Apache-2.0; verify the exact version/license
before reuse.

------------------------------------------------------------------------

# 10. Source Analysis Research

## Semgrep

-   https://github.com/semgrep/semgrep

Research:

-   supported languages;
-   rule format;
-   taint/data-flow features;
-   JSON/SARIF;
-   framework rules;
-   performance;
-   false positives;
-   licensing of the exact features we intend to ship.

Use primarily for candidate generation.

A Semgrep result is not automatically a confirmed vulnerability.

------------------------------------------------------------------------

## CodeQL

-   https://codeql.github.com/
-   https://docs.github.com/en/code-security/concepts/code-scanning/codeql-code-scanning

Research:

-   supported languages;
-   query model;
-   data-flow;
-   custom queries;
-   framework modeling;
-   database generation;
-   runtime;
-   license/commercial implications.

Keep behind:

``` text
SourceAnalyzer
```

interface so it remains optional.

------------------------------------------------------------------------

## tree-sitter / ast-grep

Research:

-   parser coverage;
-   incremental parsing;
-   structural matching;
-   query performance;
-   language grammar availability.

Goal:

Build a common security-oriented intermediate representation.

------------------------------------------------------------------------

# 11. Runtime Testing Research

## OWASP ZAP

-   https://www.zaproxy.org/
-   https://www.zaproxy.org/docs/automate/automation-framework/

Research:

-   Automation Framework;
-   spidering;
-   AJAX spider;
-   passive scanner;
-   active scanner;
-   authentication;
-   session handling;
-   request modification;
-   scripting;
-   API import;
-   Docker;
-   output formats.

ZAP is a deterministic runtime engine, not the main reasoning engine.

------------------------------------------------------------------------

## Nuclei

-   https://github.com/projectdiscovery/nuclei
-   https://github.com/projectdiscovery/nuclei-templates

Research:

-   HTTP templates;
-   workflows;
-   matchers;
-   extractors;
-   technology detection;
-   severity/tags;
-   custom templates;
-   JSON output;
-   execution controls.

Use for:

-   known CVEs;
-   exposures;
-   misconfiguration;
-   deterministic security checks.

------------------------------------------------------------------------

# 12. Browser Automation Research

Research:

-   Playwright;
-   browser context isolation;
-   cookies;
-   authentication state;
-   HAR recording;
-   screenshots;
-   network interception;
-   request/response capture.

Primary:

-   https://playwright.dev/

Browser operations must be exposed through typed tools rather than
arbitrary browser debugging.

------------------------------------------------------------------------

# 13. Security Knowledge

Use authoritative sources.

Priority:

1.  OWASP WSTG.
2.  OWASP ASVS.
3.  OWASP API Security Top 10.
4.  CWE.
5.  CAPEC.
6.  CVE/NVD and vendor advisories.
7.  Framework security documentation.

WSTG:

-   https://github.com/OWASP/wstg
-   https://owasp.org/www-project-web-security-testing-guide/

Knowledge should become structured test strategies, not just a large
vector database.

Example:

``` json
{
  "id": "WSTG-...",
  "vulnerability": "BOLA",
  "preconditions": [],
  "signals": [],
  "source_patterns": [],
  "runtime_tests": [],
  "proof_requirements": []
}
```

------------------------------------------------------------------------

# 14. Benchmark Research

## Juice Shop

-   https://github.com/juice-shop/juice-shop

Use for:

-   web vulnerability coverage;
-   authentication;
-   authorization;
-   injection;
-   XSS;
-   business logic.

## crAPI

-   https://github.com/OWASP/crAPI

Use heavily for:

-   API security;
-   BOLA;
-   authentication;
-   authorization;
-   SSRF;
-   injection;
-   JWT;
-   multi-step attack scenarios.

## XBOW validation benchmarks

-   https://github.com/xbow-engineering/validation-benchmarks

Study:

-   benchmark structure;
-   task definitions;
-   proof methodology.

Do not treat it as the only benchmark; its repository notes that the
current set is saturated for modern models.

------------------------------------------------------------------------

# 15. Build Our Own Benchmark

Create:

``` text
benchmarks/
  applications/
  manifests/
  expected/
  runner/
```

Each case:

``` text
source
commit
deployment
credentials
known vulnerability
CWE
WSTG
endpoint
preconditions
proof recipe
expected evidence
difficulty
```

Start with 20-30 cases.

Target eventually:

``` text
100+ applications/tests
multiple languages
multiple frameworks
authenticated/unauthenticated
single-step/multi-step
source-visible/source-obscured
```

------------------------------------------------------------------------

# 16. Evaluation Metrics

Measure:

``` text
TP
FP
FN
Precision
Recall
F1
```

Also:

``` text
confirmed findings
proof success rate
false-positive rate
time to first confirmed finding
time per confirmed finding
HTTP request count
browser action count
LLM calls
LLM tokens
latency
tool failures
retry count
```

Primary product metric:

> **Confirmed vulnerability recall at acceptable testing cost.**

Secondary:

> **Precision of confirmed findings.**

------------------------------------------------------------------------

# 17. Stage-1 Vulnerability Scope

Start with:

## Tier 1

-   BOLA/IDOR;
-   broken function-level authorization;
-   authentication bypass;
-   SQL injection;
-   NoSQL injection;
-   command injection;
-   SSRF;
-   path traversal;
-   reflected/stored XSS;
-   unsafe file access.

## Tier 2

-   JWT/authentication weaknesses;
-   CSRF;
-   CORS;
-   open redirect;
-   file upload;
-   mass assignment;
-   SSTI;
-   XXE where applicable;
-   sensitive-data exposure;
-   rate-limit/security-control weaknesses.

## Tier 3

Later:

-   business logic;
-   tenant isolation;
-   multi-step authorization;
-   race conditions;
-   workflow/state-machine attacks.

------------------------------------------------------------------------

# 18. Language Strategy

Design for many languages but initially support:

``` text
JavaScript/TypeScript
Python
```

Then:

``` text
Java/Spring
Go
PHP
Ruby
```

All language adapters produce a common security-oriented IR.

------------------------------------------------------------------------

# 19. Repository Intake

Steps:

1.  Clone into an isolated workspace.
2.  Pin commit SHA.
3.  Detect languages.
4.  Detect frameworks.
5.  Detect package managers.
6.  Detect build systems.
7.  Detect entry points.
8.  Detect tests.
9.  Detect configuration.
10. Detect OpenAPI/GraphQL.
11. Detect authentication/authorization code.
12. Inventory dependencies.
13. Never execute untrusted repository code directly on the host.

Repository code is untrusted input.

------------------------------------------------------------------------

# 20. Runtime Target Intake

Require explicit authorization and scope.

Target record:

``` json
{
  "base_url": "https://authorized.example",
  "allowed_hosts": ["authorized.example"],
  "allowed_ports": [443],
  "allowed_paths": ["/"],
  "rate_limit": "...",
  "test_window": "..."
}
```

Every generated URL/request must pass scope validation.

Redirect destinations must also be validated.

------------------------------------------------------------------------

# 21. Recon

Discover:

-   hosts within scope;
-   routes;
-   HTTP methods;
-   APIs;
-   forms;
-   JavaScript routes;
-   OpenAPI;
-   GraphQL;
-   WebSockets;
-   authentication endpoints;
-   cookies;
-   headers;
-   technologies;
-   error behavior.

Sources:

``` text
ZAP
HTTP crawler
Playwright
OpenAPI
source route extraction
JS bundle analysis
framework metadata
```

Output:

``` text
AttackSurface
```

------------------------------------------------------------------------

# 22. Application Security Graph

Central internal model.

Nodes:

``` text
Application
Host
Route
HTTP Parameter
Cookie
Header
User
Role
Middleware
Controller
Service
Function
Database
Query
External Service
File
Template
Sink
```

Edges:

``` text
REQUESTS
CALLS
READS
WRITES
FLOWS_TO
AUTHENTICATED_BY
AUTHORIZED_BY
QUERIES
FETCHES
RENDERS
EXECUTES
READS_FILE
```

This graph joins source and runtime information.

------------------------------------------------------------------------

# 23. Candidate Generation

Candidate sources:

``` text
Semgrep
CodeQL
ZAP
Nuclei
dependency analysis
security graph rules
runtime anomalies
LLM reasoning
```

Normalize:

``` json
{
  "candidate_id": "...",
  "type": "...",
  "source": "...",
  "confidence": 0.0,
  "endpoint": {},
  "source_locations": [],
  "dataflow": [],
  "reason": "..."
}
```

A candidate is never automatically a finding.

------------------------------------------------------------------------

# 24. LLM Hypothesis Agent

Input:

``` text
endpoint
authentication
authorization
relevant source
security graph slice
candidate signals
runtime behavior
relevant WSTG/CWE knowledge
```

Output:

``` json
{
  "vulnerability_type": "BOLA",
  "reason": "...",
  "confidence": 0.87,
  "preconditions": [],
  "test_plan": [],
  "expected_vulnerable_behavior": "...",
  "expected_secure_behavior": "...",
  "validation_criteria": []
}
```

Use structured output.

------------------------------------------------------------------------

# 25. Test Planner

Convert hypothesis into typed tool operations.

Every plan has:

``` text
scope
maximum requests
maximum browser actions
timeout
allowed tools
stop conditions
expected evidence
```

Example:

``` text
BOLA:
1. Create/identify user A.
2. Create/identify user B.
3. Authenticate A.
4. Identify resource owned by B.
5. Request resource as A.
6. Compare response.
7. Run control request.
8. Validate.
```

------------------------------------------------------------------------

# 26. Tool Gateway

Architecture:

``` text
LLM
 |
 v
ToolRequest schema
 |
 v
argument validation
 |
 v
scope validation
 |
 v
budget validation
 |
 v
executor
 |
 v
ToolResult
```

Tools:

``` text
http_request
browser_navigate
browser_click
browser_fill
browser_submit
source_read
source_search
ast_query
semgrep
codeql
zap
nuclei
openapi_parser
response_compare
```

Never expose unrestricted shell/network access to the model.

------------------------------------------------------------------------

# 27. Evidence

Store raw evidence first.

Evidence includes:

``` text
request
response
headers
body
timestamp
target
identity
session context
source location
tool
test plan
control request
control response
```

Use object storage for large artifacts.

Use PostgreSQL for metadata.

------------------------------------------------------------------------

# 28. Validation

Validator receives:

``` text
hypothesis
test plan
execution result
raw evidence
source context
runtime context
```

It outputs:

``` text
CONFIRMED
LIKELY
UNCONFIRMED
REJECTED
ERROR
```

Only `CONFIRMED` enters the confirmed findings list.

Validator must distinguish:

``` text
test failure
```

from:

``` text
vulnerability disproven
```

------------------------------------------------------------------------

# 29. Proof Rules

A confirmed finding should satisfy applicable conditions:

1.  Intended test executed.
2.  Correct target contacted.
3.  Preconditions satisfied.
4.  Attacker-controlled input reached the relevant operation.
5.  Security boundary was crossed.
6.  Observed behavior matches hypothesis.
7.  Control comparison supports the conclusion.
8.  Result is reproducible.
9.  Raw evidence is available.

Proof requirements vary by vulnerability class.

------------------------------------------------------------------------

# 30. LangGraph State

Use typed state.

Conceptual example:

``` python
class ScanState(TypedDict):
    scan_id: str
    repository: RepositorySpec
    target: TargetSpec

    attack_surface: AttackSurface
    security_graph: SecurityGraph

    candidates: list[Candidate]
    hypotheses: list[Hypothesis]

    current_hypothesis: Hypothesis | None
    current_test_plan: TestPlan | None

    executions: list[Execution]
    evidence: list[Evidence]

    findings: list[Finding]

    budget: ScanBudget
    errors: list[ScanError]
```

------------------------------------------------------------------------

# 31. LangGraph Workflow

Primary graph:

``` text
START
 |
 v
intake
 |
 v
recon
 |
 v
source_analysis
 |
 v
build_security_graph
 |
 v
candidate_generation
 |
 v
prioritize
 |
 v
hypothesis
 |
 v
plan
 |
 v
policy_check
 |
 v
execute
 |
 v
collect_evidence
 |
 v
validate
 |
 +-------------------+
 |                   |
 v                   v
CONFIRMED        MORE_EVIDENCE
 |                   |
 v                   v
correlate            plan
 |                   |
 v                   +----> execute
report
 |
 v
END
```

Use bounded loops.

------------------------------------------------------------------------

# 32. Budgets

Per scan:

``` text
max wall-clock time
max LLM calls
max LLM tokens
max HTTP requests
max browser actions
max active scanner requests
max concurrent hypotheses
max evidence size
max retries
```

Per hypothesis:

``` text
max attempts
max requests
max runtime
```

------------------------------------------------------------------------

# 33. Safety

Implement:

-   hostname allowlist;
-   IP restrictions;
-   DNS rebinding protection;
-   redirect validation;
-   port restrictions;
-   path restrictions;
-   request rate limits;
-   execution budgets;
-   audit logs;
-   kill switch;
-   isolated containers;
-   no host Docker socket;
-   no arbitrary external targets.

Only authorized targets are allowed.

------------------------------------------------------------------------

# 34. Model Strategy

The 8B model should reason over small context slices.

Do not send:

``` text
500k tokens of repository
```

Instead:

``` text
route
+
relevant controller
+
relevant service
+
dataflow
+
auth
+
runtime behavior
+
security knowledge
```

Use deterministic filtering before LLM inference.

------------------------------------------------------------------------

# 35. Cost Optimization

Example:

``` text
500 endpoints
    |
    v
deterministic filtering
    |
    v
40 candidates
    |
    v
8B reasoning
    |
    v
15 hypotheses
    |
    v
runtime tests
    |
    v
3 confirmed findings
```

Do not run LLM calls on every endpoint.

------------------------------------------------------------------------

# 36. Observability

Log:

``` text
scan timeline
graph transitions
model version
prompts/version IDs
LLM outputs
tool requests
tool responses
hypotheses
validation decisions
evidence references
```

Every event should have:

``` text
scan_id
trace_id
timestamp
component
```

------------------------------------------------------------------------

# 37. Reproducibility

A finding must be replayable using:

``` text
repository commit
target version
scan configuration
test plan
tool versions
model version
evidence
```

------------------------------------------------------------------------

# 38. Development Milestones

## M0 --- Research

Complete:

``` text
agent-frameworks.md
agentic-pentesting.md
source-analysis.md
runtime-testing.md
benchmarks.md
licenses.md
```

Acceptance:

-   LangGraph studied.
-   LangChain studied.
-   PydanticAI studied.
-   OpenAI Agents SDK studied.
-   Shannon studied.
-   Strix studied.
-   Semgrep studied.
-   CodeQL studied.
-   ZAP studied.
-   Nuclei studied.
-   OWASP WSTG studied.
-   Juice Shop studied.
-   crAPI studied.
-   XBOW studied.

------------------------------------------------------------------------

## M1 --- Framework Proof

Build a toy LangGraph workflow:

``` text
candidate
  ↓
hypothesis
  ↓
plan
  ↓
mock tool
  ↓
validation
```

Requirements:

-   typed Pydantic state;
-   checkpointing;
-   conditional edges;
-   bounded retry;
-   trace logging.

------------------------------------------------------------------------

## M2 --- Intake + Recon

Input:

``` text
repo + authorized URL
```

Output:

``` text
language
framework
routes
technologies
attack surface
```

------------------------------------------------------------------------

## M3 --- Security Graph

Support:

``` text
JavaScript/TypeScript
Python
```

Extract:

``` text
routes
controllers
functions
inputs
auth
sinks
database calls
external requests
```

------------------------------------------------------------------------

## M4 --- Deterministic Candidates

Integrate:

``` text
Semgrep
Nuclei
ZAP
```

No autonomous exploitation yet.

------------------------------------------------------------------------

## M5 --- Hypothesis Agent

Input:

``` text
candidate
+
Security Graph slice
+
runtime context
```

Output:

``` text
typed Hypothesis
```

------------------------------------------------------------------------

## M6 --- Test Planner + Tool Gateway

Implement:

``` text
HTTP
browser
source queries
AST queries
```

with:

``` text
scope
budget
audit
```

------------------------------------------------------------------------

## M7 --- Validator

Implement:

``` text
candidate
 -> plan
 -> execution
 -> evidence
 -> validation
 -> confirmed/rejected
```

This is the first real product milestone.

------------------------------------------------------------------------

## M8 --- Benchmark

Run against:

``` text
Juice Shop
crAPI
custom benchmark
```

Measure:

``` text
precision
recall
proof success
false positives
cost
time
```

------------------------------------------------------------------------

## M9 --- Adaptive Investigation

Only after M8:

``` text
test
 ↓
new evidence
 ↓
new hypothesis
 ↓
new test
```

with strict budgets.

------------------------------------------------------------------------

# 39. Definition of Done

Stage 1 is complete when the system can:

1.  Ingest repository.
2.  Connect to authorized target.
3.  Identify language/framework.
4.  Discover attack surface.
5.  Analyze source.
6.  Build Security Graph.
7.  Generate candidates.
8.  Generate testable hypotheses.
9.  Build bounded test plans.
10. Execute tests through controlled tools.
11. Capture raw evidence.
12. Validate evidence.
13. Reject false positives.
14. Produce reproducible confirmed findings.
15. Evaluate on a benchmark.

Patching is not part of this definition.

------------------------------------------------------------------------

# 40. Future Stage 2 Boundary

Stage 2 may consume:

``` text
Confirmed Finding
+
Source Location
+
Root Cause
+
Proof Test
```

and then build:

``` text
Patch Proposal
 ↓
Security Regression Test
 ↓
Original PoC must fail
 ↓
Application Tests
 ↓
Patch Validation
```

Do not implement Stage 2 before Stage 1 has strong detection and proof
metrics.

------------------------------------------------------------------------

# 41. Final Principle

The system should optimize for:

> **Validated vulnerabilities, not generated vulnerability
> descriptions.**

The product loop is:

``` text
SEE
 ↓
UNDERSTAND
 ↓
HYPOTHESIZE
 ↓
TEST
 ↓
PROVE
```

Stage 1 ends at `PROVE`.
