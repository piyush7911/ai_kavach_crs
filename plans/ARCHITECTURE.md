# ARCHITECTURE.md --- Agentic Web Application Security Testing

## Stage 1: Find and Prove Vulnerabilities

**Primary workflow engine:** LangGraph\
**Typed contracts:** Pydantic\
**Reasoning model:** local/self-hosted 8B-class model\
**Security engine:** custom modular implementation\
**Stage 1 endpoint:** confirmed, evidence-backed vulnerability\
**Patching:** explicitly excluded

------------------------------------------------------------------------

# 1. System Goal

Input:

``` text
Source repository
+
Authorized running application
+
Optional authorized credentials
```

Output:

``` text
Confirmed vulnerability
+
reproducible proof
+
raw evidence
+
structured finding
```

Core invariant:

> **No evidence-backed proof =\> no confirmed finding.**

------------------------------------------------------------------------

# 2. High-Level Architecture

``` text
                           USER / CI
                              |
                              v
                    +---------------------+
                    | FastAPI / CLI       |
                    +----------+----------+
                               |
                               v
                    +---------------------+
                    | LangGraph            |
                    | Scan Orchestrator   |
                    +----------+----------+
                               |
             +-----------------+-----------------+
             |                                   |
             v                                   v
    +-------------------+               +-------------------+
    | Repository        |               | Authorized Target |
    | Workspace         |               | Scope             |
    +---------+---------+               +---------+---------+
              |                                   |
              v                                   v
    +-------------------+               +-------------------+
    | Source Intelligence|              | Runtime Recon     |
    +---------+---------+               +---------+---------+
              |                                   |
              +----------------+------------------+
                               |
                               v
                  +-----------------------------+
                  | Application Security Graph  |
                  +-------------+---------------+
                                |
                                v
                  +-----------------------------+
                  | Candidate Engine             |
                  | SAST / DAST / Graph / LLM   |
                  +-------------+---------------+
                                |
                                v
                  +-----------------------------+
                  | 8B Hypothesis Agent          |
                  +-------------+---------------+
                                |
                                v
                  +-----------------------------+
                  | 8B Test Planner              |
                  +-------------+---------------+
                                |
                                v
                  +-----------------------------+
                  | Policy + Tool Gateway        |
                  +-------------+---------------+
                                |
             +------------------+------------------+
             |                  |                  |
             v                  v                  v
          HTTPX             Playwright         ZAP/Nuclei
             |                  |                  |
             +------------------+------------------+
                                |
                                v
                  +-----------------------------+
                  | Evidence Store              |
                  +-------------+---------------+
                                |
                                v
                  +-----------------------------+
                  | 8B Proof Validator           |
                  +-------------+---------------+
                                |
                       +--------+--------+
                       |                 |
                       v                 v
                   CONFIRMED          REJECTED
                       |
                       v
                   Correlator
                       |
                       v
                  Finding/Report
```

------------------------------------------------------------------------

# 3. Framework Boundary

LangGraph is responsible for:

``` text
workflow state
branching
loops
checkpoints
retries
pause/resume
agent node sequencing
conditional transitions
```

LangGraph is NOT responsible for:

``` text
security graph implementation
source parsing
HTTP implementation
browser implementation
ZAP
Nuclei
evidence storage
finding schema
target policy
```

Those belong to our own modules.

------------------------------------------------------------------------

# 4. Why LangGraph

The system is an investigation graph rather than a conversational agent
swarm.

Primary graph:

``` text
START
 |
 v
INTAKE
 |
 v
RECON
 |
 v
SOURCE_ANALYSIS
 |
 v
GRAPH_BUILD
 |
 v
CANDIDATES
 |
 v
PRIORITIZE
 |
 v
HYPOTHESIS
 |
 v
PLAN
 |
 v
POLICY_CHECK
 |
 v
EXECUTE
 |
 v
EVIDENCE
 |
 v
VALIDATE
 |
 +----------------------+
 |                      |
 v                      v
CONFIRMED            MORE_EVIDENCE
 |                      |
 v                      v
CORRELATE              PLAN
 |                      |
 v                      +----> EXECUTE
REPORT
 |
 v
END
```

------------------------------------------------------------------------

# 5. LangGraph State

Use Pydantic models inside typed LangGraph state.

Conceptual:

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

The exact schema should be versioned.

------------------------------------------------------------------------

# 6. Pydantic Domain Models

Required models:

``` text
RepositorySpec
TargetSpec
TargetPolicy
ScanConfig
ScanBudget
AttackSurface
Route
SourceLocation
SecurityNode
SecurityEdge
SecurityGraph
Candidate
Hypothesis
TestStep
TestPlan
ToolRequest
ToolResult
Execution
Evidence
ValidationResult
Finding
```

All models should have explicit versions where long-term persistence is
expected.

------------------------------------------------------------------------

# 7. Agent Roles

Only a small number of components should be actual LLM reasoning nodes.

## Agent 1 --- Hypothesis Agent

Purpose:

``` text
Candidate + relevant context
        ↓
security hypothesis
```

Responsibilities:

-   reason about source/runtime context;
-   identify likely vulnerability;
-   explain attack preconditions;
-   propose proof criteria.

------------------------------------------------------------------------

## Agent 2 --- Test Planner

Purpose:

``` text
Hypothesis
    ↓
bounded TestPlan
```

Responsibilities:

-   choose the smallest useful test;
-   identify required identities;
-   define control cases;
-   define expected vulnerable behavior;
-   define expected secure behavior;
-   set test steps.

------------------------------------------------------------------------

## Agent 3 --- Observation Interpreter

Purpose:

``` text
raw execution result
        ↓
structured interpretation
```

Responsibilities:

-   interpret HTTP/browser results;
-   compare expected/observed behavior;
-   identify missing evidence;
-   suggest next evidence collection.

------------------------------------------------------------------------

## Agent 4 --- Proof Validator

Purpose:

``` text
Hypothesis + Evidence
        ↓
CONFIRMED / REJECTED
```

Responsibilities:

-   independently evaluate evidence;
-   detect false positives;
-   check reproducibility;
-   verify security-boundary violation;
-   require sufficient proof.

The validator is a separate graph node from the hypothesis generator.

------------------------------------------------------------------------

# 8. Deterministic Components

These should not be LLM agents:

``` text
Repository intake
Language detection
Framework detection
AST parsing
Route extraction
Security graph construction
Semgrep
CodeQL
ZAP
Nuclei
HTTP transport
Browser automation
Scope validation
Budget enforcement
Evidence persistence
Finding correlation
Report serialization
```

------------------------------------------------------------------------

# 9. Repository Intake

``` text
Git repository
      |
      v
isolated workspace
      |
      +--> commit pin
      +--> language detection
      +--> framework detection
      +--> package manager
      +--> build system
      +--> entry points
      +--> route discovery
      +--> API schema discovery
      +--> auth discovery
      +--> dependency inventory
```

Never execute repository code on the control-plane host.

------------------------------------------------------------------------

# 10. Source Intelligence

Initial languages:

``` text
JavaScript/TypeScript
Python
```

Future:

``` text
Java/Spring
Go
PHP
Ruby
```

Language adapters output common security entities.

------------------------------------------------------------------------

# 11. Security-Oriented Intermediate Representation

Common entities:

``` text
Application
File
Module
Class
Function
Route
Controller
Middleware
Input
Validator
AuthenticationCheck
AuthorizationCheck
Database
Query
ExternalRequest
FileAccess
CommandExecution
TemplateRender
Serializer
Sink
```

Edges:

``` text
CALLS
FLOWS_TO
READS
WRITES
QUERIES
FETCHES
RENDERS
EXECUTES
AUTHENTICATED_BY
AUTHORIZED_BY
```

------------------------------------------------------------------------

# 12. Application Security Graph

The graph joins:

``` text
source code
+
runtime routes
+
authentication
+
authorization
+
data flows
+
sinks
+
external dependencies
```

Example:

``` text
GET /api/users/{id}
        |
        v
UserController.get
        |
        v
UserService.get
        |
        v
UserRepository.find
        |
        v
Database
```

Input:

``` text
{id}
 |
 v
user-controlled
 |
 v
UserRepository.find
```

Authorization:

``` text
authenticated?
      |
      v
ownership check?
      |
      +---- missing
```

This can generate a BOLA candidate.

------------------------------------------------------------------------

# 13. Runtime Recon

Output:

``` json
{
  "routes": [],
  "methods": [],
  "parameters": [],
  "forms": [],
  "apis": [],
  "graphql": [],
  "websockets": [],
  "auth_endpoints": [],
  "technologies": [],
  "cookies": [],
  "headers": []
}
```

Sources:

``` text
ZAP
HTTPX crawler
Playwright
OpenAPI
source route extraction
JavaScript analysis
framework metadata
```

------------------------------------------------------------------------

# 14. Source/Runtime Correlation

Runtime:

``` text
GET /api/users/123
```

Source:

``` text
router.get("/api/users/:id", userController.get)
```

Correlation:

``` text
runtime route
      |
      v
route definition
      |
      v
controller
      |
      v
service
      |
      v
repository
```

Correlation confidence:

``` text
EXACT
HIGH
MEDIUM
LOW
UNKNOWN
```

Hypothesis priority should consider correlation quality.

------------------------------------------------------------------------

# 15. Candidate Engine

Candidate sources:

``` text
Semgrep
CodeQL
ZAP
Nuclei
graph rules
dependency analysis
runtime anomalies
LLM source reasoning
```

Normalize:

``` python
class Candidate(BaseModel):
    candidate_id: str
    vulnerability_type: str
    source: str
    confidence: float
    endpoint: Endpoint | None
    source_locations: list[SourceLocation]
    dataflow: list[GraphEdge]
    reason: str
```

Candidates are not findings.

------------------------------------------------------------------------

# 16. Graph Security Rules

Build deterministic rules first.

### BOLA

``` text
object identifier
+
authenticated request
+
resource lookup
+
no observable ownership/authorization relationship
```

### SSRF

``` text
user-controlled URL
+
server-side HTTP client
```

### SQL injection

``` text
user-controlled input
+
query construction
+
SQL sink
```

### Command injection

``` text
user-controlled input
+
process execution
```

### Path traversal

``` text
user-controlled path
+
filesystem read/write
```

Rules create candidates; proof happens at runtime.

------------------------------------------------------------------------

# 17. Hypothesis Agent Context

Never give the model the entire repository by default.

Context builder provides:

``` text
application summary
endpoint
authentication
authorization
relevant source files
dataflow
security graph slice
candidate signals
runtime observations
relevant WSTG/CWE knowledge
previous test results
```

Example:

``` text
Endpoint:
GET /api/orders/{id}

Authentication:
JWT

Authorization:
ownership check not identified

Controller:
OrderController.get()

Service:
OrderService.get()

Repository:
OrderRepository.find(id)

Candidate:
BOLA

Task:
Design the smallest safe test that can prove or disprove
cross-user resource access.
```

------------------------------------------------------------------------

# 18. Test Plan

The LLM outputs a typed plan.

Example:

``` json
{
  "hypothesis_id": "h-001",
  "steps": [
    {
      "tool": "authenticate",
      "purpose": "authenticate as user A"
    },
    {
      "tool": "http_request",
      "purpose": "request resource owned by B"
    }
  ],
  "max_requests": 20,
  "timeout_seconds": 60,
  "stop_conditions": [
    "confirmed",
    "scope_error",
    "budget_exhausted"
  ]
}
```

Planner cannot directly bypass policy.

------------------------------------------------------------------------

# 19. Tool Gateway

Architecture:

``` text
LLM
 |
 v
ToolRequest
 |
 v
Schema Validation
 |
 v
Target Policy
 |
 v
Budget
 |
 v
Executor
 |
 v
ToolResult
```

Available tools:

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

No unrestricted shell.

------------------------------------------------------------------------

# 20. HTTP Tool

Input:

``` json
{
  "method": "GET",
  "url": "/api/users/123",
  "headers": {},
  "body": null
}
```

Validation:

``` text
URL parse
 ↓
hostname allowlist
 ↓
DNS/IP policy
 ↓
port policy
 ↓
path policy
 ↓
redirect policy
 ↓
request budget
 ↓
execute
```

Capture:

``` text
status
headers
body
timing
redirects
request ID
```

------------------------------------------------------------------------

# 21. Browser Tool

Use Playwright.

Expose:

``` text
navigate
click
fill
select
submit
wait
extract
screenshot
```

Browser contexts must be isolated per scan/identity.

Do not expose arbitrary browser debugging to the LLM.

------------------------------------------------------------------------

# 22. Scanner Adapters

Define:

``` python
class SecurityScanner(Protocol):
    async def scan(
        self,
        target: TargetSpec,
        config: ScanConfig
    ) -> list[Candidate]:
        ...
```

Implement:

``` text
SemgrepAdapter
CodeQLAdapter
ZAPAdapter
NucleiAdapter
```

All produce the common `Candidate` model.

------------------------------------------------------------------------

# 23. Evidence Store

PostgreSQL metadata:

``` text
scans
targets
assets
routes
source_locations
candidates
hypotheses
test_plans
executions
findings
```

Object storage:

``` text
HTTP requests
HTTP responses
screenshots
HAR
scanner output
logs
source snapshots
```

Every evidence item has:

``` text
evidence_id
scan_id
trace_id
timestamp
tool
content_hash
metadata
```

------------------------------------------------------------------------

# 24. Validation Node

Input:

``` text
Hypothesis
TestPlan
Execution
Evidence
Source context
Runtime context
```

Output:

``` json
{
  "status": "CONFIRMED",
  "confidence": 0.97,
  "reason": "...",
  "evidence_refs": [],
  "reproduction_steps": []
}
```

Possible states:

``` text
CONFIRMED
LIKELY
UNCONFIRMED
REJECTED
ERROR
```

Only `CONFIRMED` enters the confirmed finding collection.

------------------------------------------------------------------------

# 25. Proof Gate

A vulnerability is confirmed only when applicable proof requirements are
satisfied:

``` text
test executed
+
correct target
+
preconditions met
+
attacker input reached relevant operation
+
security boundary crossed
+
observed behavior matches hypothesis
+
control comparison supports result
+
result reproducible
+
raw evidence stored
```

The exact policy varies by vulnerability.

------------------------------------------------------------------------

# 26. Example: BOLA Proof

Source:

``` text
GET /api/orders/{id}
        |
        v
OrderRepository.find(id)
```

Runtime:

``` text
User A owns order A
User B owns order B
```

Attack:

``` text
authenticate A
GET /api/orders/B
```

Control:

``` text
unauthenticated GET /api/orders/B
```

If:

``` text
A authenticated
+
B's resource returned
+
A has no authorization to B's resource
```

then:

``` text
CONFIRMED BOLA
```

------------------------------------------------------------------------

# 27. Example: SSRF Proof

Source:

``` text
user-controlled URL
       |
       v
server-side HTTP client
```

Runtime:

``` text
controlled callback endpoint
       ^
       |
application server
       ^
       |
attacker-controlled URL
```

Proof:

``` text
application makes server-side request
+
controlled callback receives request
```

Use controlled infrastructure.

------------------------------------------------------------------------

# 28. Example: SQL Injection Proof

Source:

``` text
user input
    |
    v
query construction
    |
    v
SQL execution
```

Proof should combine applicable signals:

``` text
source dataflow
+
controlled input
+
differential database behavior
```

Do not classify generic SQL error pages as proof by themselves.

------------------------------------------------------------------------

# 29. Finding Model

``` python
class Finding(BaseModel):
    finding_id: str
    status: Literal["CONFIRMED"]
    vulnerability_type: str
    title: str
    severity: str
    confidence: float

    endpoint: Endpoint | None
    source_locations: list[SourceLocation]

    root_cause: str

    proof_steps: list[str]
    evidence_refs: list[str]

    impact: str

    cwe: str | None
    wstg: str | None
    asvs: str | None
```

------------------------------------------------------------------------

# 30. Correlation

Multiple detectors may report the same issue:

``` text
Semgrep
CodeQL
ZAP
Nuclei
Graph rule
LLM
Runtime
```

Cluster using:

``` text
vulnerability type
endpoint
method
source location
sink
dataflow
resource
evidence similarity
```

Keep provenance:

``` text
found_by:
  - semgrep
  - graph_rule
  - LLM
  - runtime
```

Produce one confirmed finding.

------------------------------------------------------------------------

# 31. Security Zones

``` text
+-----------------------------+
| CONTROL PLANE               |
| API / DB / Orchestrator     |
+---------------+-------------+
                |
                | restricted
                v
+-----------------------------+
| AGENT PLANE                 |
| LangGraph + 8B model       |
+---------------+-------------+
                |
                | typed ToolRequest
                v
+-----------------------------+
| EXECUTION PLANE             |
| HTTP / Browser / ZAP/Nuclei |
+---------------+-------------+
                |
                | scoped network
                v
+-----------------------------+
| TARGET PLANE                |
| Authorized Web Application  |
+-----------------------------+
```

Repository code must not access the control plane.

------------------------------------------------------------------------

# 32. Sandbox

Initial:

``` text
Docker
```

Requirements:

-   non-root;
-   resource limits;
-   isolated workspace;
-   restricted network;
-   short-lived credentials;
-   timeout;
-   no host Docker socket;
-   minimal host mounts;
-   separate scanner containers where useful.

Future:

``` text
Firecracker / microVM
```

for stronger isolation.

------------------------------------------------------------------------

# 33. Target Policy

Every request passes:

``` text
TargetPolicy.validate()
```

Checks:

``` text
scheme
hostname
resolved IP
port
path
redirect
method
request size
rate limit
```

Redirects are independently validated.

------------------------------------------------------------------------

# 34. Budgets

Global:

``` text
max_scan_time
max_llm_calls
max_llm_tokens
max_http_requests
max_browser_actions
max_scanner_requests
max_concurrency
max_evidence_size
max_retries
```

Per hypothesis:

``` text
max_attempts
max_requests
max_runtime
```

Budget exhaustion must not be interpreted as vulnerability confirmation.

------------------------------------------------------------------------

# 35. Memory/Storage Layers

## Scan state

Short/medium-lived:

``` text
current hypothesis
current plan
recent observations
```

## Application model

Per-scan:

``` text
attack surface
security graph
auth model
routes
assets
```

## Security knowledge

Reusable:

``` text
WSTG
ASVS
CWE
security patterns
test strategies
```

Never store application secrets in reusable knowledge.

------------------------------------------------------------------------

# 36. Observability

Capture:

``` text
graph transitions
LLM calls
model/version
prompt version
tool calls
tool outputs
HTTP traffic metadata
hypotheses
validation decisions
evidence
```

Every event:

``` text
scan_id
trace_id
timestamp
component
```

This allows replay and regression testing.

------------------------------------------------------------------------

# 37. Reproducibility

Every confirmed finding records:

``` text
repository commit
target
scan configuration
model version
tool versions
test plan
evidence
```

A proof should be replayable.

------------------------------------------------------------------------

# 38. Package Layout

``` text
agentic-security/
|
+-- docs/
|   +-- PLAN.md
|   +-- ARCHITECTURE.md
|
+-- research/
|   +-- agent-frameworks.md
|   +-- agentic-pentesting.md
|   +-- source-analysis.md
|   +-- runtime-testing.md
|   +-- benchmarks.md
|   +-- licenses.md
|
+-- scanner/
|   +-- api/
|   +-- orchestration/
|   |   +-- langgraph/
|   |
|   +-- intake/
|   +-- recon/
|   +-- source/
|   +-- graph/
|   +-- candidates/
|   +-- agents/
|   +-- tools/
|   +-- policy/
|   +-- evidence/
|   +-- findings/
|   +-- storage/
|   +-- knowledge/
|
+-- benchmarks/
|
+-- tests/
|
+-- docker/
|
+-- scripts/
```

Important boundary:

``` text
scanner/orchestration/langgraph/
```

contains framework-specific code.

The rest of the security engine should not depend directly on LangGraph
internals.

------------------------------------------------------------------------

# 39. Framework Abstraction

Keep a thin interface:

``` python
class WorkflowEngine(Protocol):

    async def run(
        self,
        scan: ScanRequest
    ) -> ScanResult:
        ...
```

Current implementation:

``` text
LangGraphWorkflowEngine
```

This allows replacing LangGraph later without rewriting:

``` text
security graph
tools
agents
evidence
findings
```

------------------------------------------------------------------------

# 40. Stage-1 Execution Example

``` text
1. Submit repository + authorized target.
2. Validate target scope.
3. Clone repository at fixed commit.
4. Detect languages/frameworks.
5. Extract routes/source/dataflows.
6. Runtime reconnaissance.
7. Correlate runtime routes with source.
8. Build Security Graph.
9. Run deterministic scanners.
10. Generate candidates.
11. Prioritize candidates.
12. Hypothesis Agent reasons over one candidate.
13. Test Planner creates bounded TestPlan.
14. Policy gate validates plan.
15. Tool Gateway executes plan.
16. Evidence is stored.
17. Observation Interpreter structures results if needed.
18. Proof Validator independently evaluates evidence.
19. If confirmed, create Finding.
20. Correlate/deduplicate.
21. Report.
```

------------------------------------------------------------------------

# 41. Critical Architectural Rule

Do not implement:

``` text
"Give repo and URL to one autonomous agent."
```

Implement:

``` text
Deterministic observation
        +
Security Graph
        +
small LLM reasoning steps
        +
typed tools
        +
evidence
        +
independent proof
```

------------------------------------------------------------------------

# 42. Stage-1 Success Criteria

The system must be able to:

``` text
Repository
+
Authorized target
      |
      v
Attack Surface
      |
      v
Security Graph
      |
      v
Candidate
      |
      v
Hypothesis
      |
      v
Bounded Test
      |
      v
Evidence
      |
      v
Independent Validation
      |
      v
Confirmed Finding
```

The system does not need to patch anything.

------------------------------------------------------------------------

# 43. Future Stage 2

Only after Stage 1 is reliable:

``` text
Confirmed Finding
+
Source Location
+
Root Cause
+
Proof Test
        |
        v
Patch Agent
        |
        v
Security Regression Test
        |
        v
Original PoC must fail
        |
        v
Application Tests
```

Stage 2 is deliberately outside the current architecture.

------------------------------------------------------------------------

# 44. Final Architecture Principle

The system has five conceptual layers:

``` text
LLM
= THINK

Tools
= SEE / ACT

Security Graph
= UNDERSTAND APPLICATION

Evidence
= REMEMBER WHAT HAPPENED

Validator
= PROVE
```

LangGraph coordinates those layers.

It is the orchestration framework, not the security product itself.

The product's core IP should be:

``` text
Application Security Graph
+
Attack Hypothesis Engine
+
Adaptive Test Planning
+
Evidence/Proof Validation
```

Stage 1 ends only when the system can reliably say:

> **This vulnerability exists, and here is reproducible evidence proving
> it.**
