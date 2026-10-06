# REFERENCES.md --- Stage-1 Agentic Web Security System

This document is the reference index for building the Stage-1 system.

## Stage-1 scope

The system's job is:

``` text
Repository + Authorized Running App
        ↓
Understand
        ↓
Find candidate
        ↓
Test
        ↓
Collect evidence
        ↓
Prove vulnerability
        ↓
Report
```

Patching/remediation is out of scope.

------------------------------------------------------------------------

# 1. Priority Reading Order

Do not read every project at once.

## Phase A --- Agent architecture

1.  LangGraph
2.  Shannon
3.  Strix
4.  PydanticAI
5.  OpenAI Agents SDK

## Phase B --- Security analysis

6.  OWASP WSTG
7.  OWASP ASVS
8.  OWASP API Security Top 10
9.  Semgrep
10. CodeQL

## Phase C --- Runtime testing

11. OWASP ZAP
12. Nuclei
13. Playwright

## Phase D --- Benchmarks

14. OWASP Juice Shop
15. OWASP crAPI
16. XBOW Validation Benchmarks

## Phase E --- Infrastructure

17. vLLM
18. tree-sitter
19. ast-grep
20. MCP

------------------------------------------------------------------------

# 2. Agent Orchestration

## 2.1 LangGraph --- PRIMARY

Documentation:

-   https://docs.langchain.com/oss/python/langgraph/overview

Repository:

-   https://github.com/langchain-ai/langgraph

### Why we use it

Our system is a durable investigation graph:

``` text
INTAKE
 ↓
RECON
 ↓
SOURCE ANALYSIS
 ↓
GRAPH
 ↓
CANDIDATES
 ↓
HYPOTHESIS
 ↓
PLAN
 ↓
EXECUTE
 ↓
EVIDENCE
 ↓
VALIDATE
 ↓
CONFIRMED / REJECTED
```

Study:

-   StateGraph
-   typed state
-   conditional edges
-   loops
-   checkpointing
-   persistence
-   interrupts
-   human-in-the-loop
-   subgraphs
-   retry/error handling
-   tracing
-   durable execution

### What to take from it

Use LangGraph for:

``` text
workflow
state
branching
loops
checkpointing
agent-node orchestration
```

Do NOT put the security engine inside LangGraph-specific code.

------------------------------------------------------------------------

# 3. LangChain

Documentation:

-   https://docs.langchain.com/oss/python/langchain/overview

Repository:

-   https://github.com/langchain-ai/langchain

### Use selectively for

-   model adapters;
-   structured output;
-   tool abstractions;
-   retrieval;
-   prompt utilities.

### Do not make it our domain architecture

Our domain models should remain ours:

``` text
Candidate
Hypothesis
TestPlan
Evidence
Finding
SecurityGraph
AttackSurface
```

------------------------------------------------------------------------

# 4. PydanticAI

Documentation:

-   https://ai.pydantic.dev/

Repository:

-   https://github.com/pydantic/pydantic-ai

### Why study it

Our system is heavily schema-driven.

We need strict objects for:

``` text
Hypothesis
TestPlan
ToolRequest
ToolResult
Evidence
ValidationResult
Finding
```

Study:

-   structured outputs;
-   tool definitions;
-   dependency injection;
-   model abstraction;
-   validation.

### Decision

Do not replace LangGraph initially.

Use Pydantic/Pydantic-style schemas throughout our system.

------------------------------------------------------------------------

# 5. OpenAI Agents SDK

Documentation:

-   https://openai.github.io/openai-agents-python/

Repository:

-   https://github.com/openai/openai-agents-python

Study:

-   tools;
-   handoffs;
-   guardrails;
-   sessions;
-   tracing;
-   structured outputs;
-   agent-as-tool patterns.

Use it primarily as an architectural comparison.

Our initial orchestration choice remains LangGraph.

------------------------------------------------------------------------

# 6. Autonomous Security Systems

## 6.1 Shannon --- MOST IMPORTANT SECURITY REFERENCE

Repository:

-   https://github.com/KeygraphHQ/shannon

### Why study it

Shannon is highly relevant to our exact problem:

``` text
source repository
+
running application
        ↓
recon
        ↓
source analysis
        ↓
attack hypothesis
        ↓
exploitation
        ↓
validation
        ↓
finding
```

Study the source tree and architecture carefully.

Focus on:

-   reconnaissance;
-   source-code analysis;
-   candidate generation;
-   agent prompts;
-   attack planning;
-   exploitation;
-   finding reconciliation;
-   evidence;
-   reporting;
-   state management;
-   local-model support;
-   tool integration.

### Important license note

The public repository is AGPL-3.0.

Use it primarily as architecture/code-reading prior art unless the
licensing model is deliberately compatible with the product.

Do not blindly copy source into a proprietary product.

------------------------------------------------------------------------

# 7. Strix

Repository:

-   https://github.com/usestrix/strix

Website:

-   https://www.strix.ai/open-source-pentesting

### Why study it

Useful for understanding:

-   autonomous runtime security testing;
-   agent tools;
-   skills;
-   HTTP interaction;
-   browser interaction;
-   terminal/tool execution;
-   Docker isolation;
-   findings;
-   local/self-hosted model support.

Study especially how the agent interacts with a real application.

Verify the license/version before reusing code.

------------------------------------------------------------------------

# 8. Source-Code Analysis

## 8.1 Semgrep

Repository:

-   https://github.com/semgrep/semgrep

Documentation:

-   https://semgrep.dev/docs/

### Study

-   rule syntax;
-   security rules;
-   taint analysis;
-   data flow;
-   framework support;
-   JSON output;
-   SARIF;
-   custom rules;
-   performance;
-   false positives.

### Our role for Semgrep

``` text
Repository
   ↓
Semgrep
   ↓
Candidate
```

A Semgrep result is NOT automatically a confirmed vulnerability.

------------------------------------------------------------------------

# 9. CodeQL

Website:

-   https://codeql.github.com/

Documentation:

-   https://codeql.github.com/docs/

Supported languages/frameworks:

-   https://codeql.github.com/docs/codeql-overview/supported-languages-and-frameworks/

### Study

-   query language;
-   data flow;
-   taint tracking;
-   sources/sinks;
-   framework modeling;
-   custom queries;
-   database generation;
-   performance;
-   licensing.

### Our architecture

Hide CodeQL behind:

``` text
SourceAnalyzer
```

so it remains replaceable/optional.

------------------------------------------------------------------------

# 10. tree-sitter

Repository:

-   https://github.com/tree-sitter/tree-sitter

### Why

We want language-independent source intelligence.

``` text
JavaScript
Python
Java
Go
PHP
...
   ↓
AST
   ↓
Security IR
```

Study:

-   parser architecture;
-   grammars;
-   incremental parsing;
-   query capabilities.

------------------------------------------------------------------------

# 11. ast-grep

Repository:

-   https://github.com/ast-grep/ast-grep

### Why

Useful for structural code search.

Potential use:

``` text
find dangerous API calls
find route declarations
find authentication middleware
find database sinks
find external HTTP calls
```

Study:

-   patterns;
-   AST matching;
-   multi-language support;
-   rule format.

------------------------------------------------------------------------

# 12. Runtime Testing

## 12.1 OWASP ZAP

Website:

-   https://www.zaproxy.org/

Automation Framework:

-   https://www.zaproxy.org/docs/automate/automation-framework/

### Study

-   spider;
-   AJAX spider;
-   passive scanner;
-   active scanner;
-   authentication;
-   session handling;
-   request modification;
-   scripting;
-   API import;
-   automation;
-   Docker;
-   output formats.

### Our architecture

``` text
Agent
  ↓
ZAP adapter
  ↓
ZAP
  ↓
runtime observations
```

ZAP is an execution/sensor component, not the reasoning engine.

------------------------------------------------------------------------

# 13. Nuclei

Repository:

-   https://github.com/projectdiscovery/nuclei

Documentation:

-   https://docs.projectdiscovery.io/tools/nuclei/overview

Templates:

-   https://github.com/projectdiscovery/nuclei-templates

### Study

-   HTTP templates;
-   matchers;
-   extractors;
-   workflows;
-   tags;
-   severity;
-   technology detection;
-   custom templates;
-   JSON output.

### Our use

``` text
known CVE
misconfiguration
exposure
technology-specific check
deterministic signature
```

Nuclei produces evidence/candidates; application-specific exploitability
may still require validation.

------------------------------------------------------------------------

# 14. Browser Automation

## Playwright

Documentation:

-   https://playwright.dev/docs/intro

### Study

-   browser contexts;
-   authentication;
-   cookies;
-   network interception;
-   screenshots;
-   HAR;
-   request/response capture;
-   multi-user sessions;
-   browser isolation.

### Our use

``` text
Agent
 ↓
typed browser tool
 ↓
Playwright
 ↓
application
```

Do not expose unrestricted browser debugging to the LLM.

------------------------------------------------------------------------

# 15. Security Methodology

## 15.1 OWASP Web Security Testing Guide

Repository:

-   https://github.com/OWASP/wstg

Website:

-   https://owasp.org/www-project-web-security-testing-guide/

### This should be one of our primary knowledge sources.

Study:

-   information gathering;
-   configuration;
-   authentication;
-   authorization;
-   session management;
-   input validation;
-   error handling;
-   cryptography;
-   business logic;
-   client-side testing;
-   API testing.

Map internal tests to WSTG identifiers.

Desired architecture:

``` text
Hypothesis
   ↓
WSTG test strategy
   ↓
runtime test
   ↓
proof criteria
```

------------------------------------------------------------------------

# 16. OWASP ASVS

Repository:

-   https://github.com/OWASP/ASVS

### Use for

-   security requirements;
-   verification criteria;
-   secure design expectations;
-   authentication/authorization requirements;
-   API requirements.

Conceptual distinction:

``` text
WSTG
= HOW TO TEST

ASVS
= WHAT SECURE BEHAVIOR SHOULD LOOK LIKE
```

------------------------------------------------------------------------

# 17. OWASP API Security Top 10

Website:

-   https://api-security.owasp.org/

### Important for

-   BOLA;
-   broken authentication;
-   broken object/property authorization;
-   unrestricted resource consumption;
-   SSRF;
-   business-flow abuse;
-   API inventory issues.

Our initial system should be heavily API-aware.

------------------------------------------------------------------------

# 18. CWE

Website:

-   https://cwe.mitre.org/

### Use for

Standard vulnerability classification.

Example:

``` text
BOLA
 ↓
CWE mapping
 ↓
Finding
```

------------------------------------------------------------------------

# 19. CAPEC

Website:

-   https://capec.mitre.org/

### Use later for

``` text
vulnerability
 ↓
attack pattern
 ↓
attack strategy
```

Useful when expanding beyond simple vulnerability signatures into
attack-chain reasoning.

------------------------------------------------------------------------

# 20. Benchmarks

## 20.1 OWASP Juice Shop

Repository:

-   https://github.com/juice-shop/juice-shop

### Use for

-   XSS;
-   SQL injection;
-   authentication;
-   authorization;
-   API;
-   business logic;
-   other common web vulnerabilities.

Create ground truth for each test.

------------------------------------------------------------------------

# 21. OWASP crAPI

Repository:

-   https://github.com/OWASP/crAPI

### Very important benchmark

Use for:

-   BOLA;
-   API authorization;
-   authentication;
-   SSRF;
-   injection;
-   JWT;
-   multi-step workflows;
-   API business logic.

This should be one of our first serious benchmark targets.

------------------------------------------------------------------------

# 22. XBOW Validation Benchmarks

Repository:

-   https://github.com/xbow-engineering/validation-benchmarks

### Study for

-   autonomous pentesting evaluation;
-   benchmark packaging;
-   validation methodology;
-   comparison with existing security agents.

The repository currently notes that the existing benchmark set is
saturated for modern models, so do not use it as our only evaluation
set.

------------------------------------------------------------------------

# 23. Build Our Own Benchmark

Eventually create:

``` text
benchmarks/
  applications/
  manifests/
  expected/
  runner/
```

Each benchmark:

``` text
source
commit
deployment
credentials
vulnerability
CWE
WSTG
endpoint
preconditions
proof recipe
expected evidence
difficulty
```

Measure:

``` text
precision
recall
F1
proof success
false positives
time
requests
LLM tokens
```

------------------------------------------------------------------------

# 24. Model Serving

## vLLM

Documentation:

-   https://docs.vllm.ai/

Repository:

-   https://github.com/vllm-project/vllm

### Study

-   OpenAI-compatible API;
-   structured outputs;
-   tool calling;
-   batching;
-   concurrency;
-   quantization;
-   memory management.

Target architecture:

``` text
Our LLM Gateway
       ↓
vLLM
       ↓
8B security model
```

Keep model serving replaceable.

------------------------------------------------------------------------

# 25. Model Selection

The framework should NOT hard-code one model.

Use:

``` text
LLMProvider
```

with adapters.

Example:

``` text
VLLMProvider
OpenAICompatibleProvider
OllamaProvider
```

The benchmark should compare models on the same security tasks.

Evaluate:

-   hypothesis accuracy;
-   test-plan quality;
-   response interpretation;
-   proof validation;
-   tool-call correctness;
-   token cost;
-   latency.

------------------------------------------------------------------------

# 26. Model Context Engineering

The model should usually receive:

``` text
endpoint
+
source slice
+
dataflow
+
auth context
+
security graph
+
runtime observations
+
WSTG/CWE knowledge
```

Not:

``` text
entire repository
```

This is especially important for an 8B model.

------------------------------------------------------------------------

# 27. MCP

Documentation:

-   https://modelcontextprotocol.io/

Repository/organization:

-   https://github.com/modelcontextprotocol

### Study for future use

Potential future tools:

``` text
MCP server
  ├── source search
  ├── ZAP
  ├── Nuclei
  ├── browser
  └── security knowledge
```

### Initial decision

Do not make MCP mandatory for v0.1.

Build our own strongly typed tool gateway first:

``` text
ToolRequest
ToolResult
```

Add MCP compatibility later if beneficial.

------------------------------------------------------------------------

# 28. Recommended Research Sequence

## Step 1

Read:

-   LangGraph
-   Shannon
-   Strix

Question:

> How should the investigation workflow operate?

## Step 2

Read:

-   WSTG
-   ASVS
-   API Security Top 10

Question:

> What exactly should we test?

## Step 3

Read:

-   Semgrep
-   CodeQL
-   tree-sitter
-   ast-grep

Question:

> How do we understand the source code?

## Step 4

Read:

-   ZAP
-   Nuclei
-   Playwright

Question:

> How do we interact with and test the running application?

## Step 5

Read:

-   Juice Shop
-   crAPI
-   XBOW

Question:

> How do we prove that our system actually works?

## Step 6

Read:

-   vLLM
-   PydanticAI
-   OpenAI Agents SDK
-   MCP

Question:

> How do we optimize model serving, typing, and future interoperability?

------------------------------------------------------------------------

# 29. Three Projects to Study Line-by-Line

If engineering time is limited, prioritize:

## 1. Shannon

Question:

> How does an autonomous security investigator combine source analysis
> and exploitation?

## 2. Strix

Question:

> How does an agent actually interact with a running web application?

## 3. LangGraph

Question:

> How do we make our investigation stateful, bounded, resumable, and
> debuggable?

Then combine:

``` text
Shannon
+
Strix
+
LangGraph
+
OWASP WSTG
+
Semgrep/CodeQL
+
ZAP/Nuclei
+
our Security Graph
```

------------------------------------------------------------------------

# 30. What NOT to Copy Blindly

Do not assume an existing project is automatically suitable for our
product.

Check:

``` text
license
dependencies
model assumptions
tool execution
sandboxing
security boundaries
false-positive behavior
state persistence
benchmark quality
```

In particular:

-   Shannon: study deeply; check AGPL obligations.
-   Strix: verify version/license before reuse.
-   Semgrep/CodeQL: verify exact features and licenses we deploy.
-   Nuclei templates: understand template licensing/provenance.
-   OWASP materials: respect their respective licenses.

------------------------------------------------------------------------

# 31. Reference-to-System Mapping

  Reference             What we learn                  Where it influences our system
  --------------------- ------------------------------ --------------------------------
  LangGraph             Workflow/state                 `orchestration/`
  PydanticAI            Typed agents                   `agents/`, schemas
  OpenAI Agents SDK     Tools/guardrails/tracing       design comparison
  Shannon               Autonomous security workflow   overall architecture
  Strix                 Runtime agent execution        executor/tools
  Semgrep               SAST                           candidate engine
  CodeQL                Deep dataflow                  source engine
  tree-sitter           Parsing                        source engine
  ast-grep              Structural search              source engine
  ZAP                   DAST                           runtime engine
  Nuclei                deterministic checks           candidate engine
  Playwright            Browser                        runtime tools
  WSTG                  Testing methodology            knowledge/test planner
  ASVS                  Security requirements          validation
  API Security Top 10   API threat coverage            API tests
  CWE                   Classification                 findings
  CAPEC                 Attack patterns                future reasoning
  Juice Shop            Web benchmark                  evaluation
  crAPI                 API benchmark                  evaluation
  XBOW                  Agent benchmark methodology    evaluation
  vLLM                  Model serving                  inference
  MCP                   Future interoperability        future tools

------------------------------------------------------------------------

# 32. Final Reference Architecture

The references should ultimately feed this system:

``` text
                 SECURITY KNOWLEDGE
            WSTG / ASVS / CWE / CAPEC
                       |
                       v
SOURCE               SECURITY              RUNTIME
TOOLS                GRAPH                TOOLS
  |                     |                    |
  |                     |                    |
Semgrep              routes                ZAP
CodeQL               auth                  Nuclei
tree-sitter          dataflow              HTTPX
ast-grep             sinks                 Playwright
  |                     |                    |
  +---------------------+--------------------+
                        |
                        v
                 CANDIDATE ENGINE
                        |
                        v
                 LANGGRAPH WORKFLOW
                        |
             +----------+----------+
             |                     |
             v                     v
        8B Hypothesis         8B Planner
             |                     |
             +----------+----------+
                        |
                        v
                   TOOL GATEWAY
                        |
                        v
                     EVIDENCE
                        |
                        v
                  8B VALIDATOR
                        |
                 +------+------+
                 |             |
                 v             v
             CONFIRMED       REJECTED
                 |
                 v
               FINDING
```

The most important lesson from all these references is:

> **Do not try to reproduce the entire security ecosystem inside the
> LLM.**

Use mature security tools for deterministic work, use LangGraph to
orchestrate the investigation, use the 8B model for security reasoning,
and make **evidence/proof validation** the final authority.
