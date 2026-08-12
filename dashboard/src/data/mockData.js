export const MOCK_KPIS = {
  targetsScanned: "37/37",
  passRate: "100%",
  povProven: "21/21",
  hardening: "34/34",
  formalProofs: "14",
  computeCost: "$0.0521",
  avgWallTime: "794s",
  unitTests: "102/102"
};

export const MOCK_SYSTEM_STATUS = [
  { name: "Semgrep Static Analysis", version: "v1.172.0", ruleset: "p/security-audit", status: "Active", health: 100 },
  { name: "LLVM clang Compiler", version: "v22.0.0", flags: "ASan + UBSan", status: "Active", health: 100 },
  { name: "CBMC Formal Verifier", version: "v6.10.0", mode: "Bounded SMT Proofs", status: "Active", health: 100 },
  { name: "libFuzzer & AFL++ Engine", version: "v5.02c", mode: "Coverage Guided", status: "Active", health: 100 }
];

export const MOCK_VULNERABILITIES = [
  {
    id: "CVE-2019-11834-CJSON",
    title: "cJSON parse_string Heap Over-read",
    cwe: "CWE-125",
    severity: "CRITICAL",
    targetFile: "benchmark_workspace/real_cve_trees/cJSON.c:660",
    date: "2026-08-12",
    winningAgent: "Agent Gamma (SARIF Patcher)",
    drvGates: "5/5 PASS",
    cbmcStatus: "PROVEN (unwind=20)",
    status: "PATCHED",
    executionTime: "65.6s",
    cost: "$0.0188"
  },
  {
    id: "CVE-2019-11835-CJSON",
    title: "cJSON_Minify Unterminated Comment NUL Step-past",
    cwe: "CWE-125",
    severity: "CRITICAL",
    targetFile: "benchmark_workspace/real_cve_trees/cJSON.c:2642",
    date: "2026-08-12",
    winningAgent: "Agent Beta (Minimalist)",
    drvGates: "5/5 PASS",
    cbmcStatus: "PROVEN (unwind=16)",
    status: "PATCHED",
    executionTime: "54.2s",
    cost: "$0.0142"
  },
  {
    id: "GH800-CJSON-PARSE-OBJECT",
    title: "cJSON parse_object Trailing Comma Length-Bounded OOB",
    cwe: "CWE-125",
    severity: "HIGH",
    targetFile: "benchmark_workspace/real_cve_trees/cJSON.c:1420",
    date: "2026-08-12",
    winningAgent: "Agent Alpha (The Analyst)",
    drvGates: "5/5 PASS",
    cbmcStatus: "PROVEN (unwind=25)",
    status: "PATCHED",
    executionTime: "71.0s",
    cost: "$0.0195"
  },
  {
    id: "VANGUARD-01-BITFIELD",
    title: "Packed Bitfield Header Payload Overrun",
    cwe: "CWE-122",
    severity: "CRITICAL",
    targetFile: "tests/vanguard_nightmare/targets/01_bitfield_overflow.c",
    date: "2026-08-11",
    winningAgent: "Agent Beta (Minimalist)",
    drvGates: "5/5 PASS",
    cbmcStatus: "PROVEN (unwind=12)",
    status: "PATCHED",
    executionTime: "25.0s",
    cost: "$0.0051"
  },
  {
    id: "VANGUARD-04-RTOS-URI",
    title: "RTOS Custom URI Path Traversal",
    cwe: "CWE-22",
    severity: "HIGH",
    targetFile: "tests/vanguard_nightmare/targets/04_rtos_uri_traversal.c",
    date: "2026-08-11",
    winningAgent: "Agent Beta (Minimalist)",
    drvGates: "5/5 PASS",
    cbmcStatus: "PROVEN (restrict contract)",
    status: "PATCHED",
    executionTime: "24.1s",
    cost: "$0.0048"
  },
  {
    id: "SYN-11-OOB-MULTIDIM",
    title: "Out-of-Bounds Multidimensional Array Indexing",
    cwe: "CWE-125",
    severity: "MEDIUM",
    targetFile: "tests/demo_vulns/11_oob_multidim_array.c",
    date: "2026-08-11",
    winningAgent: "Agent Alpha (The Analyst)",
    drvGates: "5/5 PASS",
    cbmcStatus: "PROVEN (unwind=16)",
    status: "PATCHED",
    executionTime: "19.5s",
    cost: "$0.0039"
  }
];

export const MOCK_ORIGINAL_CODE = `static cJSON_bool parse_string(cJSON * const item, parse_buffer * const input_buffer)
{
    const unsigned char *input_pointer = buffer_at_offset(input_buffer) + 1;
    const unsigned char *input_end = buffer_at_offset(input_buffer) + 1;
    unsigned char *output_pointer = NULL;
    unsigned char *output_buffer = NULL;

    /* VULNERABLE CONDITION: dereferences *input_end BEFORE checking buffer bounds */
    while ((*input_end != '"') && ((size_t)(input_end - input_buffer->content) < input_buffer->length))
    {
        /* Process escape characters */
        if (*input_end == '\\\\')
        {
            input_end++;
        }
        input_end++;
    }

    if ((size_t)(input_end - input_buffer->content) >= input_buffer->length)
    {
        goto fail; /* Unterminated string */
    }

    return true;
fail:
    return false;
}`;

export const MOCK_PATCHED_CODE = `static cJSON_bool parse_string(cJSON * const item, parse_buffer * const input_buffer)
{
    const unsigned char *input_pointer = buffer_at_offset(input_buffer) + 1;
    const unsigned char *input_end = buffer_at_offset(input_buffer) + 1;
    unsigned char *output_pointer = NULL;
    unsigned char *output_buffer = NULL;

    /* VERIFIED FIX: short-circuit evaluation re-ordered; bounds check precedes dereference */
    while (((size_t)(input_end - input_buffer->content) < input_buffer->length) && (*input_end != '"'))
    {
        /* Process escape characters */
        if (*input_end == '\\\\')
        {
            input_end++;
        }
        input_end++;
    }

    if ((size_t)(input_end - input_buffer->content) >= input_buffer->length)
    {
        goto fail; /* Unterminated string */
    }

    return true;
fail:
    return false;
}`;

export const MOCK_MEMORY_PATTERNS = [
  {
    cwe: "CWE-125",
    crashClass: "heap-buffer-overflow",
    sourceTarget: "CVE-2019-11834-CJSON",
    confidence: 0.98,
    hardened: true,
    rootCause: "Boolean short-circuit evaluation order: dereference (*ptr != val) executed before bounds check (ptr < end)",
    fixStrategy: "Re-order while loop condition to evaluate length bounds check before dereferencing pointer",
    pitfalls: [
      "Special-casing NUL byte checks without validating length pointer",
      "Using non-atomic bounds increments inside macro expansion"
    ]
  },
  {
    cwe: "CWE-122",
    crashClass: "heap-buffer-overflow",
    sourceTarget: "VANGUARD-01-BITFIELD",
    confidence: 0.95,
    hardened: true,
    rootCause: "Payload length in packed bitfield header overruns fixed stack/heap allocation",
    fixStrategy: "AST-extracted typedef struct boundary enforcement before memcpy operation",
    pitfalls: [
      "Truncating bitfield values prior to comparison",
      "Omitting overflow checks on multi-part headers"
    ]
  },
  {
    cwe: "CWE-22",
    crashClass: "path-traversal",
    sourceTarget: "VANGUARD-04-RTOS-URI",
    confidence: 0.96,
    hardened: true,
    rootCause: "Custom rtos:// URI concatenated into storage root without sanitizing relative ../ elements",
    fixStrategy: "Enforce restrict contract rejecting leading or interleaved dot-dot traversal tokens",
    pitfalls: [
      "Single-pass string stripping allowing ....// bypass payloads",
      "Applying differential execution check to restrict contract targets"
    ]
  }
];
