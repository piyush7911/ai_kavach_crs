# Where this matters in defence software

AI Kavach repairs memory-safety and input-handling defects in C, and proves each
repair with a replayed proof-of-vulnerability. That is the class of defect that
dominates the software defence systems actually run on.

| Weakness we handle | Where it lives in defence systems | Why automated, proven repair matters there |
|---|---|---|
| Out-of-bounds read/write (CWE-121/122/125/787) | Protocol parsers for tactical data links, radio and satellite message decoders, sensor-frame unpackers | One malformed frame from an adversary reaches the parser before any authentication. |
| Integer overflow into allocation size (CWE-190) | Length fields in binary message formats, image/telemetry decoders | Length arithmetic on attacker-supplied headers is the classic route to heap corruption. |
| Use-after-free / double free (CWE-416/415) | Long-running command-and-control services and message brokers with complex object lifetimes | Uptime pressure means patches must be small and provably correct. |
| NULL dereference (CWE-476) | Embedded controllers and firmware with no memory protection | A crash is a denial of service on equipment that cannot be rebooted in the field. |
| Off-by-one and string handling (CWE-193/120) | Legacy C in configuration and logging paths of embedded comms | Old code, few maintainers, high reuse. |

## What makes this suitable for that setting

- **Runs offline.** The whole pipeline runs on a laptop against a local model
  (for example `gemma4:12b`; its on-device speed and repair quality are still being measured). No source code leaves the
  machine.
- **Proof before trust.** A patch is accepted only after the original crash input
  no longer reproduces, benign behaviour is preserved, and hardening fails to
  falsify it. A patch that games the checks is caught by the verifier red-team
  layers (policy, gates, hardening) and the results are published as measured.
- **Evidence you can audit.** Every run directory is hash-manifested, with tool
  versions and a script that re-derives a verdict.

## Targets from this world

Candidate targets (an embedded protocol parser or a small firmware library) will be
chosen **by buildability first**, and any defect identifier will be checked against
the upstream advisory before it is named. None is named here yet.
