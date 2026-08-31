# 🌐 Public Benchmarks Extension Evaluation Report

**Date:** 2026-08-30 09:44:56  
**Evaluation Scope:** NIST Juliet Expansion, DARPA CGC MultiOS, Historical CVE Datasets (LibTIFF).

---

## 🏆 Results Table

| Target ID | Suite | CWE | Description | Status | Winning Agent | Hardening | Time (s) |
| :--- | :--- | :--- | :--- | :---: | :---: | :---: | :---: |
| **SYNTH-TIFF-CROP-OOB** | CVE-inspired synthetic | CWE-125 | Crop-box out-of-bounds read: the copy loop indexes the source image by the requested box dimensions without checking them against the image's own width/height. Modelled on the shape of CVE-2016-5321 (LibTIFF); NOT LibTIFF code and NOT that CVE. | **PATCHED** | beta | SURVIVED | 5.65 |
| **SYNTH-SERVICE-STACK-OVERFLOW** | CVE-inspired synthetic | CWE-121 | Unbounded strcpy of attacker input into a fixed 64-byte packet body, overflowing the enclosing stack struct. Written in the style of a DARPA CGC service; NOT the CGC CADET_00001 challenge binary. | **PATCHED** | alpha | SURVIVED | 5.69 |

---

---

## 🔬 Per-Target Verification Notes

*Generated from this run's recorded outcomes.*


**SYNTH-TIFF-CROP-OOB**

- Pre-flight: PoV reproduces on the original; gate is valid
- Outcome: **PATCHED** (agent: beta)
- Hardening: **SURVIVED**
    - differential testing not applicable (contract=restrict): an input-validation fix legitimately narrows the accepted input domain, so rejecting inputs the original accepted is the remediation working, not a regression; the regression gate checks the intended behaviour instead; re-fuzz: clean

**SYNTH-SERVICE-STACK-OVERFLOW**

- Pre-flight: PoV reproduces on the original; gate is valid
- Outcome: **PATCHED** (agent: alpha)
- Hardening: **SURVIVED**
    - differential(25 inputs): behaviour preserved

---

**Execution Cost:** $0.0018 USD  
**Total Evaluation Time:** 40.19s  
