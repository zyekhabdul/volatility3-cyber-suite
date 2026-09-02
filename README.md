# Volatility 3 Cyber Suite (`vol3-suite`)

```
================================================================================
  __     ______  _      _____     ______   ____  ____  ____  ____ _____ _____ 
  \ \   / / __ \| |    |___ /    / / ___| / ___|| __ )|  _ \| __ )_   _| ____|
   \ \ / / |  | | |      |_ \   / /\___ \| |    |  _ \|  _ \|  _ \ | | |  _|  
    \ V /| |__| | |___  ___) | / /  ___) | |___ | |_) | |_) | |_) || | | |___ 
     \_/  \____/|_____||____/ /_/  |____/ \____||____/|____/|____/ |_| |_____|
================================================================================
       UNIFIED MEMORY FORENSICS • eBPF ROOTKIT HUNTING • AI INCIDENT TRIAGE
```

[![PyPI Version](https://img.shields.io/pypi/v/vol3-suite.svg)](https://pypi.org/project/vol3-suite/)
[![PyPI Downloads](https://img.shields.io/pypi/dm/vol3-suite.svg)](https://pypi.org/project/vol3-suite/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python Version](https://img.shields.io/badge/Python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue)](pyproject.toml)
[![Tests: 22/22 Passing](https://img.shields.io/badge/Tests-22%2F22%20PASS-brightgreen)](tests/)
[![Architecture: Zero-Dependency](https://img.shields.io/badge/Architecture-Zero--Dependency-success)](#architecture)
[![Style: Strict No-Emoji](https://img.shields.io/badge/Aesthetic-Strict%20No--Emoji-informational)](#philosophy)

**Volatility 3 Cyber Suite (`vol3-suite`)** is an enterprise-grade digital forensics and incident response (DFIR) framework. It consolidates advanced Volatility 3 memory triage, kernel-level eBPF rootkit detection, heuristic memory injection hunting, and automated LLM-assisted threat reporting into a single unified CLI and Python library.

---

## [ 1. ARCHITECTURAL OVERVIEW ]

```
+--------------------------------------------------------------------------------+
|                             INCIDENT INGESTION LAYER                           |
|  +-----------------------------+             +------------------------------+  |
|  |  Live Memory Dump (.raw)    |             |  Pre-extracted Logs (*.json) |  |
|  +--------------+--------------+             +--------------+---------------+  |
+-----------------|-------------------------------------------|------------------+
                  |                                           |
                  v                                           v
+--------------------------------------------------------------------------------+
|                         VOLATILITY 3 RUNNER & TELEMETRY                        |
|  +--------------------------------------------------------------------------+  |
|  |  ForensicTelemetry (PsList, Malfind, NetScan, CmdLine, eBPF, Memfd)      |  |
|  +--------------------------------------------------------------------------+  |
+-----------------|-------------------------------------------|------------------+
                  |                                           |
                  v                                           v
+------------------------------------+     +-------------------------------------+
|    MEMORY ANOMALY TRIAGE ENGINE    |     |      eBPF ROOTKIT HUNTING ENGINE    |
|  • Direct Syscalls / API Hashing   |     |  • O(1) BPF Helper Threat Scorer    |
|  • Sleep Obfuscation (Ekko/Kronos) |     |  • Radix Tree & XArray prog_idr     |
|  • Go C2 Implants & Memfd Injection|     |  • JIT Executable Page Carver       |
|  • LSASS Process Injection Triage  |     |  • Struct_ops LSM & Fops Hijack Aud |
+-----------------+------------------+     +------------------+------------------+
                  |                                           |
                  +---------------------+---------------------+
                                        |
                                        v
+--------------------------------------------------------------------------------+
|                     CORRELATION & THREAT SCORING ENGINE                        |
|  • Cross-Plugin PID & Category Correlator                                      |
|  • MITRE ATT&CK Matrix Mapper (T1055, T1014, T1027, T1620, T1003, T1071)       |
|  • Deterministic Scoring (0-100) & AI Summary (Gemini / OpenAI / Ollama)       |
+---------------------------------------+----------------------------------------+
                                        |
                                        v
+--------------------------------------------------------------------------------+
|                              MULTI-FORMAT OUTPUT                               |
|   [ Markdown Report ]     [ Interactive HTML ]     [ SIEM JSON ]     [ STIX 2.1 ]
+--------------------------------------------------------------------------------+
```

---

## [ 2. CORE CAPABILITIES ]

### A. Advanced Memory Anomaly Triage (`vol3_suite.triage`)
- **Direct Syscall & API Hashing Evasion**: Scans unbacked memory segments for raw `syscall`, `sysenter`, or ROR13 hashing routines designed to bypass user-mode EDR hooks.
- **Sleep Obfuscation Detection**: Identifies VAD permission flips (`PAGE_NOACCESS`, `PAGE_READWRITE`) and ROP timers characteristic of Ekko, Foliage, and Kronos C2 loaders.
- **Go-Malware Runtime Reconstruction**: Identifies compiled Golang implants in memory via runtime symbol tables and build metadata (`runtime.main`, `go.buildid`).
- **Linux Fileless & `memfd_create` Hunting**: Identifies memory-only payloads executing from volatile memory descriptors (`/dev/shm`, `memfd:`).
- **LSASS Credential Access Auditing**: Correlates injected threads and outbound connections touching `lsass.exe`.

### B. eBPF Rootkit Hunting & Kernel Forensics (`vol3_suite.ebpf`)
- **O(1) Threat Scorer**: Analyzes BPF helper function IDs with compound rules (e.g. `bpf_probe_write_user` + Kprobe attachment = Critical Risk).
- **IDR & XArray Navigator**: Traverses the Linux kernel's global `prog_idr` structure across Linux 4.x, 5.x, and 6.x kernels.
- **Deep JIT Memory Carver**: Scans raw kernel executable pages for orphaned or unlinked JIT bytecode using 16-byte aligned instruction stepping and `bpf_binary_header` validation.
- **Struct_ops & File Operations Auditor**: Audits `file_operations`, `seq_operations`, and `bpf_struct_ops` tables for stealth LSM or procfs hooking.
- **Ring Buffer Telemetry Carver**: Recovers exfiltrated keystrokes, credentials, and network packets from active `BPF_MAP_TYPE_RINGBUF` allocations.

### C. Multi-Format SIEM & Threat Intel Export (`vol3_suite.core.reporter`)
- **GitHub Markdown (`report.md`)**: High-signal report formatted with tables and evidence proofs.
- **Standalone HTML Dashboard (`report.html`)**: Self-contained incident dashboard with zero external CDN dependencies.
- **Structured JSON (`report.json`)**: Machine-readable telemetry for SIEM and SOAR automation.
- **STIX 2.1 Bundle (`stix_indicators.json`)**: Indicator, Malware, and Relationship objects ready for MISP and OpenCTI ingestion.

---

## [ 3. INSTALLATION ]

### Standard PyPI Installation
```bash
# Core CLI & Python Library
pip install vol3-suite

# Full Forensic Suite (with optional Capstone disassembler & Volatility 3)
pip install "vol3-suite[full]"
```

### From Source
```bash
git clone https://github.com/zyekhabdul/volatility3-cyber-suite.git
cd volatility3-cyber-suite
pip install -e ".[full]"
```

---

## [ 4. COMMAND LINE USAGE ]

### 1. Memory Dump Triage (`vol3-suite triage`)

```bash
# Analyze a live memory dump using Volatility 3
vol3-suite triage -f /path/to/memory.raw --os windows -o ./reports

# Analyze pre-extracted Volatility JSON logs (Offline Mode)
vol3-suite triage -l /path/to/vol_logs/ -o ./reports

# Enrich report with Gemini or OpenAI LLM summary
export GEMINI_API_KEY="your_api_key_here"
vol3-suite triage -l ./logs --ai-provider gemini -o ./reports
```

### 2. Standalone eBPF Rootkit Hunting (`vol3-suite ebpf`)

```bash
# Carve unlinked eBPF JIT programs from raw RAM buffer
vol3-suite ebpf -f /path/to/kernel_mem.dmp --carve --export stix -o ./ebpf_threats.json

# Run built-in self-test evaluation
vol3-suite ebpf
```

### 3. Volatility 3 Plugin Integration

Load the plugin directly within your standard Volatility 3 environment:
```bash
vol -p /path/to/volatility3-cyber-suite/vol3_suite/plugins -f memory.raw linux.ebpf_detector.EbpfDetector
```

---

## [ 5. PROGRAMMATIC PYTHON API ]

```python
from vol3_suite import ForensicTelemetry, ForensicAnalyzer, ReportGenerator

# 1. Construct or load forensic telemetry
telemetry = ForensicTelemetry(
    malfind=[{"PID": 4096, "Process": "svchost.exe", "Protection": "PAGE_EXECUTE_READWRITE"}],
    netscan=[{"PID": 4096, "Owner": "svchost.exe", "ForeignAddr": "198.51.100.25", "ForeignPort": 4444}],
    cmdline=[{"PID": 4096, "Process": "svchost.exe", "Args": "powershell.exe -enc ..."}]
)

# 2. Run heuristic and AI analysis
analyzer = ForensicAnalyzer(ai_provider="heuristic")
result = analyzer.analyze(telemetry)

print(f"Threat Score: {result.threat_score}/100 ([ {result.risk_level} ])")
print(f"MITRE Techniques: {result.mitre_techniques}")

# 3. Generate reports
reporter = ReportGenerator(result)
reporter.generate_markdown("./report.md")
reporter.generate_json("./report.json")
reporter.generate_stix("./stix_bundle.json")
```

---

## [ 6. VERIFICATION & QUALITY GATES ]

Run the test suite:
```bash
python3 -m pytest -v
```

Output:
```
============================== test session starts ==============================
collected 22 items

tests/test_cli.py::TestCLI::test_ebpf_self_test PASSED                   [  4%]
tests/test_cli.py::TestCLI::test_triage_log_dir PASSED                   [  9%]
tests/test_ebpf.py::TestEbpfThreatScorer::test_compound_threat_rule PASSED [ 13%]
tests/test_ebpf.py::TestEbpfThreatScorer::test_high_risk_helpers PASSED  [ 18%]
tests/test_ebpf.py::TestEbpfThreatScorer::test_stealth_metadata_rule PASSED [ 22%]
tests/test_ebpf.py::TestEbpfHookAnalyzer::test_inspect_attachment PASSED [ 27%]
tests/test_ebpf.py::TestEbpfHookAnalyzer::test_resolve_prog_type PASSED  [ 31%]
tests/test_ebpf.py::TestDisasmEngine::test_disasm_fallback_or_execution PASSED [ 36%]
tests/test_ebpf.py::TestJitCarver::test_scan_memory_buffer PASSED        [ 40%]
tests/test_ebpf.py::TestFopsChecker::test_audit_seq_ops_clean PASSED     [ 45%]
tests/test_ebpf.py::TestFopsChecker::test_audit_seq_ops_hooked PASSED    [ 50%]
tests/test_ebpf.py::TestMapInspector::test_inspect_map_metadata PASSED   [ 54%]
tests/test_ebpf.py::TestMapInspector::test_resolve_map_type PASSED       [ 59%]
tests/test_ebpf.py::TestRingbufCarver::test_carve_ringbuffer_map PASSED  [ 63%]
tests/test_ebpf.py::TestStructOpsAuditor::test_audit_struct_ops PASSED   [ 68%]
tests/test_reporter.py::TestReportGenerator::test_generate_html PASSED   [ 72%]
tests/test_reporter.py::TestReportGenerator::test_generate_json PASSED   [ 77%]
tests/test_reporter.py::TestReportGenerator::test_generate_markdown PASSED [ 81%]
tests/test_reporter.py::TestReportGenerator::test_generate_stix PASSED   [ 86%]
tests/test_triage.py::TestForensicAnalyzer::test_analyzer_clean_telemetry PASSED [ 90%]
tests/test_triage.py::TestForensicAnalyzer::test_analyzer_detects_linux_fileless_memfd PASSED [ 95%]
tests/test_triage.py::TestForensicAnalyzer::test_analyzer_detects_malfind_and_network PASSED [100%]

============================== 22 passed in 0.17s ==============================
```

---

## [ 7. LICENSE ]

Released under the **MIT License**. Created by [Zyekh Abdul Qadir Jailani](https://zyekh.com).
