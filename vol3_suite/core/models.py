"""
models.py — Common Dataclasses and Data Models for Memory Forensics & Triage.
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field


@dataclass
class ForensicTelemetry:
    """Aggregates forensic telemetry extracted across multiple Volatility plugins."""
    pslist: List[Dict[str, Any]] = field(default_factory=list)
    psscan: List[Dict[str, Any]] = field(default_factory=list)
    pstree: List[Dict[str, Any]] = field(default_factory=list)
    cmdline: List[Dict[str, Any]] = field(default_factory=list)
    netscan: List[Dict[str, Any]] = field(default_factory=list)
    netstat: List[Dict[str, Any]] = field(default_factory=list)
    malfind: List[Dict[str, Any]] = field(default_factory=list)
    dlllist: List[Dict[str, Any]] = field(default_factory=list)
    handles: List[Dict[str, Any]] = field(default_factory=list)
    ldrmodules: List[Dict[str, Any]] = field(default_factory=list)
    linux_pslist: List[Dict[str, Any]] = field(default_factory=list)
    linux_malfind: List[Dict[str, Any]] = field(default_factory=list)
    linux_check_syscall: List[Dict[str, Any]] = field(default_factory=list)
    linux_ebpf: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class AnomalyFinding:
    """Represents a single correlated anomaly detected during memory triage."""
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    category: str  # Injection, Evasion, Network, ProcessTree, LinuxFileless, CredentialAccess, eBPFRootkit
    title: str
    description: str
    evidence_proof: str = ""  # Offset, PID, hex, or raw line for empirical verification
    pid: Optional[int] = None
    memory_offset: Optional[str] = None
    correlated_findings: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TriageAnalysisResult:
    """Encapsulates the final incident triage verdict, threat score, and remediation roadmap."""
    threat_score: int  # 0 to 100
    risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    findings: List[AnomalyFinding] = field(default_factory=list)
    ai_summary: str = ""
    mitre_techniques: List[str] = field(default_factory=list)
    remediation_steps: List[str] = field(default_factory=list)


@dataclass
class EbpfProgramFinding:
    """Represents an eBPF program identified or carved from Linux kernel memory."""
    prog_id: int
    name: str
    prog_type: str
    score: int
    severity: str
    attached_func: str = "N/A"
    jit_address: str = "0x0"
    helper_ids: List[int] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)
    disasm_preview: List[Dict[str, Any]] = field(default_factory=list)
