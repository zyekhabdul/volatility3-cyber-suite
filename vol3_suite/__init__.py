"""
volatility3-cyber-suite
Unified Memory Forensics, eBPF Rootkit Detection, and AI-Driven Incident Triage Suite.
"""

__version__ = "2.0.0"
__author__ = "Zyekh Abdul Qadir Jailani"
__license__ = "MIT"

from .core.models import ForensicTelemetry, AnomalyFinding, TriageAnalysisResult
from .core.runner import VolatilityRunner
from .core.reporter import ReportGenerator
from .triage.analyzer import ForensicAnalyzer
from .ebpf.threat_scorer import ThreatScorer
from .ebpf.hook_analyzer import HookAnalyzer
from .ebpf.jit_carver import JitCarver
from .ebpf.disasm_engine import DisasmEngine

__all__ = [
    "__version__",
    "ForensicTelemetry",
    "AnomalyFinding",
    "TriageAnalysisResult",
    "VolatilityRunner",
    "ReportGenerator",
    "ForensicAnalyzer",
    "ThreatScorer",
    "HookAnalyzer",
    "JitCarver",
    "DisasmEngine",
]
