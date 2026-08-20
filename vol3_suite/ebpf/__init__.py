"""
ebpf — eBPF Rootkit Detection, JIT Carving, and Kernel Operations Auditing Engine.
"""

from .threat_scorer import ThreatScorer
from .hook_analyzer import HookAnalyzer
from .disasm_engine import DisasmEngine
from .jit_carver import JitCarver
from .fops_checker import FopsChecker
from .radix_tree import ProgIdrNavigator
from .map_inspector import MapInspector
from .ringbuf_carver import RingbufCarver
from .struct_ops_auditor import StructOpsAuditor

__all__ = [
    "ThreatScorer",
    "HookAnalyzer",
    "DisasmEngine",
    "JitCarver",
    "FopsChecker",
    "ProgIdrNavigator",
    "MapInspector",
    "RingbufCarver",
    "StructOpsAuditor",
]
