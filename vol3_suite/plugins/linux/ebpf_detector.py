"""
ebpf_detector.py — Volatility 3 Plugin Interface Entrypoint.
Command usage:
  vol -f memory.img linux.ebpf_detector.EbpfDetector [--disassemble] [--scan-carve] [--dump-dir PATH]
"""

import os
import logging
from typing import List, Iterable, Tuple, Any

try:
    from volatility3.framework import interfaces, renderers
    from volatility3.framework.configuration import requirements
    from volatility3.framework.renderers import format_hints
    VOLATILITY_AVAILABLE = True
except ImportError:
    VOLATILITY_AVAILABLE = False
    interfaces = None
    renderers = None
    requirements = None
    format_hints = None

from ...ebpf.threat_scorer import ThreatScorer
from ...ebpf.hook_analyzer import HookAnalyzer
from ...ebpf.disasm_engine import DisasmEngine
from ...ebpf.fops_checker import FopsChecker
from ...ebpf.radix_tree import ProgIdrNavigator
from ...ebpf.jit_carver import JitCarver
from ...core.export_engine import ExportEngine

logger = logging.getLogger("vol3_suite.plugins.ebpf_detector")


class EbpfDetector(getattr(interfaces, "plugins", type("Dummy", (), {})) if VOLATILITY_AVAILABLE else object):
    """Detects loaded, hidden, or malicious eBPF programs and hooks from Linux memory dumps."""

    _required_framework_version = (2, 0, 0)
    _version = (2, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[Any]:
        if not VOLATILITY_AVAILABLE:
            return []
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel module",
                architectures=["Intel32", "Intel64", "ARM64"]
            ),
            requirements.BooleanRequirement(
                name="disassemble",
                description="Disassemble JIT-compiled native code using Capstone",
                default=False,
                optional=True
            ),
            requirements.BooleanRequirement(
                name="scan-carve",
                description="Perform deep JIT memory carving for unlinked eBPF rootkits",
                default=False,
                optional=True
            ),
            requirements.StringRequirement(
                name="dump-dir",
                description="Directory path to export raw eBPF bytecode",
                default=None,
                optional=True
            )
        ]

    def _generator(self):
        """Generator rendering forensic results in Volatility 3 tabular format."""
        if not VOLATILITY_AVAILABLE:
            logger.error("Volatility 3 framework is not installed.")
            return

        vmlinux = self.context.modules[self.config['kernel']]
        vmlinux_layer = vmlinux.layer_name
        symbol_table = vmlinux.symbol_table_name

        disasm = DisasmEngine()
        carver = JitCarver()
        navigator = ProgIdrNavigator(self.context, symbol_table)

        dump_dir = self.config.get("dump-dir", None)
        if dump_dir and not os.path.exists(dump_dir):
            try:
                os.makedirs(dump_dir, exist_ok=True)
            except Exception as e:
                logger.error(f"Failed to create dump-dir '{dump_dir}': {e}")

        prog_count = 0

        # 1. Walk kernel prog_idr structure
        for prog_id, bpf_prog in navigator.walk_idr(vmlinux_layer):
            prog_count += 1
            try:
                prog_name = "N/A"
                prog_type_str = "UNKNOWN"
                jit_addr = 0
                helper_ids = []

                if hasattr(bpf_prog, "aux") and bpf_prog.aux:
                    aux = bpf_prog.aux
                    if hasattr(aux, "name") and aux.name:
                        prog_name = str(aux.name)

                    if hasattr(aux, "used_helpers") and aux.used_helpers:
                        try:
                            helper_cnt = getattr(aux, "used_helper_cnt", 0)
                            for i in range(min(int(helper_cnt), 32)):
                                h_val = int(aux.used_helpers[i])
                                if h_val:
                                    helper_ids.append(h_val)
                        except Exception:
                            pass

                if hasattr(bpf_prog, "type"):
                    prog_type_str = HookAnalyzer.resolve_prog_type(int(bpf_prog.type))

                if hasattr(bpf_prog, "bpf_func"):
                    jit_addr = int(bpf_prog.bpf_func)

                score, severity, findings = ThreatScorer.evaluate_program(
                    prog_type=prog_type_str,
                    helper_ids=helper_ids,
                    name=prog_name
                )

                findings_desc = "; ".join([f["description"] for f in findings]) if findings else "Clean program"

                yield (
                    0,
                    (
                        int(prog_id),
                        prog_name,
                        prog_type_str,
                        format_hints.Hex(jit_addr),
                        f"{score}/100",
                        severity,
                        findings_desc
                    )
                )

            except Exception as e:
                logger.debug(f"Error evaluating prog {prog_id}: {e}")

    def run(self):
        if not VOLATILITY_AVAILABLE:
            raise RuntimeError("Volatility 3 framework not installed.")
        return renderers.TreeGrid([
            ("Prog ID", int),
            ("Name", str),
            ("Type", str),
            ("JIT Address", format_hints.Hex),
            ("Threat Score", str),
            ("Severity", str),
            ("Forensic Findings", str)
        ], self._generator())
