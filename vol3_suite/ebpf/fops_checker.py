"""
fops_checker.py — Procfs & Sysfs File Operations (`file_operations` / `seq_operations`)
Integrity Checker for detecting stealth hooks on `/sys/fs/bpf` and `/proc`.
"""

from typing import List, Dict, Any, Optional, Tuple


class FopsChecker:
    """Audits file_operations and seq_operations function pointers against kernel text section and module memory ranges."""

    @staticmethod
    def audit_seq_ops(seq_ops_obj: Any, stext_addr: int, etext_addr: int, module_ranges: Optional[List[Tuple[int, int]]] = None) -> List[Dict[str, Any]]:
        """
        Verifies that seq_operations pointers (start, next, stop, show) point within kernel _stext.._etext
        or valid loaded kernel module address ranges. Pointers outside indicate stealth function hijacking.
        """
        anomalies = []
        callbacks = ["start", "next", "stop", "show"]
        module_ranges = module_ranges or []

        for cb_name in callbacks:
            if hasattr(seq_ops_obj, cb_name):
                func_ptr = int(getattr(seq_ops_obj, cb_name))
                if func_ptr != 0:
                    in_core = stext_addr <= func_ptr <= etext_addr
                    in_module = any(m_start <= func_ptr <= m_end for m_start, m_end in module_ranges)

                    if not (in_core or in_module):
                        anomalies.append({
                            "callback": cb_name,
                            "address": hex(func_ptr),
                            "status": "HOOKED_OUT_OF_BOUNDS",
                            "description": f"{cb_name} pointer points outside valid kernel/module code bounds [{hex(stext_addr)} - {hex(etext_addr)}]"
                        })

        return anomalies
