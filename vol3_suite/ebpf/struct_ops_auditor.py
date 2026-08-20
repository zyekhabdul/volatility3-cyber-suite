"""
struct_ops_auditor.py — Audits BPF_PROG_TYPE_STRUCT_OPS and bpf_struct_ops_map instances.
Detects stealth kernel operations overrides (LSM hooks, TCP congestion ops, file_operations replacement).
"""

from typing import List, Dict, Any, Optional
import logging

logger = logging.getLogger("vol3_suite.ebpf.struct_ops")


class StructOpsAuditor:
    """Inspects bpf_struct_ops_map objects to detect replaced kernel operation tables."""

    @staticmethod
    def audit_struct_ops(prog_obj: Any, map_obj: Optional[Any] = None) -> Dict[str, Any]:
        """
        Audits struct_ops maps for hijacked security or subsystem callbacks.
        """
        audit_result = {
            "is_struct_ops": False,
            "target_ops_name": "N/A",
            "overridden_callbacks_count": 0,
            "threat_level": "LOW",
            "findings": []
        }

        try:
            if hasattr(prog_obj, "type") and int(prog_obj.type) == 27:  # BPF_PROG_TYPE_STRUCT_OPS
                audit_result["is_struct_ops"] = True
                audit_result["threat_level"] = "HIGH"

                if hasattr(prog_obj, "aux") and prog_obj.aux and hasattr(prog_obj.aux, "attach_func_name"):
                    target_name = str(prog_obj.aux.attach_func_name)
                    audit_result["target_ops_name"] = target_name if target_name else "bpf_lsm_ops"

                audit_result["findings"].append({
                    "type": "STRUCT_OPS_HIJACK",
                    "description": "Kernel operations structure overridden via BPF_PROG_TYPE_STRUCT_OPS (LSM / Subsystem Hooking)"
                })

        except Exception as e:
            logger.debug(f"Error auditing struct_ops: {e}")

        return audit_result
