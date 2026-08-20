"""
hook_analyzer.py — Analyzes eBPF program attachment points & bpf_link structures.
Identifies kprobes, fentry/fexit, tracepoints, XDP, TC, SK_LOOKUP, and NETFILTER hooks.
"""

from typing import Dict, Any, Optional

PROG_TYPES = {
    1: "BPF_PROG_TYPE_SOCKET_FILTER",
    2: "BPF_PROG_TYPE_KPROBE",
    3: "BPF_PROG_TYPE_SCHED_ACT",
    4: "BPF_PROG_TYPE_SCHED_CLS",
    5: "BPF_PROG_TYPE_TRACEPOINT",
    6: "BPF_PROG_TYPE_XDP",
    7: "BPF_PROG_TYPE_PERF_EVENT",
    8: "BPF_PROG_TYPE_CGROUP_SKB",
    9: "BPF_PROG_TYPE_CGROUP_SOCK",
    10: "BPF_PROG_TYPE_LWT_IN",
    11: "BPF_PROG_TYPE_LWT_OUT",
    12: "BPF_PROG_TYPE_LWT_XMIT",
    13: "BPF_PROG_TYPE_SOCK_OPS",
    14: "BPF_PROG_TYPE_SK_SKB",
    15: "BPF_PROG_TYPE_CGROUP_DEVICE",
    16: "BPF_PROG_TYPE_SK_MSG",
    17: "BPF_PROG_TYPE_RAW_TRACEPOINT",
    18: "BPF_PROG_TYPE_CGROUP_SOCK_ADDR",
    19: "BPF_PROG_TYPE_LWT_SEG6LOCAL",
    20: "BPF_PROG_TYPE_LIRC_MODE2",
    21: "BPF_PROG_TYPE_SK_REUSEPORT",
    22: "BPF_PROG_TYPE_FLOW_DISSECTOR",
    23: "BPF_PROG_TYPE_CGROUP_SYSCTL",
    24: "BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE",
    25: "BPF_PROG_TYPE_CGROUP_SOCKOPT",
    26: "BPF_PROG_TYPE_TRACING",  # fentry / fexit / fmod_ret
    27: "BPF_PROG_TYPE_STRUCT_OPS",
    28: "BPF_PROG_TYPE_EXT",
    29: "BPF_PROG_TYPE_LSM",
    30: "BPF_PROG_TYPE_SK_LOOKUP",
    31: "BPF_PROG_TYPE_SYSCALL",
    32: "BPF_PROG_TYPE_NETFILTER",
}


class HookAnalyzer:
    """Resolves eBPF attachment targets, target symbols, and bpf_link objects."""

    @staticmethod
    def resolve_prog_type(type_id: int) -> str:
        """Converts raw integer bpf_prog_type enum to human-readable string."""
        return PROG_TYPES.get(type_id, f"UNKNOWN_TYPE_{type_id}")

    @staticmethod
    def inspect_attachment(bpf_prog: Any, context: Any = None, symbol_table: str = "") -> Dict[str, Any]:
        """
        Inspects bpf_prog_aux and bpf_link structures to locate target function names or devices.
        """
        details = {
            "attached_func": "N/A",
            "attach_type": "Direct Hook",
            "bpf_link_addr": None
        }

        try:
            if hasattr(bpf_prog, "aux") and bpf_prog.aux:
                aux = bpf_prog.aux
                if hasattr(aux, "attach_func_name") and aux.attach_func_name:
                    func_name = str(aux.attach_func_name)
                    details["attached_func"] = func_name if func_name else "N/A"
                elif hasattr(aux, "attach_btf_id") and aux.attach_btf_id:
                    details["attached_func"] = f"BTF_ID_{int(aux.attach_btf_id)}"

                if hasattr(aux, "link") and aux.link:
                    details["bpf_link_addr"] = hex(int(aux.link))

        except Exception:
            pass

        return details
