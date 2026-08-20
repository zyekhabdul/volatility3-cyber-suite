"""
threat_scorer.py — Advanced Heuristic Threat Scoring Engine for eBPF Programs.
Optimized for high-throughput evaluation using O(1) dictionary lookups, modern helpers, and compound risk rules.
"""

from typing import List, Dict, Any, Tuple, Final

# Helper function ID mapping (Linux Kernel eBPF Helper IDs up to Linux 6.x)
HIGH_RISK_HELPERS: Final[Dict[int, Tuple[str, str]]] = {
    36: ("bpf_probe_write_user", "Overwrites user-space memory of live processes (Process Injection / Patching)"),
    58: ("bpf_override_return", "Overrides syscall return codes (Syscall Hijacking / File & Process Hiding)"),
    166: ("bpf_sys_bpf", "Executes bpf() syscall from within eBPF (Nested / Dynamic eBPF loading)"),
    109: ("bpf_send_signal", "Sends signals to processes to terminate or manipulate execution"),
    170: ("bpf_send_signal_thread", "Sends signals to specific threads"),
    200: ("bpf_rcu_read_lock", "Manipulates RCU locks during kernel traversal"),
    167: ("bpf_kallsyms_lookup_name", "Resolves dynamic kernel symbols at runtime (Kernel Symbol Reconnaissance)"),
    49: ("bpf_setsockopt", "Manipulates socket parameters (Socket Redirection & Traffic Modification)"),
}

MEDIUM_RISK_HELPERS: Final[Dict[int, Tuple[str, str]]] = {
    6: ("bpf_trace_printk", "Outputs debug messages to trace pipe (Information Leakage)"),
    113: ("bpf_probe_read_kernel", "Reads arbitrary kernel memory addresses"),
    114: ("bpf_probe_read_user", "Reads arbitrary user-space memory addresses"),
    115: ("bpf_probe_read_kernel_str", "Reads strings directly from kernel memory space"),
    116: ("bpf_probe_read_user_str", "Reads strings directly from user memory space"),
    16: ("bpf_get_current_pid_tgid", "Queries PID/TGID context"),
    25: ("bpf_probe_read", "Legacy arbitrary memory read helper"),
    130: ("bpf_ringbuf_reserve", "Reserves space in ring buffer for stealth data exfiltration"),
}


class ThreatScorer:
    """Calculates risk score and severity for enumerated eBPF programs with O(1) lookups and compound weighting."""

    __slots__ = ()

    @staticmethod
    def evaluate_program(prog_type: str, helper_ids: List[int], tag: str = "", name: str = "") -> Tuple[int, str, List[Dict[str, str]]]:
        """
        Evaluates an eBPF program given its type, used helper function IDs, and metadata.

        Returns:
            Tuple[score (0-100), risk_level ("CRITICAL"|"HIGH"|"MEDIUM"|"LOW"), findings]
        """
        score = 0
        findings = []

        # 1. Evaluate Helper Functions via fast dictionary lookups
        for helper_id in helper_ids:
            high_info = HIGH_RISK_HELPERS.get(helper_id)
            if high_info:
                h_name, desc = high_info
                score += 35
                findings.append({
                    "type": "HIGH_RISK_HELPER",
                    "helper": f"{h_name} (ID: {helper_id})",
                    "description": desc
                })
                continue

            med_info = MEDIUM_RISK_HELPERS.get(helper_id)
            if med_info:
                h_name, desc = med_info
                score += 10
                findings.append({
                    "type": "MEDIUM_RISK_HELPER",
                    "helper": f"{h_name} (ID: {helper_id})",
                    "description": desc
                })

        # 2. Evaluate Program Attachment Type Risk
        prog_type_upper = str(prog_type).upper()
        if "KPROBE" in prog_type_upper or "KRETPROBE" in prog_type_upper:
            score += 15
            findings.append({
                "type": "SENSITIVE_ATTACHMENT",
                "description": "Program attached to Kprobe/Kretprobe (Kernel Function Hooking)"
            })
        elif "FENTRY" in prog_type_upper or "FEXIT" in prog_type_upper or "TRACING" in prog_type_upper:
            score += 20
            findings.append({
                "type": "SENSITIVE_ATTACHMENT",
                "description": "Program attached to Fentry/Fexit (Kernel Function Modification/Monitoring)"
            })
        elif "XDP" in prog_type_upper or "SCHED_CLS" in prog_type_upper:
            score += 10
            findings.append({
                "type": "NETWORK_HOOK",
                "description": "Program hooked to raw network interfaces (Traffic Sniffing / Packet Modification)"
            })
        elif "LSM" in prog_type_upper:
            score += 25
            findings.append({
                "type": "LSM_HOOK",
                "description": "Program hooked to Linux Security Module (Security Bypass Risk)"
            })

        # 3. Anonymous / Unnamed Program Check (Stealth Indicator)
        if not name or not name.strip() or name == "N/A":
            score += 15
            findings.append({
                "type": "ANONYMOUS_PROGRAM",
                "description": "Program lacks a registered name in bpf_prog_aux (Stealth Indicator)"
            })
        elif any(susp in name.lower() for susp in ["rootkit", "stealth", "hide", "backdoor", "hook", "inject"]):
            score += 25
            findings.append({
                "type": "SUSPICIOUS_NAME_KEYWORD",
                "description": f"Program name '{name}' matches suspicious heuristic pattern"
            })

        # 4. COMPOUND RISK RULE: Active Process Memory Injection (bpf_probe_write_user + KPROBE/SYSCALL)
        if 36 in helper_ids and ("KPROBE" in prog_type_upper or "SYSCALL" in prog_type_upper or "TRACING" in prog_type_upper):
            score = 100
            findings.append({
                "type": "COMPOUND_THREAT_MALWARE",
                "description": "CONFIRMED PROCESS INJECTION ROOTKIT: Program uses bpf_probe_write_user on execution paths"
            })

        # Cap score between 0 and 100
        final_score = min(100, max(0, score))

        # Categorize Severity Level
        if final_score >= 70:
            severity = "CRITICAL"
        elif final_score >= 45:
            severity = "HIGH"
        elif final_score >= 20:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        return final_score, severity, findings
