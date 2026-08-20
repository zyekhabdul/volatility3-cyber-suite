"""
analyzer.py — Correlated Memory Forensics & AI Anomaly Triage Engine.
Performs cross-plugin correlation, heuristic scoring, MITRE ATT&CK mapping, and multi-provider AI enrichment.
"""

import os
import json
import urllib.request
import urllib.error
import logging
from typing import Dict, Any, List, Optional
from ..core.models import ForensicTelemetry, AnomalyFinding, TriageAnalysisResult

logger = logging.getLogger("vol3_suite.analyzer")


class ForensicAnalyzer:
    """Analyzes telemetry for advanced memory anomalies, correlates plugins, and invokes LLM engine."""

    def __init__(self, ai_provider: str = "heuristic", api_key: Optional[str] = None, ollama_model: str = "llama3"):
        self.ai_provider = ai_provider.lower()
        self.api_key = api_key or os.getenv("GEMINI_API_KEY") or os.getenv("OPENAI_API_KEY")
        self.ollama_model = ollama_model

    def analyze(self, telemetry: ForensicTelemetry) -> TriageAnalysisResult:
        """Runs heuristic anomaly detection, correlates findings, and enriches via AI Agent."""
        findings: List[AnomalyFinding] = []

        # 1. Malfind & Direct Syscall / API Hashing / Sleep Obfuscation
        for item in telemetry.malfind:
            pid = item.get("PID") or item.get("pid")
            process = item.get("Process") or item.get("process_name") or "Unknown"
            protection = str(item.get("Protection") or item.get("protection") or "PAGE_EXECUTE_READWRITE")
            offset = item.get("Start") or item.get("start_vpn") or item.get("Offset") or "0x0"
            hex_data = str(item.get("HexDump") or item.get("Disasm") or "")

            title = f"Suspicious Executable Memory Region (PID {pid})"
            category = "Injection"
            severity = "CRITICAL"
            description = f"Process '{process}' allocated unbacked memory at offset {offset} with protection '{protection}'."

            if any(ins in hex_data.lower() for ins in ["syscall", "sysenter", "0f05", "ror 13", "ror13"]):
                category = "Evasion"
                title = f"Direct Syscall / API Hashing Evasion Detected (PID {pid})"
                description += " Disassembly pattern reveals raw `syscall` instructions or ROR13 API hashing assembly routines, bypassing user-mode Ntdll.dll hooks."

            if any(p in protection.upper() for p in ["PAGE_NOACCESS", "PAGE_READWRITE"]) or "timer" in hex_data.lower():
                category = "Evasion"
                title = f"Sleep Obfuscation Signature Detected (Ekko/Foliage) (PID {pid})"
                description += f" VAD memory protection flip ({protection}) or ROP timer routine detected, indicative of C2 sleep obfuscation evading RAM scans."

            findings.append(AnomalyFinding(
                severity=severity,
                category=category,
                title=title,
                description=description,
                evidence_proof=f"Offset: {offset} | PID: {pid} | Protection: {protection} | Disasm: {hex_data[:60]}",
                pid=int(pid) if pid and str(pid).isdigit() else None,
                memory_offset=str(offset),
                details=item
            ))

        # 2. Go-Malware Runtime Reconstruction & CmdLine Heuristics
        suspicious_binaries = ["powershell.exe", "cmd.exe", "rundll32.exe", "mshta.exe", "wscript.exe", "cscript.exe", "regsvr32.exe"]
        for item in telemetry.cmdline:
            cmd = str(item.get("Args") or item.get("CommandLine") or "")
            pid = item.get("PID") or item.get("pid")
            process = str(item.get("Process") or item.get("process_name") or "")

            if any(go_kw in cmd for go_kw in ["go.buildid", "runtime.main", "goid", "runtime.goexit"]):
                findings.append(AnomalyFinding(
                    severity="HIGH",
                    category="Evasion",
                    title=f"Golang Runtime Binary Identified (PID {pid})",
                    description=f"Process '{process}' contains Go runtime signatures and symbol tables (`runtime.main`), indicative of Go-compiled C2 implants.",
                    evidence_proof=f"PID: {pid} | Cmd: {cmd[:100]}",
                    pid=int(pid) if pid and str(pid).isdigit() else None,
                    details=item
                ))

            if any(b in process.lower() for b in suspicious_binaries):
                if any(kw in cmd.lower() for kw in ["-e ", "-enc", "encodedcommand", "downloadstring", "iex", "bypass", "hidden"]):
                    findings.append(AnomalyFinding(
                        severity="HIGH",
                        category="ProcessTree",
                        title=f"Suspicious Obfuscated Command Line (PID {pid})",
                        description=f"Process '{process}' executed with obfuscated or download command flags.",
                        evidence_proof=f"PID: {pid} | Cmd: {cmd[:120]}",
                        pid=int(pid) if pid and str(pid).isdigit() else None,
                        details=item
                    ))

        # 3. NetScan Heuristics
        suspicious_ports = [4444, 1337, 6667, 8080, 8443, 9001, 3389]
        for item in telemetry.netscan:
            rport = item.get("ForeignPort") or item.get("rport") or 0
            pid = item.get("PID") or item.get("pid")
            raddr = item.get("ForeignAddr") or item.get("raddr") or "N/A"
            owner = item.get("Owner") or item.get("owner") or "Unknown"

            if rport in suspicious_ports or (any(b in str(owner).lower() for b in ["cmd.exe", "powershell.exe"]) and rport != 0):
                findings.append(AnomalyFinding(
                    severity="HIGH",
                    category="Network",
                    title=f"Suspicious Outbound Network Socket (PID {pid})",
                    description=f"Process '{owner}' connected to remote endpoint {raddr}:{rport}.",
                    evidence_proof=f"PID: {pid} | ForeignAddr: {raddr}:{rport} | Owner: {owner}",
                    pid=int(pid) if pid and str(pid).isdigit() else None,
                    details=item
                ))

        # 4. Linux Ephemeral & memfd_create Fileless Malware Detection
        for item in telemetry.linux_malfind + telemetry.linux_pslist:
            name = str(item.get("Name") or item.get("process") or "")
            pid = item.get("PID") or item.get("pid")
            if "memfd:" in name.lower() or "/dev/shm" in name.lower() or "anon_hugepage" in name.lower():
                findings.append(AnomalyFinding(
                    severity="CRITICAL",
                    category="LinuxFileless",
                    title=f"Linux Fileless Memory Execution (memfd_create) (PID {pid})",
                    description=f"Linux process '{name}' executing entirely from volatile memory buffers (`memfd_create` / `/dev/shm`), evading disk-based AV.",
                    evidence_proof=f"PID: {pid} | Process Name: {name}",
                    pid=int(pid) if pid and str(pid).isdigit() else None,
                    details=item
                ))

        # 5. Linux eBPF Rootkit Telemetry Ingestion
        for item in telemetry.linux_ebpf:
            prog_name = str(item.get("Name") or item.get("name") or "unnamed_ebpf")
            severity = str(item.get("Severity") or item.get("severity") or "HIGH").upper()
            findings.append(AnomalyFinding(
                severity=severity,
                category="eBPFRootkit",
                title=f"Suspicious eBPF Kernel Program ({prog_name})",
                description=f"Identified eBPF rootkit hook in Linux kernel: {item.get('findings', 'Suspicious helper invocation')}",
                evidence_proof=f"Name: {prog_name} | Type: {item.get('type', 'N/A')}",
                details=item
            ))

        # 6. LSASS Credential Access / Dumping Triage
        for item in telemetry.pslist:
            process = str(item.get("ImageFileName") or item.get("Process") or "").lower()
            pid = item.get("PID") or item.get("pid")
            if "lsass.exe" in process:
                lsass_findings = [f for f in findings if f.pid == pid and f.category in ["Injection", "Network", "Evasion"]]
                if lsass_findings:
                    findings.append(AnomalyFinding(
                        severity="CRITICAL",
                        category="CredentialAccess",
                        title=f"LSASS Process Injection / Memory Access (PID {pid})",
                        description=f"LSASS process (PID {pid}) exhibits injected memory pages or unauthorized outbound connections, indicating credential dumping.",
                        evidence_proof=f"PID: {pid} | Image: lsass.exe",
                        pid=int(pid) if pid and str(pid).isdigit() else None,
                        details=item
                    ))

        # Perform Cross-Plugin Correlation
        self._correlate_findings(findings)

        # Calculate Threat Score
        score = min(100, len([f for f in findings if f.severity == "CRITICAL"]) * 35 +
                         len([f for f in findings if f.severity == "HIGH"]) * 20 +
                         len([f for f in findings if f.severity == "MEDIUM"]) * 10)

        risk_level = "LOW"
        if score >= 75:
            risk_level = "CRITICAL"
        elif score >= 50:
            risk_level = "HIGH"
        elif score >= 25:
            risk_level = "MEDIUM"

        result = TriageAnalysisResult(
            threat_score=score,
            risk_level=risk_level,
            findings=findings,
            mitre_techniques=self._map_mitre(findings),
            remediation_steps=self._get_default_remediations(findings)
        )

        result.ai_summary = self._generate_ai_summary(telemetry, findings, score, risk_level)
        return result

    def _correlate_findings(self, findings: List[AnomalyFinding]):
        """Correlates findings sharing the same PID across multiple plugins."""
        pid_map: Dict[int, List[AnomalyFinding]] = {}
        for f in findings:
            if f.pid is not None:
                pid_map.setdefault(f.pid, []).append(f)

        for pid, group in pid_map.items():
            if len(group) > 1:
                categories = list(set([item.category for item in group]))
                for item in group:
                    item.correlated_findings = [f"{c.category}: {c.title}" for c in group if c != item]
                    if len(categories) >= 2 and item.severity != "CRITICAL":
                        item.severity = "HIGH"
                        item.description += f" [CROSS-PLUGIN CORRELATION]: Correlated with {len(group)-1} other anomaly events across categories: {', '.join(categories)}."

    def _map_mitre(self, findings: List[AnomalyFinding]) -> List[str]:
        """Maps detected anomaly categories to official MITRE ATT&CK techniques."""
        techniques = set()
        for f in findings:
            if f.category == "Injection":
                techniques.add("T1055 - Process Injection")
            elif f.category == "Evasion":
                techniques.add("T1027 - Obfuscated/Encrypted Files or Information")
                techniques.add("T1055.012 - Process Hollowing")
            elif f.category == "Network":
                techniques.add("T1071 - Application Layer Protocol (C2)")
                techniques.add("T1095 - Non-Application Layer Protocol")
            elif f.category == "ProcessTree":
                techniques.add("T1059.001 - PowerShell Execution")
            elif f.category == "LinuxFileless":
                techniques.add("T1620 - Reflective Code Loading (memfd_create)")
            elif f.category == "CredentialAccess":
                techniques.add("T1003.001 - OS Credential Dumping: LSASS Memory")
            elif f.category == "eBPFRootkit":
                techniques.add("T1014 - Rootkit: eBPF Kernel Hooks")

        return sorted(list(techniques))

    def _get_default_remediations(self, findings: List[AnomalyFinding]) -> List[str]:
        """Provides deterministic remediation actions based on detected categories."""
        remediations = set()
        for f in findings:
            if f.category == "Injection" and f.pid:
                remediations.add(f"Isolate host from network and terminate suspicious injected PID {f.pid}.")
            elif f.category == "CredentialAccess":
                remediations.add("Rotate all domain administrator and service account credentials immediately.")
            elif f.category == "Network":
                remediations.add("Block remote IP indicators on edge firewall / IDS.")
            elif f.category == "LinuxFileless":
                remediations.add("Audit /proc/[pid]/exe and restrict unprivileged memfd_create syscalls.")
            elif f.category == "eBPFRootkit":
                remediations.add("Enforce kernel lockdown (`kernel.unprivileged_bpf_disabled = 2`) and audit loaded eBPF programs via bpftool.")

        if not remediations:
            remediations.add("Perform standard integrity verification on operating system core binaries.")

        return sorted(list(remediations))

    def _generate_ai_summary(self, telemetry: ForensicTelemetry, findings: List[AnomalyFinding], score: int, risk_level: str) -> str:
        """Generates deterministic summary or invokes AI backend for enrichment."""
        if self.ai_provider == "heuristic":
            return (
                f"Empirical memory triage completed. Threat Score: {score}/100 ([ {risk_level} ]). "
                f"Identified {len(findings)} correlated anomalies. Multi-stage memory injection, "
                f"stealth evasions, and network C2 artifacts have been categorized and mapped to MITRE ATT&CK."
            )

        prompt = (
            f"You are a Senior DFIR Memory Forensics Lead. Summarize the following forensic findings into a concise, "
            f"high-signal technical assessment (max 3 paragraphs). Threat score is {score}/100, Risk Level is {risk_level}.\n"
            f"Findings:\n" + "\n".join([f"- [{f.severity}] {f.title}: {f.description} (Proof: {f.evidence_proof})" for f in findings])
        )

        if self.ai_provider == "gemini" and self.api_key:
            return self._call_gemini(prompt)
        elif self.ai_provider == "openai" and self.api_key:
            return self._call_openai(prompt)
        elif self.ai_provider == "ollama":
            return self._call_ollama(prompt)

        return f"Deterministic Heuristic Assessment: Threat score {score}/100 ({risk_level}). Identified {len(findings)} anomalies."

    def _call_gemini(self, prompt: str) -> str:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={self.api_key}"
        data = json.dumps({"contents": [{"parts": [{"text": prompt}]}]}).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                res = json.loads(resp.read().decode("utf-8"))
                return res["candidates"][0]["content"]["parts"][0]["text"].strip()
        except Exception as e:
            logger.warning(f"Gemini API call failed, falling back to heuristic: {e}")
            return f"Heuristic Fallback: Anomaly evaluation completed with score {self.ai_provider}."

    def _call_openai(self, prompt: str) -> str:
        url = "https://api.openai.com/v1/chat/completions"
        data = json.dumps({
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.2
        }).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        })
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                res = json.loads(resp.read().decode("utf-8"))
                return res["choices"][0]["message"]["content"].strip()
        except Exception as e:
            logger.warning(f"OpenAI API call failed, falling back to heuristic: {e}")
            return f"Heuristic Fallback: Anomaly evaluation completed."

    def _call_ollama(self, prompt: str) -> str:
        url = "http://localhost:11434/api/generate"
        data = json.dumps({"model": self.ollama_model, "prompt": prompt, "stream": False}).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                res = json.loads(resp.read().decode("utf-8"))
                return res.get("response", "").strip()
        except Exception as e:
            logger.warning(f"Ollama local API call failed: {e}")
            return "Heuristic Fallback: Local LLM service unreachable."
