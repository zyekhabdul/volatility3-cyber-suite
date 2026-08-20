"""
test_triage.py — Unit Tests for Memory Forensics & Anomaly Triage Engine.
"""

import unittest
from vol3_suite.core.models import ForensicTelemetry
from vol3_suite.triage.analyzer import ForensicAnalyzer


class TestForensicAnalyzer(unittest.TestCase):

    def test_analyzer_detects_malfind_and_network(self):
        telemetry = ForensicTelemetry(
            malfind=[{"PID": 5678, "Process": "powershell.exe", "Protection": "PAGE_EXECUTE_READWRITE"}],
            cmdline=[{"PID": 5678, "Process": "powershell.exe", "Args": "powershell.exe -e aWV4... -bypass"}],
            netscan=[{"PID": 5678, "Owner": "powershell.exe", "ForeignAddr": "185.220.101.5", "ForeignPort": 4444}],
        )

        analyzer = ForensicAnalyzer(ai_provider="heuristic")
        result = analyzer.analyze(telemetry)

        self.assertGreaterEqual(result.threat_score, 50)
        self.assertIn(result.risk_level, ["HIGH", "CRITICAL"])
        self.assertGreaterEqual(len(result.findings), 3)
        self.assertIn("T1055 - Process Injection", result.mitre_techniques)
        self.assertIn("T1071 - Application Layer Protocol (C2)", result.mitre_techniques)

    def test_analyzer_detects_linux_fileless_memfd(self):
        telemetry = ForensicTelemetry(
            linux_pslist=[{"PID": 1337, "Name": "memfd:malware (deleted)"}],
            linux_ebpf=[{"Name": "bpf_rootkit", "Severity": "CRITICAL", "findings": "Overrides syscall return"}],
        )

        analyzer = ForensicAnalyzer(ai_provider="heuristic")
        result = analyzer.analyze(telemetry)

        self.assertGreaterEqual(result.threat_score, 60)
        self.assertIn("T1620 - Reflective Code Loading (memfd_create)", result.mitre_techniques)
        self.assertIn("T1014 - Rootkit: eBPF Kernel Hooks", result.mitre_techniques)

    def test_analyzer_clean_telemetry(self):
        telemetry = ForensicTelemetry()
        analyzer = ForensicAnalyzer(ai_provider="heuristic")
        result = analyzer.analyze(telemetry)

        self.assertEqual(result.threat_score, 0)
        self.assertEqual(result.risk_level, "LOW")
        self.assertEqual(len(result.findings), 0)


if __name__ == "__main__":
    unittest.main()
