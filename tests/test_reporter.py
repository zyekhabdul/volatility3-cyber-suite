"""
test_reporter.py — Unit Tests for Markdown, HTML, JSON, and STIX 2.1 Report Generators.
"""

import os
import json
import tempfile
import unittest
from vol3_suite.core.models import ForensicTelemetry
from vol3_suite.triage.analyzer import ForensicAnalyzer
from vol3_suite.core.reporter import ReportGenerator


class TestReportGenerator(unittest.TestCase):

    def setUp(self):
        telemetry = ForensicTelemetry(
            malfind=[{"PID": 1234, "Process": "beacon.exe", "Protection": "PAGE_EXECUTE_READWRITE"}],
            netscan=[{"PID": 1234, "Owner": "beacon.exe", "ForeignAddr": "198.51.100.2", "ForeignPort": 4444}],
        )
        analyzer = ForensicAnalyzer(ai_provider="heuristic")
        self.result = analyzer.analyze(telemetry)
        self.reporter = ReportGenerator(self.result)

    def test_generate_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            json_file = os.path.join(tmpdir, "report.json")
            content = self.reporter.generate_json(json_file)

            self.assertTrue(os.path.exists(json_file))
            data = json.loads(content)
            self.assertEqual(data["threat_score"], self.result.threat_score)
            self.assertEqual(data["risk_level"], self.result.risk_level)
            self.assertEqual(len(data["findings"]), len(self.result.findings))

    def test_generate_stix(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            stix_file = os.path.join(tmpdir, "stix.json")
            content = self.reporter.generate_stix(stix_file)

            self.assertTrue(os.path.exists(stix_file))
            data = json.loads(content)
            self.assertEqual(data["type"], "bundle")
            self.assertGreater(len(data["objects"]), 0)

    def test_generate_markdown(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            md_file = os.path.join(tmpdir, "report.md")
            content = self.reporter.generate_markdown(md_file)

            self.assertTrue(os.path.exists(md_file))
            self.assertIn("[ DFIR ] Memory Forensics & Incident Triage Report", content)
            self.assertIn("Threat Score", content)
            self.assertIn("beacon.exe", content)

    def test_generate_html(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            html_file = os.path.join(tmpdir, "report.html")
            content = self.reporter.generate_html(html_file)

            self.assertTrue(os.path.exists(html_file))
            self.assertIn("<!DOCTYPE html>", content)
            self.assertIn("DFIR Triage Report", content)
            self.assertIn("beacon.exe", content)


if __name__ == "__main__":
    unittest.main()
