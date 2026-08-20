"""
test_cli.py — Unit Tests for Unified Command Line Interface & Execution Dispatcher.
"""

import os
import types
import json
import tempfile
import unittest
from unittest.mock import patch
from vol3_suite.cli import main, run_ebpf_command, run_triage_command


class TestCLI(unittest.TestCase):

    def test_ebpf_self_test(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, "ebpf_out.json")

            args = types.SimpleNamespace(
                file=None,
                carve=False,
                export="json",
                output=out_file,
                disasm=False
            )

            run_ebpf_command(args)

            self.assertTrue(os.path.exists(out_file))
            with open(out_file, "r") as f:
                data = json.load(f)
                self.assertIn("findings", data)
                self.assertGreater(len(data["findings"]), 0)

    def test_triage_log_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_dir = os.path.join(tmpdir, "logs")
            os.makedirs(log_dir, exist_ok=True)
            malfind_log = os.path.join(log_dir, "windows_malfind.json")
            with open(malfind_log, "w") as f:
                json.dump([{"PID": 999, "Process": "injected.exe", "Protection": "PAGE_EXECUTE_READWRITE"}], f)

            report_dir = os.path.join(tmpdir, "reports")

            args = types.SimpleNamespace(
                memory_dump=None,
                log_dir=log_dir,
                volatility_path="vol",
                os="windows",
                output_dir=report_dir,
                ai_provider="heuristic",
                api_key=None,
                ollama_model="llama3",
                format="html,md,json,stix"
            )

            run_triage_command(args)

            self.assertTrue(os.path.exists(os.path.join(report_dir, "report.md")))
            self.assertTrue(os.path.exists(os.path.join(report_dir, "report.html")))
            self.assertTrue(os.path.exists(os.path.join(report_dir, "report.json")))
            self.assertTrue(os.path.exists(os.path.join(report_dir, "stix_indicators.json")))


if __name__ == "__main__":
    unittest.main()
