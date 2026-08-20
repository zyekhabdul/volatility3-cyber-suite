"""
test_ebpf.py — Unit Tests for eBPF Hunting, Scoring, JIT Carving, and Auditing Engines.
"""

import unittest
from vol3_suite.ebpf.threat_scorer import ThreatScorer
from vol3_suite.ebpf.hook_analyzer import HookAnalyzer
from vol3_suite.ebpf.disasm_engine import DisasmEngine
from vol3_suite.ebpf.fops_checker import FopsChecker
from vol3_suite.ebpf.jit_carver import JitCarver
from vol3_suite.ebpf.map_inspector import MapInspector
from vol3_suite.ebpf.ringbuf_carver import RingbufCarver
from vol3_suite.ebpf.struct_ops_auditor import StructOpsAuditor
from vol3_suite.core.export_engine import ExportEngine


class TestEbpfThreatScorer(unittest.TestCase):

    def test_high_risk_helpers(self):
        score, severity, findings = ThreatScorer.evaluate_program(
            prog_type="BPF_PROG_TYPE_KPROBE",
            helper_ids=[36, 58],
            name="test_prog"
        )
        self.assertGreaterEqual(score, 70)
        self.assertEqual(severity, "CRITICAL")
        self.assertTrue(any(f["type"] == "HIGH_RISK_HELPER" for f in findings))

    def test_compound_threat_rule(self):
        score, severity, findings = ThreatScorer.evaluate_program(
            prog_type="BPF_PROG_TYPE_KPROBE",
            helper_ids=[36],
            name="injector"
        )
        self.assertEqual(score, 100)
        self.assertEqual(severity, "CRITICAL")
        self.assertTrue(any("COMPOUND_THREAT" in f["type"] for f in findings))

    def test_stealth_metadata_rule(self):
        score, severity, findings = ThreatScorer.evaluate_program(
            prog_type="BPF_PROG_TYPE_XDP",
            helper_ids=[],
            name=""
        )
        self.assertEqual(score, 25)
        self.assertEqual(severity, "MEDIUM")
        self.assertTrue(any(f["type"] == "ANONYMOUS_PROGRAM" for f in findings))


class TestEbpfHookAnalyzer(unittest.TestCase):

    def test_resolve_prog_type(self):
        self.assertEqual(HookAnalyzer.resolve_prog_type(2), "BPF_PROG_TYPE_KPROBE")
        self.assertEqual(HookAnalyzer.resolve_prog_type(6), "BPF_PROG_TYPE_XDP")
        self.assertEqual(HookAnalyzer.resolve_prog_type(27), "BPF_PROG_TYPE_STRUCT_OPS")
        self.assertEqual(HookAnalyzer.resolve_prog_type(999), "UNKNOWN_TYPE_999")

    def test_inspect_attachment(self):
        class MockProg:
            class Aux:
                attach_func_name = "sys_execve"
                link = 0xffff888012345678
            aux = Aux()

        details = HookAnalyzer.inspect_attachment(MockProg())
        self.assertEqual(details["attached_func"], "sys_execve")
        self.assertEqual(details["bpf_link_addr"], hex(0xffff888012345678))


class TestDisasmEngine(unittest.TestCase):

    def test_disasm_fallback_or_execution(self):
        engine = DisasmEngine(arch="x86_64")
        code = b"\x90\x90\xc3"
        instructions = engine.disassemble_jit(code, base_address=0x1000)
        self.assertGreater(len(instructions), 0)
        self.assertIn("address", instructions[0])


class TestJitCarver(unittest.TestCase):

    def test_scan_memory_buffer(self):
        carver = JitCarver(page_size=4096)
        # Create a buffer with x86 JIT prologue
        buffer = b"\x00" * 100 + b"\x55\x48\x89\xe5" + b"\x90" * 100
        candidates = carver.scan_memory_buffer(buffer, base_address=0xffffffffc0000000)
        self.assertGreaterEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["signature"], "X86_JIT_PROLOGUE")


class TestFopsChecker(unittest.TestCase):

    def test_audit_seq_ops_clean(self):
        class MockSeqOps:
            start = 0xffffffff81001000
            next = 0xffffffff81001050
            stop = 0xffffffff81001080
            show = 0xffffffff81001100

        stext = 0xffffffff81000000
        etext = 0xffffffff82000000
        anomalies = FopsChecker.audit_seq_ops(MockSeqOps(), stext, etext)
        self.assertEqual(len(anomalies), 0)

    def test_audit_seq_ops_hooked(self):
        class MockHookedSeqOps:
            start = 0xffffffffc0002000  # Outside stext..etext and no module range
            next = 0xffffffff81001050
            stop = 0
            show = 0

        stext = 0xffffffff81000000
        etext = 0xffffffff82000000
        anomalies = FopsChecker.audit_seq_ops(MockHookedSeqOps(), stext, etext)
        self.assertEqual(len(anomalies), 1)
        self.assertEqual(anomalies[0]["status"], "HOOKED_OUT_OF_BOUNDS")


class TestMapInspector(unittest.TestCase):

    def test_resolve_map_type(self):
        self.assertEqual(MapInspector.resolve_map_type(1), "BPF_MAP_TYPE_HASH")
        self.assertEqual(MapInspector.resolve_map_type(27), "BPF_MAP_TYPE_RINGBUF")

    def test_inspect_map_metadata(self):
        class MockMap:
            name = "c2_ip_table"
            map_type = 1
            key_size = 4
            value_size = 8
            max_entries = 1024

        meta = MapInspector.inspect_map_metadata(MockMap())
        self.assertEqual(meta["name"], "c2_ip_table")
        self.assertEqual(meta["type"], "BPF_MAP_TYPE_HASH")
        self.assertEqual(meta["max_entries"], 1024)


class TestRingbufCarver(unittest.TestCase):

    def test_carve_ringbuffer_map(self):
        carver = RingbufCarver()

        class MockMap:
            name = "stolen_creds_ringbuf"
            value = 0xffff888000200000

        res = carver.carve_ringbuffer_map(MockMap(), "vmlinux_layer")
        self.assertEqual(res["map_name"], "stolen_creds_ringbuf")
        self.assertGreater(res["data_bytes_available"], 0)


class TestStructOpsAuditor(unittest.TestCase):

    def test_audit_struct_ops(self):
        class MockProg:
            type = 27
            class Aux:
                attach_func_name = "bpf_tcp_congestion"
            aux = Aux()

        res = StructOpsAuditor.audit_struct_ops(MockProg())
        self.assertTrue(res["is_struct_ops"])
        self.assertEqual(res["threat_level"], "HIGH")
        self.assertEqual(res["target_ops_name"], "bpf_tcp_congestion")


if __name__ == "__main__":
    unittest.main()
