"""
cli.py — Unified Command Line Interface for Volatility 3 Cyber Suite.
Provides single-binary orchestration for memory triage, eBPF rootkit hunting, and DFIR reporting.
"""

import os
import sys
import json
import logging
import argparse
from pathlib import Path
from typing import List, Dict, Any

from .core.models import ForensicTelemetry
from .core.runner import VolatilityRunner
from .core.reporter import ReportGenerator
from .core.export_engine import ExportEngine
from .triage.analyzer import ForensicAnalyzer
from .ebpf.threat_scorer import ThreatScorer
from .ebpf.jit_carver import JitCarver
from .ebpf.disasm_engine import DisasmEngine

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("vol3_suite.cli")


def run_triage_command(args):
    """Executes memory triage analysis and generates multi-format incident reports."""
    if not args.memory_dump and not args.log_dir:
        logger.error("You must specify either --memory-dump (-f) or --log-dir (-l).")
        sys.exit(1)

    runner = VolatilityRunner(volatility_path=getattr(args, "volatility_path", "vol"))
    if args.memory_dump:
        logger.info(f"Ingesting live memory dump: {args.memory_dump}")
        telemetry = runner.run_dump(args.memory_dump, os_type=getattr(args, "os", "windows"))
    else:
        logger.info(f"Ingesting log directory: {args.log_dir}")
        telemetry = runner.load_from_directory(args.log_dir)

    analyzer = ForensicAnalyzer(
        ai_provider=args.ai_provider,
        api_key=args.api_key,
        ollama_model=args.ollama_model,
    )
    logger.info("Executing heuristic correlation and threat scoring...")
    result = analyzer.analyze(telemetry)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    reporter = ReportGenerator(result)
    formats = [fmt.strip().lower() for fmt in args.format.split(",")]

    if "md" in formats or "markdown" in formats:
        md_path = output_dir / "report.md"
        reporter.generate_markdown(str(md_path))
        logger.info(f"Markdown report generated: {md_path}")

    if "html" in formats:
        html_path = output_dir / "report.html"
        reporter.generate_html(str(html_path))
        logger.info(f"HTML report generated: {html_path}")

    if "json" in formats:
        json_path = output_dir / "report.json"
        reporter.generate_json(str(json_path))
        logger.info(f"SIEM JSON report generated: {json_path}")

    if "stix" in formats:
        stix_path = output_dir / "stix_indicators.json"
        reporter.generate_stix(str(stix_path))
        logger.info(f"STIX 2.1 threat indicators generated: {stix_path}")

    print("\n=========================================================")
    print(f" [ DFIR ] TRIAGE COMPLETE: Threat Score {result.threat_score}/100 ([ {result.risk_level} ])")
    print(f" Total Correlated Findings: {len(result.findings)}")
    print(f" Reports Saved to: {output_dir.resolve()}")
    print("=========================================================\n")


def run_ebpf_command(args):
    """Executes standalone eBPF rootkit analysis and JIT memory carving."""
    print("=========================================================")
    print(" [ DFIR ] Volatility 3 Cyber Suite — eBPF Rootkit Engine")
    print("=========================================================")

    findings = []

    if args.file and os.path.exists(args.file):
        print(f"[*] Ingesting memory image / binary buffer: {args.file}")
        with open(args.file, "rb") as f:
            buffer = f.read()

        if args.carve:
            carver = JitCarver()
            print("[*] Executing JIT Executable Memory Carver...")
            candidates = carver.scan_memory_buffer(buffer, base_address=0xffffffffc0000000)
            print(f"[+] Identified {len(candidates)} JIT candidate regions.")
            for c in candidates:
                print(f"  - [{c['status']}] Addr: {c['address']} | Sig: {c['signature']}")
                findings.append({
                    "id": len(findings) + 1,
                    "name": f"carved_jit_{c['address']}",
                    "type": "CARVED_JIT_REGION",
                    "severity": "HIGH",
                    "findings": c["description"]
                })
    else:
        print("[*] No target file specified or file not found. Running self-test evaluation...")
        score, severity, f_list = ThreatScorer.evaluate_program(
            prog_type="BPF_PROG_TYPE_KPROBE",
            helper_ids=[36, 58],
            name="stealth_ebpf_rootkit"
        )
        findings.append({
            "id": 1,
            "name": "stealth_ebpf_rootkit",
            "type": "BPF_PROG_TYPE_KPROBE",
            "score": score,
            "severity": severity,
            "findings": "; ".join(item["description"] for item in f_list)
        })

    if args.export == "stix":
        report = json.dumps(ExportEngine.to_stix2(findings), indent=2)
    else:
        report = ExportEngine.to_json(findings, indent=2)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"[+] Forensic report exported to: {args.output}")
    else:
        print("\n--- [ Forensic Threat Report ] ---")
        print(report)


def main():
    parser = argparse.ArgumentParser(
        prog="vol3-suite",
        description="Volatility 3 Cyber Suite — Unified Memory Forensics, eBPF Hunting & AI Incident Triage",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    subparsers = parser.add_subparsers(dest="subcommand", help="Available modules")

    # 'triage' subcommand
    triage_p = subparsers.add_parser("triage", help="Automated memory dump analysis & AI incident triage reporter")
    triage_p.add_argument("-f", "--memory-dump", help="Path to raw memory dump file (.raw / .dmp)")
    triage_p.add_argument("-l", "--log-dir", help="Path to directory containing pre-extracted Volatility JSON/text logs")
    triage_p.add_argument("--os", choices=["windows", "linux"], default="windows", help="Target OS memory architecture")
    triage_p.add_argument("--volatility-path", default="vol", help="Path to Volatility 3 executable")
    triage_p.add_argument("-o", "--output-dir", default="./reports", help="Directory to save generated reports")
    triage_p.add_argument("--ai-provider", choices=["heuristic", "gemini", "openai", "ollama"], default="heuristic", help="AI summary provider")
    triage_p.add_argument("--api-key", help="API key for Gemini/OpenAI (can use GEMINI_API_KEY / OPENAI_API_KEY)")
    triage_p.add_argument("--ollama-model", default="llama3", help="Ollama model name")
    triage_p.add_argument("--format", default="html,md,json,stix", help="Comma-separated report formats")

    # 'ebpf' subcommand
    ebpf_p = subparsers.add_parser("ebpf", help="Standalone eBPF rootkit detector & JIT memory page carver")
    ebpf_p.add_argument("-f", "--file", help="Path to raw memory dump or binary file")
    ebpf_p.add_argument("--carve", action="store_true", help="Perform JIT memory carving on buffer")
    ebpf_p.add_argument("--export", choices=["json", "stix"], default="json", help="Export threat report format")
    ebpf_p.add_argument("-o", "--output", help="Output file path for report")
    ebpf_p.add_argument("--disasm", action="store_true", help="Test JIT disassembly engine")

    args = parser.parse_args()

    if not args.subcommand:
        # Default fallback to triage if options match, else print help
        parser.print_help()
        sys.exit(0)

    if args.subcommand == "triage":
        run_triage_command(args)
    elif args.subcommand == "ebpf":
        run_ebpf_command(args)


def main_ebpf():
    """Direct entrypoint for `ebpf-detector` standalone command."""
    parser = argparse.ArgumentParser(
        prog="ebpf-detector",
        description="vol3-ebpf-detector — Standalone eBPF Rootkit Detector & Memory Carver"
    )
    parser.add_argument("-f", "--file", help="Path to raw memory dump or binary file", required=False)
    parser.add_argument("--carve", action="store_true", help="Perform JIT memory carving on buffer")
    parser.add_argument("--export", choices=["json", "stix"], default="json", help="Export threat report format")
    parser.add_argument("-o", "--output", help="Output file path for report")
    parser.add_argument("--disasm", action="store_true", help="Test JIT disassembly engine")

    args = parser.parse_args()
    run_ebpf_command(args)


if __name__ == "__main__":
    main()
