"""
runner.py — Orchestrates Volatility 3 Plugin Execution & Telemetry Ingestion.
Supports live execution via `vol` CLI wrapper or parsing pre-extracted forensic log directories.
"""

import json
import logging
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional
from .models import ForensicTelemetry

logger = logging.getLogger("vol3_suite.runner")


class VolatilityRunner:
    """Automates execution of Volatility 3 plugins and parses outputs into ForensicTelemetry."""

    DEFAULT_WINDOWS_PLUGINS = [
        ("pslist", "windows.pslist.PsList"),
        ("psscan", "windows.psscan.PsScan"),
        ("pstree", "windows.pstree.PsTree"),
        ("cmdline", "windows.cmdline.CmdLine"),
        ("netscan", "windows.netscan.NetScan"),
        ("malfind", "windows.malfind.Malfind"),
        ("dlllist", "windows.dlllist.DllList"),
    ]

    DEFAULT_LINUX_PLUGINS = [
        ("linux_pslist", "linux.pslist.PsList"),
        ("linux_malfind", "linux.malfind.Malfind"),
        ("linux_check_syscall", "linux.check_syscall.Check_syscall"),
        ("linux_ebpf", "linux.ebpf_detector.EbpfDetector"),
    ]

    def __init__(self, volatility_path: str = "vol"):
        self.volatility_path = volatility_path

    def run_dump(self, memory_dump_path: str, os_type: str = "windows", custom_plugins: Optional[List[str]] = None) -> ForensicTelemetry:
        """
        Executes Volatility 3 plugins against a raw memory image file and aggregates telemetry.
        """
        telemetry = ForensicTelemetry()
        plugins = self.DEFAULT_WINDOWS_PLUGINS if os_type.lower() == "windows" else self.DEFAULT_LINUX_PLUGINS

        for field_name, plugin_name in plugins:
            if custom_plugins and field_name not in custom_plugins:
                continue
            logger.info(f"Executing Volatility 3 plugin: {plugin_name}...")
            cmd = [self.volatility_path, "-f", memory_dump_path, "-r", "json", plugin_name]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                if result.returncode == 0 and result.stdout.strip():
                    try:
                        data = json.loads(result.stdout)
                        setattr(telemetry, field_name, data if isinstance(data, list) else [data])
                    except json.JSONDecodeError:
                        logger.warning(f"Plugin {plugin_name} output is not valid JSON. Storing raw lines.")
                        lines = [{"raw": line} for line in result.stdout.splitlines() if line.strip()]
                        setattr(telemetry, field_name, lines)
                else:
                    logger.warning(f"Plugin {plugin_name} exited with code {result.returncode}: {result.stderr[:200]}")
            except Exception as e:
                logger.error(f"Failed to execute plugin {plugin_name}: {e}")

        return telemetry

    def load_from_directory(self, log_dir_path: str) -> ForensicTelemetry:
        """
        Parses pre-extracted Volatility 3 JSON/text log files from a directory.
        Allows offline analysis without requiring the Volatility 3 runtime binary.
        """
        telemetry = ForensicTelemetry()
        dir_path = Path(log_dir_path)

        if not dir_path.exists():
            logger.error(f"Log directory not found: {log_dir_path}")
            return telemetry

        for json_file in dir_path.glob("*.json"):
            name = json_file.stem.lower()
            try:
                content = json.loads(json_file.read_text(encoding="utf-8"))
                rows = content if isinstance(content, list) else content.get("rows", [content])

                if "pslist" in name:
                    telemetry.pslist = rows
                elif "psscan" in name:
                    telemetry.psscan = rows
                elif "pstree" in name:
                    telemetry.pstree = rows
                elif "cmdline" in name:
                    telemetry.cmdline = rows
                elif "netscan" in name:
                    telemetry.netscan = rows
                elif "netstat" in name:
                    telemetry.netstat = rows
                elif "malfind" in name:
                    telemetry.malfind = rows
                elif "dlllist" in name:
                    telemetry.dlllist = rows
                elif "handles" in name:
                    telemetry.handles = rows
                elif "ldrmodules" in name:
                    telemetry.ldrmodules = rows
                elif "linux_pslist" in name:
                    telemetry.linux_pslist = rows
                elif "linux_malfind" in name:
                    telemetry.linux_malfind = rows
                elif "ebpf" in name:
                    telemetry.linux_ebpf = rows
            except Exception as e:
                logger.warning(f"Failed to parse {json_file.name}: {e}")

        return telemetry
