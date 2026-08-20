"""
disasm_engine.py — Capstone JIT Disassembly Engine & eBPF Bytecode Exporter.
Optimized with cached Capstone disassembler instances for high-throughput disassembly.
"""

from typing import List, Dict, Any, Optional
import logging

logger = logging.getLogger("vol3_suite.ebpf.disasm")

try:
    import capstone
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False


class DisasmEngine:
    """Disassembles JIT machine code using cached Capstone disassemblers."""

    _cs_instances: Dict[str, Any] = {}

    def __init__(self, arch: str = "x86_64"):
        self.arch = arch.lower()
        self.cs = self._get_cached_cs(self.arch)

    @classmethod
    def _get_cached_cs(cls, arch: str) -> Optional[Any]:
        """Singleton/Cache pattern to avoid allocating Capstone context repeatedly."""
        if not CAPSTONE_AVAILABLE:
            return None

        if arch in cls._cs_instances:
            return cls._cs_instances[arch]

        cs_obj = None
        if arch in ["x86_64", "x86"]:
            cs_obj = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        elif arch in ["arm64", "aarch64"]:
            cs_obj = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)

        if cs_obj:
            cs_obj.detail = True
            cls._cs_instances[arch] = cs_obj

        return cs_obj

    def disassemble_jit(self, code_bytes: bytes, base_address: int = 0, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Disassembles raw JIT byte buffer using Capstone.

        Returns list of instructions: [{address, mnemonic, op_str, bytes}].
        """
        instructions = []
        if not CAPSTONE_AVAILABLE or not self.cs:
            return [{
                "address": hex(base_address),
                "mnemonic": "; Capstone disassembler not available",
                "op_str": "Install via: pip install capstone",
                "bytes": code_bytes[:8].hex() if code_bytes else ""
            }]

        try:
            count = 0
            for insn in self.cs.disasm(code_bytes, base_address):
                instructions.append({
                    "address": hex(insn.address),
                    "mnemonic": insn.mnemonic,
                    "op_str": insn.op_str,
                    "bytes": insn.bytes.hex()
                })
                count += 1
                if count >= limit:
                    break
        except Exception as e:
            logger.error(f"Error during disassembly: {e}")

        return instructions

    @staticmethod
    def export_bytecode(bytecode: bytes, output_path: str) -> bool:
        """Saves extracted eBPF bytecode to file for external tools (Ghidra/IDA)."""
        try:
            with open(output_path, "wb") as f:
                f.write(bytecode)
            return True
        except Exception as e:
            logger.error(f"Failed to export bytecode to {output_path}: {e}")
            return False
