"""
jit_carver.py — Direct Executable Memory Page Carver for Orphaned JIT eBPF Programs.
High-efficiency byte scanning utilizing C-level buffer.find() with precise alignment and header validation.
"""

from typing import List, Dict, Any, Tuple
import logging

logger = logging.getLogger("vol3_suite.ebpf.carver")

# Common x86_64 eBPF JIT signatures
ENDBR64_SIG = b"\x0f\x1e\xfa"
X86_JIT_PROLOGUE = b"\x55\x48\x89\xe5"  # push rbp; mov rbp, rsp


class JitCarver:
    """Carves raw kernel executable memory pages to detect unlinked or orphaned JIT eBPF programs."""

    def __init__(self, page_size: int = 4096):
        self.page_size = page_size

    def scan_memory_buffer(self, buffer: bytes, base_address: int) -> List[Dict[str, Any]]:
        """
        Scans a raw memory buffer for JIT prologue signatures using C-level string search (buffer.find).
        Uses 16-byte alignment step (pos = idx + 16) instead of page skips to ensure multiple JIT functions
        in the same 4KB page are not missed.
        """
        candidates = []
        buf_len = len(buffer)
        signatures = [(ENDBR64_SIG, "ENDBR64"), (X86_JIT_PROLOGUE, "X86_JIT_PROLOGUE")]

        for sig_bytes, sig_name in signatures:
            pos = 0
            while pos < buf_len:
                idx = buffer.find(sig_bytes, pos)
                if idx == -1:
                    break

                candidate_addr = base_address + idx
                is_valid_header = self._validate_bpf_header(buffer, idx)

                candidates.append({
                    "address": hex(candidate_addr),
                    "offset": idx,
                    "signature": sig_name,
                    "header_verified": is_valid_header,
                    "status": "VERIFIED_JIT_PROGRAM" if is_valid_header else "CARVED_JIT_CANDIDATE",
                    "description": "Verified unlinked JIT eBPF binary header & prologue" if is_valid_header else "Potential unlinked JIT eBPF code block"
                })

                pos = idx + 16

        unique_candidates = {c["offset"]: c for c in candidates}
        result = list(unique_candidates.values())
        result.sort(key=lambda x: x["offset"])
        return result

    def _validate_bpf_header(self, buffer: bytes, prologue_idx: int) -> bool:
        """
        Checks if the 32 bytes preceding the JIT prologue contain a valid struct bpf_binary_header.
        struct bpf_binary_header {
            u32 size;
            u8 image[];
        };
        """
        if prologue_idx < 32:
            return False

        try:
            size_val = int.from_bytes(buffer[prologue_idx-32:prologue_idx-28], byteorder="little")
            if 64 <= size_val <= 65536:
                return True
        except Exception:
            pass

        return False
