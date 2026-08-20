"""
radix_tree.py — Traverses Linux Kernel IDR (Radix Tree) and XArray `prog_idr`.
Extracts all `bpf_prog` and `bpf_prog_aux` objects via full multi-level tree slot recursion across Linux 4.x, 5.x, and 6.x.
"""

from typing import Iterable, Tuple, Any, Optional
import logging

logger = logging.getLogger("vol3_suite.ebpf.radix_tree")


class ProgIdrNavigator:
    """Navigates Linux kernel IDR structures (`prog_idr`) with recursive slot traversal."""

    def __init__(self, context: Any = None, symbol_table: str = ""):
        self.context = context
        self.symbol_table = symbol_table

    def walk_idr(self, vmlinux_layer: Any) -> Iterable[Tuple[int, Any]]:
        """
        Walks the global `prog_idr` symbol and yields `(prog_id, bpf_prog_object)`.
        Recursively traverses XArray slots (Kernel >= 4.20) and Radix Tree slots (Kernel < 4.20).
        """
        if not self.context:
            return

        try:
            prog_idr_addr = self.context.layers[vmlinux_layer].has_symbol("prog_idr")
            if not prog_idr_addr:
                logger.warning("Symbol 'prog_idr' not found in kernel symbol table.")
                return

            prog_idr = self.context.object(
                self.symbol_table + ".idr",
                layer_name=vmlinux_layer,
                offset=prog_idr_addr
            )

            for prog_id, prog_ptr in self._extract_idr_entries(prog_idr, vmlinux_layer):
                if prog_ptr and prog_ptr > 0xffff000000000000:
                    try:
                        bpf_prog = self.context.object(
                            self.symbol_table + ".bpf_prog",
                            layer_name=vmlinux_layer,
                            offset=prog_ptr
                        )
                        yield prog_id, bpf_prog
                    except Exception as e:
                        logger.debug(f"Failed to instantiate bpf_prog at {hex(prog_ptr)}: {e}")

        except Exception as e:
            logger.error(f"Error traversing prog_idr: {e}")

    def _extract_idr_entries(self, idr_obj: Any, vmlinux_layer: Any) -> Iterable[Tuple[int, int]]:
        """
        Recursively walks XArray (xa_node) or Radix Tree (radix_tree_node) slot arrays.
        """
        extracted = []
        try:
            if hasattr(idr_obj, "xa_head") and idr_obj.xa_head:
                head_ptr = int(idr_obj.xa_head)
                self._walk_xa_node(head_ptr, vmlinux_layer, 0, extracted)
            elif hasattr(idr_obj, "idr_rt") and idr_obj.idr_rt:
                root = idr_obj.idr_rt
                if hasattr(root, "rhead") and root.rhead:
                    self._walk_radix_node(int(root.rhead), vmlinux_layer, 0, extracted)
        except Exception as e:
            logger.debug(f"IDR extraction helper warning: {e}")

        if extracted:
            for item in extracted:
                yield item
        else:
            if hasattr(idr_obj, "xa_head") and idr_obj.xa_head:
                head_val = int(idr_obj.xa_head)
                if head_val > 0xffff000000000000:
                    yield 1, head_val

    def _walk_xa_node(self, node_ptr: int, vmlinux_layer: Any, current_id: int, results: list, depth: int = 0):
        """Recursive traversal over xa_node slots in XArray."""
        if depth > 8 or not node_ptr or node_ptr == 0:
            return

        if node_ptr & 2:
            node_addr = node_ptr & ~3
            try:
                xa_node = self.context.object(
                    self.symbol_table + ".xa_node",
                    layer_name=vmlinux_layer,
                    offset=node_addr
                )
                if hasattr(xa_node, "slots"):
                    for idx, slot_ptr in enumerate(xa_node.slots):
                        val = int(slot_ptr)
                        if val:
                            self._walk_xa_node(val, vmlinux_layer, (current_id << 6) | idx, results, depth + 1)
            except Exception:
                pass
        else:
            if node_ptr > 0xffff000000000000:
                results.append((current_id, node_ptr))

    def _walk_radix_node(self, node_ptr: int, vmlinux_layer: Any, current_id: int, results: list, depth: int = 0):
        """Recursive traversal over radix_tree_node slots in classic Radix Tree IDR."""
        if depth > 8 or not node_ptr or node_ptr == 0:
            return

        try:
            rt_node = self.context.object(
                self.symbol_table + ".radix_tree_node",
                layer_name=vmlinux_layer,
                offset=node_ptr
            )
            if hasattr(rt_node, "slots"):
                for idx, slot_ptr in enumerate(rt_node.slots):
                    val = int(slot_ptr)
                    if val > 0xffff000000000000:
                        shift = getattr(rt_node, "shift", 0)
                        if shift == 0:
                            results.append(((current_id << 6) | idx, val))
                        else:
                            self._walk_radix_node(val, vmlinux_layer, (current_id << 6) | idx, results, depth + 1)
        except Exception:
            pass
