"""
map_inspector.py — Inspects bpf_map instances in memory to uncover stored C2 IPs,
hidden PIDs, and exfiltrated credential data.
"""

from typing import List, Dict, Any, Optional

MAP_TYPES = {
    1: "BPF_MAP_TYPE_HASH",
    2: "BPF_MAP_TYPE_ARRAY",
    3: "BPF_MAP_TYPE_PROG_ARRAY",
    4: "BPF_MAP_TYPE_PERF_EVENT_ARRAY",
    5: "BPF_MAP_TYPE_PERCPU_HASH",
    6: "BPF_MAP_TYPE_PERCPU_ARRAY",
    7: "BPF_MAP_TYPE_STACK_TRACE",
    8: "BPF_MAP_TYPE_CGROUP_ARRAY",
    9: "BPF_MAP_TYPE_LRU_HASH",
    10: "BPF_MAP_TYPE_LRU_PERCPU_HASH",
    11: "BPF_MAP_TYPE_LPM_TRIE",
    12: "BPF_MAP_TYPE_ARRAY_OF_MAPS",
    13: "BPF_MAP_TYPE_HASH_OF_MAPS",
    14: "BPF_MAP_TYPE_DEVMAP",
    15: "BPF_MAP_TYPE_SOCKMAP",
    16: "BPF_MAP_TYPE_CPUMAP",
    17: "BPF_MAP_TYPE_XSKMAP",
    18: "BPF_MAP_TYPE_SOCKHASH",
    19: "BPF_MAP_TYPE_CGROUP_STORAGE",
    20: "BPF_MAP_TYPE_REUSEPORT_SOCKARRAY",
    21: "BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE",
    22: "BPF_MAP_TYPE_QUEUE",
    23: "BPF_MAP_TYPE_STACK",
    24: "BPF_MAP_TYPE_SK_STORAGE",
    25: "BPF_MAP_TYPE_DEVMAP_HASH",
    26: "BPF_MAP_TYPE_STRUCT_OPS",
    27: "BPF_MAP_TYPE_RINGBUF",
    28: "BPF_MAP_TYPE_BLOOM_FILTER",
}


class MapInspector:
    """Enumerates bpf_map objects and resolves map metadata."""

    @staticmethod
    def resolve_map_type(type_id: int) -> str:
        """Converts raw integer bpf_map_type enum to human-readable string."""
        return MAP_TYPES.get(type_id, f"UNKNOWN_MAP_TYPE_{type_id}")

    @staticmethod
    def inspect_map_metadata(bpf_map_obj: Any) -> Dict[str, Any]:
        """Extracts map dimensions, key size, value size, and max entries."""
        metadata = {
            "name": "N/A",
            "type": "UNKNOWN",
            "key_size": 0,
            "value_size": 0,
            "max_entries": 0,
            "flags": 0
        }

        try:
            if hasattr(bpf_map_obj, "name") and bpf_map_obj.name:
                metadata["name"] = str(bpf_map_obj.name)
            if hasattr(bpf_map_obj, "map_type"):
                metadata["type"] = MapInspector.resolve_map_type(int(bpf_map_obj.map_type))
            if hasattr(bpf_map_obj, "key_size"):
                metadata["key_size"] = int(bpf_map_obj.key_size)
            if hasattr(bpf_map_obj, "value_size"):
                metadata["value_size"] = int(bpf_map_obj.value_size)
            if hasattr(bpf_map_obj, "max_entries"):
                metadata["max_entries"] = int(bpf_map_obj.max_entries)
        except Exception:
            pass

        return metadata
