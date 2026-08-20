"""
export_engine.py — Exports forensic findings into structured JSON & STIX 2.1 IOC formats.
Enables interoperability with SIEM, SOAR, EDR, MISP, and threat intelligence platforms.
"""

import json
import time
import uuid
import datetime
from typing import List, Dict, Any, Union


class ExportEngine:
    """Formats forensic findings and eBPF detections into JSON or STIX 2.1 Bundle objects."""

    @staticmethod
    def to_json(findings: Union[List[Dict[str, Any]], Dict[str, Any]], indent: int = 2) -> str:
        """Serializes findings into formatted JSON string."""
        if isinstance(findings, dict) and "findings" in findings:
            payload = findings
        else:
            payload = {
                "metadata": {
                    "generator": "volatility3-cyber-suite",
                    "version": "2.0.0",
                    "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "total_items": len(findings) if isinstance(findings, list) else 1,
                },
                "findings": findings
            }
        return json.dumps(payload, indent=indent)

    @staticmethod
    def to_stix2(findings: List[Dict[str, Any]], bundle_name: str = "vol3-cyber-suite-report") -> Dict[str, Any]:
        """
        Converts findings into a STIX 2.1 Bundle containing Indicator, Malware, and Relationship objects.
        """
        stix_objects = []
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        for item in findings:
            severity = str(item.get("severity", "MEDIUM")).upper()
            if severity in ["MEDIUM", "HIGH", "CRITICAL"]:
                item_id = item.get("id") or item.get("prog_id") or item.get("pid") or str(uuid.uuid4())[:8]
                item_name = item.get("name") or item.get("title") or "Unnamed Finding"
                category = item.get("category") or item.get("type") or "GenericAnomaly"
                description = item.get("description") or item.get("findings") or "Suspicious memory artifact detected"

                # STIX Indicator Object
                indicator_id = f"indicator--{uuid.uuid4()}"
                indicator = {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": indicator_id,
                    "created": now_iso,
                    "modified": now_iso,
                    "name": f"[{severity}] {item_name}",
                    "description": str(description),
                    "indicator_types": ["malicious-activity", "anomalous-activity"],
                    "pattern": f"[x-vol3-indicator:category = '{category}']",
                    "pattern_type": "stix",
                    "valid_from": now_iso,
                }
                stix_objects.append(indicator)

                # STIX Malware / Tool Object
                malware_id = f"malware--{uuid.uuid4()}"
                malware = {
                    "type": "malware",
                    "spec_version": "2.1",
                    "id": malware_id,
                    "created": now_iso,
                    "modified": now_iso,
                    "name": f"Malware-{item_name}",
                    "is_family": False,
                    "malware_types": ["rootkit" if "ebpf" in category.lower() else "trojan"],
                    "description": f"Detected via Volatility3 Cyber Suite ({category})"
                }
                stix_objects.append(malware)

                # STIX Relationship Object
                relationship = {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": f"relationship--{uuid.uuid4()}",
                    "created": now_iso,
                    "modified": now_iso,
                    "relationship_type": "indicates",
                    "source_ref": indicator_id,
                    "target_ref": malware_id
                }
                stix_objects.append(relationship)

        return {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": stix_objects
        }
