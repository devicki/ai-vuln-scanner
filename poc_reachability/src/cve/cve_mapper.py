"""CVE mapping loader and query functions."""
import json
import logging
from pathlib import Path
from typing import Dict, Optional

logger = logging.getLogger(__name__)

_DEFAULT_CONFIG = Path(__file__).parent.parent.parent / "config" / "cve_mapping.json"


def load_cve_mapping(config_path: str = None) -> Dict:
    """Load CVE mapping from JSON config file."""
    path = Path(config_path) if config_path else _DEFAULT_CONFIG
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        logger.info(f"Loaded {len(data)} CVE entries from {path}")
        return data
    except Exception as e:
        logger.error(f"Failed to load CVE mapping: {e}")
        return {}


def get_vulnerable_method(cve_id: str, mapping: Dict) -> Optional[Dict]:
    """Get CVE info by ID."""
    return mapping.get(cve_id)


def get_all_cve_ids(mapping: Dict) -> list:
    return list(mapping.keys())
