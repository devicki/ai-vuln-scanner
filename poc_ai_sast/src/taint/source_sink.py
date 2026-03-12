import yaml
import os
from typing import List, Dict

def load_source_sink_config(config_path: str = None) -> Dict:
    if config_path is None:
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        config_path = os.path.join(base_dir, "config", "source_sink.yaml")

    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def get_sources(config: Dict = None) -> List[Dict]:
    if config is None:
        config = load_source_sink_config()
    return config.get("java_spring", {}).get("sources", [])

def get_sinks(vuln_type: str, config: Dict = None) -> List[Dict]:
    if config is None:
        config = load_source_sink_config()
    return config.get("java_spring", {}).get("sinks", {}).get(vuln_type, [])

def get_sanitizers(vuln_type: str, config: Dict = None) -> List[Dict]:
    if config is None:
        config = load_source_sink_config()
    return config.get("java_spring", {}).get("sanitizers", {}).get(vuln_type, [])
