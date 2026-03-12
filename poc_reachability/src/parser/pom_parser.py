"""Parser for pom.xml and build.gradle dependency files."""
import logging
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class Dependency:
    group_id: str
    artifact_id: str
    version: Optional[str]

    def __str__(self):
        return f"{self.group_id}:{self.artifact_id}:{self.version or 'unknown'}"


def _parse_version_tuple(version_str: str) -> Tuple[int, ...]:
    parts = re.sub(r"[^0-9.]", "", version_str).split(".")
    return tuple(int(p) for p in parts if p.isdigit())


def is_version_affected(version: str, min_ver: str, max_ver: str) -> Optional[bool]:
    """Return True if version is within [min_ver, max_ver], None if unparseable."""
    try:
        v = _parse_version_tuple(version)
        vmin = _parse_version_tuple(min_ver)
        vmax = _parse_version_tuple(max_ver)
        if not v or not vmin or not vmax:
            return None
        return vmin <= v <= vmax
    except Exception:
        return None


def parse_pom(pom_path: str) -> List[Dependency]:
    """Parse pom.xml and return list of dependencies."""
    deps = []
    try:
        tree = ET.parse(pom_path)
        root = tree.getroot()
        ns = ""
        if root.tag.startswith("{"):
            ns = root.tag.split("}")[0] + "}"

        # Collect properties for variable resolution (e.g. ${spring.version})
        properties = {}
        props_elem = root.find(f"{ns}properties")
        if props_elem is not None:
            for prop in props_elem:
                tag = prop.tag.replace(ns, "")
                properties[tag] = prop.text or ""

        for dep in root.iter(f"{ns}dependency"):
            group_id = (dep.findtext(f"{ns}groupId") or "").strip()
            artifact_id = (dep.findtext(f"{ns}artifactId") or "").strip()
            version = (dep.findtext(f"{ns}version") or "").strip()

            if version.startswith("${") and version.endswith("}"):
                var_name = version[2:-1]
                version = properties.get(var_name, version)

            if group_id and artifact_id:
                deps.append(Dependency(group_id=group_id, artifact_id=artifact_id, version=version or None))
    except Exception as e:
        logger.warning(f"Failed to parse {pom_path}: {e}")
    return deps


def parse_gradle(gradle_path: str) -> List[Dependency]:
    """Parse build.gradle and return list of dependencies."""
    deps = []
    try:
        content = Path(gradle_path).read_text(encoding="utf-8", errors="replace")
        pattern = r"""(?:implementation|compile|api|runtimeOnly|testImplementation)\s+['"]([^'"]+)['"]"""
        for match in re.finditer(pattern, content):
            coord = match.group(1)
            parts = coord.split(":")
            if len(parts) >= 2:
                group_id = parts[0]
                artifact_id = parts[1]
                version = parts[2] if len(parts) > 2 else None
                deps.append(Dependency(group_id=group_id, artifact_id=artifact_id, version=version))
    except Exception as e:
        logger.warning(f"Failed to parse {gradle_path}: {e}")
    return deps


def find_dependencies(source_dir: str) -> List[Dependency]:
    """Find and parse all pom.xml and build.gradle in the directory tree."""
    base = Path(source_dir)
    all_deps: List[Dependency] = []

    for pom in sorted(base.rglob("pom.xml")):
        deps = parse_pom(str(pom))
        logger.info(f"pom.xml ({pom}): {len(deps)} dependencies")
        all_deps.extend(deps)

    for gradle in sorted(base.rglob("build.gradle")):
        deps = parse_gradle(str(gradle))
        logger.info(f"build.gradle ({gradle}): {len(deps)} dependencies")
        all_deps.extend(deps)

    return all_deps
