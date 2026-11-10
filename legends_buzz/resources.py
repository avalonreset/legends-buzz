"""Locate distributed recipes, knowledge pack manifests, and blueprints for legends-buzz."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .blueprints import list_blueprints


def _resolve_data_root() -> tuple[Path, str]:
    pkg_dir = Path(__file__).resolve().parent
    packaged = pkg_dir / "_data"
    if (packaged / "knowledge" / "buzz" / "pack.json").is_file():
        return packaged, "package_data"
    repo_root = pkg_dir.parent
    return repo_root, "repo_checkout"


def resource_info() -> dict[str, Any]:
    """Return machine-readable paths for the distributed recipe, knowledge pack, and blueprints."""
    root, source = _resolve_data_root()
    recipe = root / "docs" / "AGENT-RECIPE.md"
    pack_manifest = root / "knowledge" / "buzz" / "pack.json"
    router_skill = root / "skills" / "cto-legends" / "SKILL.md"
    wiki_index = root / "wiki" / "index.md"
    complete = (
        recipe.is_file()
        and pack_manifest.is_file()
        and router_skill.is_file()
        and wiki_index.is_file()
    )
    return {
        "module": "legends-buzz",
        "source": source,
        "root": str(root),
        "recipe": str(recipe),
        "pack_manifest": str(pack_manifest),
        "router_skill": str(router_skill),
        "wiki_index": str(wiki_index),
        "blueprints": [item["name"] for item in list_blueprints()],
        "complete": complete,
    }
