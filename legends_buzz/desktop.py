"""Windows PE subsystem inspection, embedded frontend asset scanning, and Buzz Desktop install auditing."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import struct
from typing import Any

IMAGE_SUBSYSTEM_WINDOWS_GUI = 2
IMAGE_SUBSYSTEM_WINDOWS_CUI = 3
_ASSET_PATTERN = re.compile(rb"assets/[A-Za-z0-9._-]{4,120}\.(?:js|css|woff2?|svg|png|webp|wasm)")


def inspect_pe_file(path: Path) -> dict[str, Any]:
    """Inspect a Windows Portable Executable (PE) header to classify GUI vs CUI (console) binaries."""
    target = Path(path)
    if not target.exists() or target.is_symlink() or not target.is_file():
        return {
            "exists": False,
            "is_pe": False,
            "subsystem_code": None,
            "subsystem": "missing",
        }
    try:
        with target.open("rb") as handle:
            mz = handle.read(64)
            if len(mz) < 64 or mz[:2] != b"MZ":
                return {
                    "exists": True,
                    "is_pe": False,
                    "subsystem_code": None,
                    "subsystem": "non_pe",
                }
            pe_offset = struct.unpack_from("<I", mz, 0x3C)[0]
            if pe_offset < 64 or pe_offset > 16 * 1024 * 1024:
                return {
                    "exists": True,
                    "is_pe": False,
                    "subsystem_code": None,
                    "subsystem": "non_pe",
                }
            handle.seek(pe_offset)
            header = handle.read(24 + 96)
            if len(header) < 24 + 70 or header[:4] != b"PE\x00\x00":
                return {
                    "exists": True,
                    "is_pe": False,
                    "subsystem_code": None,
                    "subsystem": "non_pe",
                }
            opt_magic = struct.unpack_from("<H", header, 24)[0]
            if opt_magic not in (0x10B, 0x20B):
                return {
                    "exists": True,
                    "is_pe": False,
                    "subsystem_code": None,
                    "subsystem": "non_pe",
                }
            subsystem_code = struct.unpack_from("<H", header, 24 + 68)[0]
    except OSError:
        return {
            "exists": False,
            "is_pe": False,
            "subsystem_code": None,
            "subsystem": "unreadable",
        }

    if subsystem_code == IMAGE_SUBSYSTEM_WINDOWS_CUI:
        subsystem_name = "cui"
    elif subsystem_code == IMAGE_SUBSYSTEM_WINDOWS_GUI:
        subsystem_name = "gui"
    else:
        subsystem_name = f"other_{subsystem_code}"

    return {
        "exists": True,
        "is_pe": True,
        "subsystem_code": subsystem_code,
        "subsystem": subsystem_name,
    }


def scan_embedded_frontend_assets(path: Path, max_bytes: int = 256 * 1024 * 1024) -> dict[str, Any]:
    """Scan a compiled Buzz Desktop binary for embedded index.html and hashed assets/... bundles."""
    target = Path(path)
    if not target.exists() or target.is_symlink() or not target.is_file():
        return {
            "exists": False,
            "has_index_html": False,
            "asset_count": 0,
            "sample_assets": [],
            "sha256": None,
            "size_bytes": 0,
        }
    size_bytes = target.stat().st_size
    if size_bytes > max_bytes:
        raise ValueError(f"Binary {target.name} exceeds scan ceiling ({size_bytes} > {max_bytes} bytes).")

    hasher = hashlib.sha256()
    has_index_html = False
    discovered_assets: set[str] = set()
    overlap = b""
    chunk_size = 4 * 1024 * 1024

    with target.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
            window = overlap + chunk
            if not has_index_html and b"index.html" in window:
                has_index_html = True
            for match in _ASSET_PATTERN.finditer(window):
                discovered_assets.add(match.group(0).decode("ascii", errors="ignore"))
            overlap = window[-256:]

    sorted_assets = sorted(discovered_assets)
    return {
        "exists": True,
        "has_index_html": has_index_html,
        "asset_count": len(sorted_assets),
        "sample_assets": sorted_assets[:10],
        "sha256": hasher.hexdigest(),
        "size_bytes": size_bytes,
    }


def default_buzz_install_dir() -> Path:
    """Return the default platform installation directory for Buzz Desktop."""
    if os.name == "nt":
        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data:
            return Path(local_app_data) / "Programs" / "Buzz"
        return Path.home() / "AppData" / "Local" / "Programs" / "Buzz"
    return Path("/Applications/Buzz.app/Contents/MacOS")


def audit_desktop_install(
    install_dir: Path | None = None,
    cli_bin: Path | None = None,
) -> dict[str, Any]:
    """Audit a Buzz Desktop installation for NTFS Buzz.exe/buzz.exe collisions, PE subsystems, and embedded assets."""
    root = (Path(install_dir) if install_dir else default_buzz_install_dir()).resolve()
    findings: list[dict[str, str]] = []
    binaries: dict[str, Any] = {}

    candidates = [
        ("desktop_0x", root / "buzz-desktop.exe"),
        ("root_buzz_exe", root / "buzz.exe"),
        ("bin_buzz_exe", root / "bin" / "buzz.exe"),
        ("bin_buzz_agent_command", root / "bin" / "buzz-agent-command.exe"),
        ("bin_goose_acp", root / "bin" / "goose-acp.exe"),
        ("buzz_acp_root", root / "buzz-acp.exe"),
    ]
    if cli_bin is not None:
        candidates.append(("explicit_cli_bin", Path(cli_bin).resolve()))

    for label, candidate in candidates:
        if candidate.exists() and not candidate.is_symlink() and candidate.is_file():
            pe = inspect_pe_file(candidate)
            info: dict[str, Any] = {
                "path": str(candidate),
                "size_bytes": candidate.stat().st_size,
                "pe": pe,
            }
            if label in ("desktop_0x", "root_buzz_exe") and pe.get("subsystem") == "gui":
                assets = scan_embedded_frontend_assets(candidate)
                info["embedded_assets"] = assets
            else:
                info["sha256"] = hashlib.sha256(candidate.read_bytes()).hexdigest()
            binaries[label] = info

    ntfs_case_collision = False
    root_buzz = binaries.get("root_buzz_exe")
    if root_buzz and root_buzz["pe"].get("subsystem") == "gui":
        ntfs_case_collision = True
        findings.append(
            {
                "severity": "critical",
                "code": "ntfs_buzz_exe_case_collision",
                "message": (
                    "Root buzz.exe/Buzz.exe has PE subsystem WINDOWS_GUI (2) instead of WINDOWS_CUI (3). "
                    "On Windows NTFS (case-insensitive), installing Buzz 1.0.0 directly into Programs\\Buzz "
                    "overwrites the CLI buzz.exe with the 148 MB GUI Buzz.exe binary. Use bin\\buzz.exe for CLI "
                    "automation or restore a CUI buzz.exe at the install root and place Buzz 1.0 GUI in Programs\\Buzz-1.0."
                ),
            }
        )

    gui_target = binaries.get("desktop_0x")
    if gui_target is None and root_buzz and root_buzz["pe"].get("subsystem") == "gui":
        gui_target = root_buzz

    if gui_target and "embedded_assets" in gui_target:
        assets_info = gui_target["embedded_assets"]
        if not assets_info.get("has_index_html") or int(assets_info.get("asset_count", 0)) == 0:
            findings.append(
                {
                    "severity": "critical",
                    "code": "missing_embedded_frontend_assets",
                    "message": (
                        "Desktop GUI binary is missing embedded index.html or hashed assets/ bundles "
                        "(the 0.5.22 empty-asset build trap). Run pnpm build before cargo build --release."
                    ),
                }
            )

    if not binaries:
        findings.append(
            {
                "severity": "warning",
                "code": "install_dir_empty_or_missing",
                "message": f"No Buzz binaries found under {root}.",
            }
        )

    healthy = not any(item["severity"] == "critical" for item in findings) and bool(binaries)
    return {
        "schema": "legends-buzz.desktop-audit/v1",
        "install_dir": str(root),
        "exists": root.is_dir(),
        "ok": healthy,
        "healthy": healthy,
        "ntfs_case_collision_detected": ntfs_case_collision,
        "binaries": binaries,
        "findings": findings,
    }
