"""Core operational API for legends-buzz: SSRF-guarded relay probes, safe CLI execution, membership audits, and canaries."""
from __future__ import annotations

import base64
import csv
import datetime as dt
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import statistics
import subprocess
import tempfile
import time
from typing import Any
import urllib.error
import urllib.parse
import urllib.request
import uuid
import xml.etree.ElementTree as ET
import zipfile

from .desktop import audit_desktop_install, default_buzz_install_dir, inspect_pe_file
from .mcp_map import MCP_DOMAINS
from .resources import resource_info

MAX_ENV_FILE_BYTES = 64 * 1024
MAX_HTTP_RESPONSE_BYTES = 2 * 1024 * 1024
_CGNAT_NETWORK = ipaddress.ip_network("100.64.0.0/10")
_BECH32_CHARSET = set("qpzry9x8gf2tvdw0s3jn54khce6mua7l")
_NSEC_RE = re.compile(r"\bnsec1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{20,120}\b", re.IGNORECASE)
_HEX64_ENV_RE = re.compile(
    r"((?:BUZZ_PRIVATE_KEY|BUZZ_PRIVATE_KEY_HEX|BUZZ_NSEC|private_key)\s*[=:]\s*['\"]?)([0-9a-fA-F]{64})\b",
    re.IGNORECASE,
)
_TOKEN_ENV_RE = re.compile(
    r"((?:BUZZ_FEDERATED_IDENTITY_TOKEN|Authorization|Bearer)\s*[=:]?\s*['\"]?)([A-Za-z0-9._~+/=-]{16,})\b",
    re.IGNORECASE,
)


class BuzzValidationError(ValueError):
    """Raised when user inputs, URLs, or CLI parameters fail validation."""


class BuzzSecurityError(RuntimeError):
    """Raised when SSRF, redirect, symlink, or PE subsystem safety gates refuse an operation."""


class BuzzOperationError(RuntimeError):
    """Raised when an external Buzz relay or CLI operation fails."""


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuse all automatic HTTP redirects so credentials and probes never cross origins."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise BuzzSecurityError(f"Refusing HTTP redirect ({code}) from {req.full_url}")


def scrub_secrets(text: str | None) -> str:
    """Mask nsec1 Bech32 keys, 64-character hex secret keys, and federated bearer tokens."""
    if not text:
        return ""
    scrubbed = _NSEC_RE.sub("nsec1[REDACTED]", str(text))
    scrubbed = _HEX64_ENV_RE.sub(r"\1[REDACTED_HEX64]", scrubbed)
    scrubbed = _TOKEN_ENV_RE.sub(r"\1[REDACTED_TOKEN]", scrubbed)
    return scrubbed


_BECH32_ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_polymod(values: list[int]) -> int:
    gen = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            if (b >> i) & 1:
                chk ^= gen[i]
    return chk


def _bech32_hrp_expand(hrp: str) -> list[int]:
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def normalize_pubkey(value: str) -> str:
    """Normalize a Nostr public key (Bech32 npub1... or 64-char hex) to lowercase hex."""
    cleaned = str(value or "").strip().lower()
    if not cleaned.startswith("npub1"):
        return cleaned
    data = [_BECH32_ALPHABET.find(ch) for ch in cleaned[5:]]
    if any(d == -1 for d in data) or len(data) < 6:
        raise BuzzValidationError(f"Invalid Bech32 characters in npub: {value}")
    if _bech32_polymod(_bech32_hrp_expand("npub") + data) != 1:
        raise BuzzValidationError(f"Invalid BIP-173 Bech32 checksum in npub: {value}")
    acc = 0
    bits = 0
    out: list[int] = []
    for word in data[:-6]:
        acc = (acc << 5) | word
        bits += 5
        while bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
    hex_str = bytes(out).hex()
    if len(hex_str) != 64:
        raise BuzzValidationError(f"Decoded npub is not 32 bytes: {value}")
    return hex_str


def classify_key(value: str | None) -> dict[str, Any]:
    """Classify a Nostr secret key without exposing any raw secret material."""
    if value is None or not str(value).strip():
        return {"kind": "missing", "valid": False, "fingerprint": None}
    cleaned = str(value).strip()
    digest = hashlib.sha256(cleaned.encode("utf-8")).hexdigest()[:8]
    lower = cleaned.lower()
    if lower.startswith("nsec1") and len(lower) >= 58:
        payload = lower[5:]
        if all(ch in _BECH32_CHARSET for ch in payload):
            return {"kind": "nsec", "valid": True, "fingerprint": f"sha256:{digest}"}
        return {"kind": "invalid", "valid": False, "fingerprint": None}
    if len(cleaned) == 64 and all(ch in "0123456789abcdefABCDEF" for ch in cleaned):
        return {"kind": "hex64", "valid": True, "fingerprint": f"sha256:{digest}"}
    return {"kind": "invalid", "valid": False, "fingerprint": None}


_MACOS_SYSTEM_SYMLINKS = frozenset({Path("/var"), Path("/tmp"), Path("/etc")})


def check_no_symlink_chain(path: Path) -> None:
    """Verify neither the target path nor any non-system parent directory is a symlink."""
    target = Path(path)
    if target.is_symlink():
        raise BuzzSecurityError(f"Refusing symlinked path: {target}")
    for parent in target.absolute().parents:
        if parent in _MACOS_SYSTEM_SYMLINKS:
            continue
        if parent.is_symlink():
            raise BuzzSecurityError(f"Refusing path under symlinked parent directory: {parent}")


def parse_env_file(path: Path) -> dict[str, str]:
    """Read a Buzz .env file safely, rejecting symlinks and oversized files."""
    target = Path(path)
    check_no_symlink_chain(target)
    if not target.exists() or not target.is_file():
        raise BuzzValidationError(f"Env file not found: {target}")
    size = target.stat().st_size
    if size > MAX_ENV_FILE_BYTES:
        raise BuzzSecurityError(f"Env file exceeds {MAX_ENV_FILE_BYTES} bytes: {target}")

    parsed: dict[str, str] = {}
    raw = target.read_text(encoding="utf-8")
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("export "):
            stripped = stripped[len("export ") :].strip()
        if "=" not in stripped:
            continue
        key, val = stripped.split("=", 1)
        key = key.strip()
        val = val.strip()
        if len(val) >= 2 and ((val[0] == '"' and val[-1] == '"') or (val[0] == "'" and val[-1] == "'")):
            val = val[1:-1]
        if key:
            parsed[key] = val
    return parsed


def resolve_credentials(
    env_file: Path | None = None,
    relay_url: str | None = None,
) -> dict[str, Any]:
    """Resolve relay URL, secret key, and federated identity settings from env_file or environment."""
    source_map: dict[str, str] = dict(os.environ)
    env_file_used: str | None = None
    if env_file is not None:
        file_vars = parse_env_file(Path(env_file))
        source_map.update(file_vars)
        env_file_used = str(Path(env_file).resolve())

    private_key = (
        source_map.get("BUZZ_PRIVATE_KEY")
        or source_map.get("BUZZ_NSEC")
        or source_map.get("BUZZ_PRIVATE_KEY_HEX")
        or ""
    ).strip()
    resolved_relay = (relay_url or source_map.get("BUZZ_RELAY_URL") or "").strip()
    federated_token = (source_map.get("BUZZ_FEDERATED_IDENTITY_TOKEN") or "").strip()
    federated_adapter = (source_map.get("BUZZ_FEDERATED_IDENTITY_ADAPTER") or "").strip()
    output_format = (source_map.get("BUZZ_OUTPUT_FORMAT") or "").strip()
    key_info = classify_key(private_key)
    return {
        "relay_url": resolved_relay or None,
        "private_key": private_key or None,
        "key_classification": key_info,
        "has_federated_token": bool(federated_token),
        "federated_token": federated_token or None,
        "federated_adapter": federated_adapter or None,
        "output_format": output_format or None,
        "env_file": env_file_used,
    }


def _is_disallowed_ip(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if (
        addr.is_loopback
        or addr.is_private
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_unspecified
        or addr.is_reserved
    ):
        return True
    if isinstance(addr, ipaddress.IPv4Address) and addr in _CGNAT_NETWORK:
        return True
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return _is_disallowed_ip(addr.ipv4_mapped)
    return False


def validate_relay_url(
    url: str,
    allow_private_network: bool = False,
    resolve_dns: bool = True,
) -> dict[str, Any]:
    """Validate a Buzz relay URL and enforce SSRF public-IP resolution guards."""
    if not url or not str(url).strip():
        raise BuzzValidationError("Relay URL must not be empty.")
    raw = str(url).strip()
    parsed = urllib.parse.urlsplit(raw)
    scheme = parsed.scheme.lower()
    if scheme == "wss":
        http_scheme = "https"
    elif scheme == "ws":
        http_scheme = "http"
    elif scheme in ("https", "http"):
        http_scheme = scheme
    else:
        raise BuzzValidationError(f"Unsupported relay URL scheme '{parsed.scheme}'. Use https:// or wss://.")

    if http_scheme != "https" and not allow_private_network:
        raise BuzzSecurityError("Relay URL must use https:// or wss:// unless --allow-private-network is set.")

    if parsed.username or parsed.password:
        raise BuzzSecurityError("Relay URL must not embed credentials.")

    hostname = parsed.hostname
    if not hostname:
        raise BuzzValidationError("Relay URL is missing a valid hostname.")

    try:
        port = parsed.port
    except ValueError as exc:
        raise BuzzValidationError(f"Relay URL contains an invalid port: {exc}") from exc

    resolved_ips: list[str] = []
    if resolve_dns:
        try:
            infos = socket.getaddrinfo(hostname, port or (443 if http_scheme == "https" else 80), type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise BuzzOperationError(f"DNS resolution failed for relay host '{hostname}': {exc}") from exc

        for info in infos:
            ip_str = info[4][0]
            ip_obj = ipaddress.ip_address(ip_str)
            if not allow_private_network and _is_disallowed_ip(ip_obj):
                raise BuzzSecurityError(
                    f"Refusing relay host '{hostname}' because it resolves to non-public IP {ip_str}."
                )
            if ip_str not in resolved_ips:
                resolved_ips.append(ip_str)

    netloc = hostname if port is None else f"{hostname}:{port}"
    clean_path = parsed.path.rstrip("/")
    normalized_http = urllib.parse.urlunsplit((http_scheme, netloc, clean_path, "", ""))
    ws_scheme = "wss" if http_scheme == "https" else "ws"
    normalized_ws = urllib.parse.urlunsplit((ws_scheme, netloc, clean_path, "", ""))
    return {
        "input_url": raw,
        "http_url": normalized_http,
        "ws_url": normalized_ws,
        "hostname": hostname,
        "port": port or (443 if http_scheme == "https" else 80),
        "resolved_ips": resolved_ips,
    }


def _http_get(
    url: str,
    headers: dict[str, str] | None = None,
    timeout: float = 10.0,
) -> dict[str, Any]:
    req_headers = {"User-Agent": "legends-buzz/0.1.0"}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, headers=req_headers, method="GET")
    context = ssl.create_default_context()
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=context),
        _NoRedirectHandler(),
    )
    start = time.monotonic()
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read(MAX_HTTP_RESPONSE_BYTES + 1)
            if len(raw) > MAX_HTTP_RESPONSE_BYTES:
                raise BuzzSecurityError(f"Response from {url} exceeded {MAX_HTTP_RESPONSE_BYTES} bytes.")
            elapsed_ms = round((time.monotonic() - start) * 1000.0, 2)
            text = raw.decode("utf-8", errors="replace")
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            return {
                "ok": 200 <= resp.status < 300,
                "status": resp.status,
                "elapsed_ms": elapsed_ms,
                "body": text,
                "content_type": resp.headers.get("Content-Type", ""),
                "headers": resp_headers,
            }
    except urllib.error.HTTPError as exc:
        elapsed_ms = round((time.monotonic() - start) * 1000.0, 2)
        raw_err = exc.read(4096).decode("utf-8", errors="replace") if exc.fp else ""
        err_headers = {k.lower(): v for k, v in exc.headers.items()} if exc.headers else {}
        return {
            "ok": False,
            "status": exc.code,
            "elapsed_ms": elapsed_ms,
            "body": scrub_secrets(raw_err),
            "content_type": exc.headers.get("Content-Type", "") if exc.headers else "",
            "headers": err_headers,
        }
    except urllib.error.URLError as exc:
        raise BuzzOperationError(f"HTTP request to {url} failed: {scrub_secrets(str(exc))}") from exc


def _probe_pairing_websocket(
    hostname: str,
    port: int,
    connect_ip: str | None = None,
    timeout: float = 8.0,
) -> dict[str, Any]:
    """Perform a pinned-IP RFC 6455 TLS WebSocket 101 upgrade handshake against /pair (buzz-pair-relay)."""
    start = time.monotonic()
    ws_key = base64.b64encode(os.urandom(16)).decode("ascii")
    expected_accept = base64.b64encode(
        hashlib.sha1((ws_key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")).digest()
    ).decode("ascii")
    ctx = ssl.create_default_context()
    target_host = connect_ip or hostname
    try:
        with socket.create_connection((target_host, port), timeout=timeout) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=hostname) as tls_sock:
                req = (
                    f"GET /pair HTTP/1.1\r\n"
                    f"Host: {hostname}\r\n"
                    f"User-Agent: legends-buzz/0.1.0\r\n"
                    f"Upgrade: websocket\r\n"
                    f"Connection: Upgrade\r\n"
                    f"Sec-WebSocket-Key: {ws_key}\r\n"
                    f"Sec-WebSocket-Version: 13\r\n\r\n"
                )
                tls_sock.sendall(req.encode("ascii"))
                resp_raw = tls_sock.recv(2048).decode("latin1", errors="replace")
    except OSError as exc:
        return {
            "ok": False,
            "status": 0,
            "elapsed_ms": round((time.monotonic() - start) * 1000.0, 2),
            "accept_verified": False,
            "detail": scrub_secrets(str(exc)),
        }

    elapsed_ms = round((time.monotonic() - start) * 1000.0, 2)
    lines = resp_raw.splitlines()
    status_line = lines[0] if lines else ""
    status_code = 0
    parts = status_line.split()
    if len(parts) >= 2 and parts[1].isdigit():
        status_code = int(parts[1])
    accept_header = ""
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            if k.strip().lower() == "sec-websocket-accept":
                accept_header = v.strip()
                break
    accept_ok = (status_code == 101) and (accept_header == expected_accept)
    return {
        "ok": accept_ok,
        "status": status_code,
        "elapsed_ms": elapsed_ms,
        "accept_verified": accept_ok,
        "detail": status_line,
    }


def probe_relay(
    relay_url: str,
    allow_private_network: bool = False,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """Probe a Buzz relay's /_readiness, /health, NIP-11, Tauri CORS, /invite/* edge, and /pair WebSocket."""
    target = validate_relay_url(relay_url, allow_private_network=allow_private_network)
    base_http = target["http_url"].rstrip("/")

    readiness = _http_get(
        f"{base_http}/_readiness",
        headers={"Origin": "tauri://localhost"},
        timeout=timeout,
    )
    health = _http_get(f"{base_http}/health", timeout=timeout)
    nip11_resp = _http_get(
        f"{base_http}/",
        headers={"Accept": "application/nostr+json"},
        timeout=timeout,
    )
    invite_resp = _http_get(
        f"{base_http}/invite/legends-probe-check",
        timeout=timeout,
    )
    connect_ip = target["resolved_ips"][0] if target["resolved_ips"] else None
    pair_ws = _probe_pairing_websocket(
        hostname=target["hostname"],
        port=target["port"],
        connect_ip=connect_ip,
        timeout=min(timeout, 8.0),
    )

    nip11_doc: dict[str, Any] = {}
    if nip11_resp["ok"] and nip11_resp["body"].strip().startswith("{"):
        try:
            parsed_doc = json.loads(nip11_resp["body"])
            if isinstance(parsed_doc, dict):
                nip11_doc = parsed_doc
        except json.JSONDecodeError:
            nip11_doc = {}

    supported_nips = nip11_doc.get("supported_nips") if isinstance(nip11_doc.get("supported_nips"), list) else []
    limitation = nip11_doc.get("limitation") if isinstance(nip11_doc.get("limitation"), dict) else {}
    requires_nip_fi = bool(
        nip11_doc.get("federated_identity")
        or limitation.get("federated_identity_required")
        or "NIP-FI" in str(nip11_doc)
    )

    acao = readiness.get("headers", {}).get("access-control-allow-origin", "")
    tauri_cors_ok = acao in ("tauri://localhost", "*")
    invite_headers = invite_resp.get("headers", {})
    invite_csp = invite_headers.get("content-security-policy", "")
    invite_edge_ok = bool(invite_resp["ok"] and ("<html" in invite_resp["body"].lower() or bool(invite_csp)))

    healthy = bool(readiness["ok"] and health["ok"])
    return {
        "schema": "legends-buzz.relay-probe/v1",
        "relay_url": base_http,
        "ws_url": target["ws_url"],
        "hostname": target["hostname"],
        "resolved_ips": target["resolved_ips"],
        "ok": healthy,
        "healthy": healthy,
        "readiness": {
            "ok": readiness["ok"],
            "status": readiness["status"],
            "elapsed_ms": readiness["elapsed_ms"],
            "body": readiness["body"].strip()[:200],
        },
        "health": {
            "ok": health["ok"],
            "status": health["status"],
            "elapsed_ms": health["elapsed_ms"],
            "body": health["body"].strip()[:200],
        },
        "nip11": {
            "ok": bool(nip11_doc),
            "status": nip11_resp["status"],
            "name": nip11_doc.get("name"),
            "description": nip11_doc.get("description"),
            "software": nip11_doc.get("software"),
            "version": nip11_doc.get("version"),
            "supported_nips": supported_nips,
            "auth_required": bool(limitation.get("auth_required")),
            "restricted_writes": bool(limitation.get("restricted_writes")),
            "requires_nip_fi": requires_nip_fi,
        },
        "production_surfaces": {
            "tauri_cors": {
                "ok": tauri_cors_ok,
                "access_control_allow_origin": acao or None,
            },
            "invite_edge": {
                "ok": invite_edge_ok,
                "status": invite_resp["status"],
                "has_csp": bool(invite_csp),
                "cache_control": invite_headers.get("cache-control"),
            },
            "pairing_websocket": pair_ws,
        },
    }


def resolve_buzz_binary(explicit_path: str | Path | None = None) -> dict[str, Any]:
    """Locate a safe console (CUI) buzz CLI binary, guarding against the Windows NTFS Buzz.exe GUI collision."""
    candidates: list[tuple[str, Path]] = []
    if explicit_path:
        candidates.append(("explicit", Path(explicit_path)))
    env_bin = os.environ.get("BUZZ_CLI_BIN")
    if env_bin:
        candidates.append(("env_BUZZ_CLI_BIN", Path(env_bin)))

    install_root = default_buzz_install_dir()
    if os.name == "nt":
        candidates.append(("install_bin_buzz_exe", install_root / "bin" / "buzz.exe"))
        candidates.append(("install_root_buzz_exe", install_root / "buzz.exe"))
    which_hit = shutil.which("buzz")
    if which_hit:
        candidates.append(("path_which", Path(which_hit)))

    rejected_gui_collisions: list[str] = []
    for source, candidate in candidates:
        if not candidate.exists() or candidate.is_symlink() or not candidate.is_file():
            continue
        resolved = candidate.resolve()
        if os.name == "nt":
            pe = inspect_pe_file(resolved)
            if pe.get("subsystem") == "gui":
                rejected_gui_collisions.append(str(resolved))
                continue
            if pe.get("subsystem") != "cui":
                continue
        return {
            "found": True,
            "source": source,
            "path": str(resolved),
            "rejected_gui_collisions": rejected_gui_collisions,
        }

    return {
        "found": False,
        "source": None,
        "path": None,
        "rejected_gui_collisions": rejected_gui_collisions,
    }


def run_buzz_cli(
    args: list[str],
    relay_url: str | None = None,
    private_key: str | None = None,
    federated_token: str | None = None,
    federated_adapter: str | None = None,
    buzz_bin: str | Path | None = None,
    timeout: float = 25.0,
) -> dict[str, Any]:
    """Run the external buzz CLI safely with shell=False and environment-injected credentials."""
    resolved = resolve_buzz_binary(buzz_bin)
    if not resolved["found"] or not resolved["path"]:
        collision_note = ""
        if resolved["rejected_gui_collisions"]:
            collision_note = (
                f" Rejected GUI binary collision at: {', '.join(resolved['rejected_gui_collisions'])}."
            )
        raise BuzzOperationError(f"Could not locate a valid console buzz CLI binary.{collision_note}")

    clean_args: list[str] = []
    fmt_value: str | None = None
    idx = 0
    while idx < len(args):
        if args[idx] == "--format" and idx + 1 < len(args):
            fmt_value = args[idx + 1]
            idx += 2
        else:
            clean_args.append(args[idx])
            idx += 1

    cmd = [resolved["path"]]
    if relay_url and "--relay" not in clean_args:
        cmd.extend(["--relay", relay_url])
    if fmt_value:
        cmd.extend(["--format", fmt_value])
    cmd.extend(clean_args)

    env = dict(os.environ)
    if relay_url:
        env["BUZZ_RELAY_URL"] = relay_url
    if private_key:
        env["BUZZ_PRIVATE_KEY"] = private_key
    if federated_token:
        env["BUZZ_FEDERATED_IDENTITY_TOKEN"] = federated_token
    if federated_adapter:
        env["BUZZ_FEDERATED_IDENTITY_ADAPTER"] = federated_adapter

    start = time.monotonic()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise BuzzOperationError(f"buzz CLI timed out after {timeout}s: {' '.join(args[:3])}") from exc
    except OSError as exc:
        raise BuzzOperationError(f"Failed to execute buzz CLI: {scrub_secrets(str(exc))}") from exc

    elapsed_ms = round((time.monotonic() - start) * 1000.0, 2)
    stdout_clean = scrub_secrets(proc.stdout.strip())
    stderr_clean = scrub_secrets(proc.stderr.strip())
    parsed_json: Any = None
    if stdout_clean.startswith("{") or stdout_clean.startswith("["):
        try:
            parsed_json = json.loads(stdout_clean)
        except json.JSONDecodeError:
            parsed_json = None

    return {
        "ok": proc.returncode == 0,
        "exit_code": proc.returncode,
        "elapsed_ms": elapsed_ms,
        "binary": resolved["path"],
        "stdout": stdout_clean,
        "stderr": stderr_clean,
        "json": parsed_json,
    }


def cli_inventory(buzz_bin: str | Path | None = None) -> dict[str, Any]:
    """Inspect the installed buzz CLI binary to inventory command groups, sha256, and 1.0.0 capabilities."""
    resolved = resolve_buzz_binary(buzz_bin)
    if not resolved["found"] or not resolved["path"]:
        return {
            "schema": "legends-buzz.cli-inventory/v1",
            "ok": False,
            "found": False,
            "binary": None,
            "rejected_gui_collisions": resolved["rejected_gui_collisions"],
            "sha256": None,
            "generation": "missing",
            "command_group_count": 0,
            "command_groups": [],
            "supports_format_agent": False,
            "supports_federated_identity": False,
        }

    bin_path = Path(resolved["path"])
    bin_sha256 = hashlib.sha256(bin_path.read_bytes()).hexdigest()
    help_res = run_buzz_cli(["--help"], buzz_bin=resolved["path"], timeout=10.0)

    known_groups = {item["domain"] for item in MCP_DOMAINS}
    discovered_groups: list[str] = []
    for line in help_res["stdout"].splitlines():
        if line.startswith("  ") and not line.startswith("    "):
            tokens = line.strip().split()
            if tokens and tokens[0] in known_groups and tokens[0] not in discovered_groups:
                discovered_groups.append(tokens[0])

    help_text = help_res["stdout"]
    supports_format_agent = "agent:" in help_text or "'agent'" in help_text
    supports_federated_identity = "BUZZ_FEDERATED_IDENTITY_TOKEN" in help_text
    has_1x_domains = any(group in discovered_groups for group in ("sidebar", "huddles", "projects", "auth"))
    generation = "1.0.0+" if (has_1x_domains or supports_format_agent) else "0.5.x"

    return {
        "schema": "legends-buzz.cli-inventory/v1",
        "ok": True,
        "found": True,
        "binary": resolved["path"],
        "source": resolved["source"],
        "sha256": bin_sha256,
        "rejected_gui_collisions": resolved["rejected_gui_collisions"],
        "generation": generation,
        "command_group_count": len(discovered_groups),
        "command_groups": discovered_groups,
        "supports_format_agent": supports_format_agent,
        "supports_federated_identity": supports_federated_identity,
    }


def membership_check(
    relay_url: str | None = None,
    env_file: Path | None = None,
    buzz_bin: str | Path | None = None,
    allow_private_network: bool = False,
) -> dict[str, Any]:
    """Verify authenticated relay membership and distinguish member access from residual 403 or NIP-FI gates."""
    creds = resolve_credentials(env_file=env_file, relay_url=relay_url)
    if not creds["relay_url"]:
        raise BuzzValidationError("Relay URL is required via --relay, BUZZ_RELAY_URL, or --env-file.")
    if not creds["key_classification"]["valid"]:
        raise BuzzValidationError("A valid BUZZ_PRIVATE_KEY (nsec1... or 64-char hex) is required for membership-check.")

    probe = probe_relay(creds["relay_url"], allow_private_network=allow_private_network)
    if probe["nip11"]["requires_nip_fi"] and not creds["has_federated_token"]:
        return {
            "schema": "legends-buzz.membership-check/v1",
            "relay_url": probe["relay_url"],
            "ok": False,
            "status": "nip_fi_required",
            "key": creds["key_classification"],
            "channel_count": 0,
            "channels": [],
            "unread": None,
            "remediation": (
                "Relay advertises NIP-FI federated identity requirements. Provide BUZZ_FEDERATED_IDENTITY_TOKEN "
                "(and optional BUZZ_FEDERATED_IDENTITY_ADAPTER) or complete enterprise SSO pairing."
            ),
        }

    ch_res = run_buzz_cli(
        ["channels", "list", "--format", "json"],
        relay_url=probe["relay_url"],
        private_key=creds["private_key"],
        federated_token=creds["federated_token"],
        federated_adapter=creds["federated_adapter"],
        buzz_bin=buzz_bin,
    )

    combined_err = f"{ch_res['stderr']} {ch_res['stdout']}".lower()
    if not ch_res["ok"]:
        if "403" in combined_err or "relay_membership_required" in combined_err or "not a member" in combined_err:
            status = "residual_403"
            remediation = (
                "Identity authenticated cryptographically (NIP-OA), but the relay returned HTTP 403 "
                "(relay_membership_required). Redeem a valid /invite/<token> link in Buzz Desktop or ask a relay "
                "admin to add your npub via buzz relay members add."
            )
        elif "federated" in combined_err or "nip-fi" in combined_err:
            status = "nip_fi_required"
            remediation = "Relay rejected request due to missing or expired BUZZ_FEDERATED_IDENTITY_TOKEN."
        else:
            status = "auth_or_api_error"
            remediation = f"CLI exited with code {ch_res['exit_code']}: {ch_res['stderr'] or ch_res['stdout']}"
        return {
            "schema": "legends-buzz.membership-check/v1",
            "relay_url": probe["relay_url"],
            "ok": False,
            "status": status,
            "exit_code": ch_res["exit_code"],
            "key": creds["key_classification"],
            "channel_count": 0,
            "channels": [],
            "unread": None,
            "remediation": remediation,
        }

    raw_channels = ch_res["json"]
    if isinstance(raw_channels, dict) and "channels" in raw_channels:
        channel_list = raw_channels["channels"]
    elif isinstance(raw_channels, list):
        channel_list = raw_channels
    else:
        channel_list = []

    summarized_channels = []
    for item in channel_list:
        if isinstance(item, dict):
            summarized_channels.append(
                {
                    "id": item.get("id") or item.get("channel_id"),
                    "name": item.get("name"),
                    "channel_type": item.get("channel_type") or item.get("type"),
                    "visibility": item.get("visibility") or item.get("access"),
                }
            )

    unread_summary: Any = None
    inv = cli_inventory(buzz_bin=buzz_bin)
    if inv.get("generation") == "1.0.0+":
        unread_res = run_buzz_cli(
            ["channels", "unread", "--format", "json"],
            relay_url=probe["relay_url"],
            private_key=creds["private_key"],
            federated_token=creds["federated_token"],
            federated_adapter=creds["federated_adapter"],
            buzz_bin=buzz_bin,
        )
        if unread_res["ok"]:
            unread_summary = unread_res["json"]

    return {
        "schema": "legends-buzz.membership-check/v1",
        "relay_url": probe["relay_url"],
        "ok": True,
        "status": "member",
        "exit_code": 0,
        "key": creds["key_classification"],
        "channel_count": len(summarized_channels),
        "channels": summarized_channels,
        "unread": unread_summary,
        "remediation": None,
    }


def owner_access_audit(
    relay_url: str | None = None,
    env_file: Path | None = None,
    expected_pubkey: str | None = None,
    allow_channels: tuple[str, ...] = (),
    buzz_bin: str | Path | None = None,
    allow_private_network: bool = False,
) -> dict[str, Any]:
    """Audit active shared channels on a Buzz relay to verify owner/admin governance coverage."""
    membership = membership_check(
        relay_url=relay_url,
        env_file=env_file,
        buzz_bin=buzz_bin,
        allow_private_network=allow_private_network,
    )
    if membership["status"] != "member":
        return {
            "schema": "legends-buzz.owner-access-audit/v1",
            "relay_url": membership["relay_url"],
            "ok": False,
            "membership_status": membership["status"],
            "remediation": membership["remediation"],
            "audited_channels": [],
            "gaps": [],
        }

    creds = resolve_credentials(env_file=env_file, relay_url=relay_url)
    allow_set = {item.strip() for item in allow_channels if item.strip()}
    expected_norm = normalize_pubkey(expected_pubkey) if expected_pubkey else None

    audited: list[dict[str, Any]] = []
    gaps: list[dict[str, Any]] = []
    seen_shared_names: dict[str, list[str]] = {}

    for ch in membership["channels"]:
        ch_id = str(ch.get("id") or "").strip()
        ch_name = str(ch.get("name") or ch_id)
        if not ch_id:
            continue
        if ch_id in allow_set or ch_name in allow_set:
            audited.append({"id": ch_id, "name": ch_name, "status": "allowlisted_skip"})
            continue
        if ch_name == "DM" or str(ch.get("channel_type") or "").lower() == "dm":
            audited.append({"id": ch_id, "name": ch_name, "status": "dm_skip"})
            continue
        if "huddle" in ch_name.lower():
            audited.append({"id": ch_id, "name": ch_name, "status": "ephemeral_huddle_skip"})
            continue

        norm_name = ch_name.strip().lower()
        seen_shared_names.setdefault(norm_name, []).append(ch_id)

        mem_res = run_buzz_cli(
            ["channels", "members", "--channel", ch_id, "--format", "json"],
            relay_url=membership["relay_url"],
            private_key=creds["private_key"],
            federated_token=creds["federated_token"],
            federated_adapter=creds["federated_adapter"],
            buzz_bin=buzz_bin,
        )
        if not mem_res["ok"]:
            gap = {
                "id": ch_id,
                "name": ch_name,
                "reason": "members_query_failed",
                "detail": mem_res["stderr"] or mem_res["stdout"],
            }
            gaps.append(gap)
            audited.append(gap)
            continue

        payload = mem_res["json"]
        if isinstance(payload, dict) and "members" in payload:
            members = payload["members"]
        elif isinstance(payload, list):
            members = payload
        else:
            members = []

        if len(members) == 0:
            audited.append(
                {
                    "id": ch_id,
                    "name": ch_name,
                    "member_count": 0,
                    "admin_or_owner_count": 0,
                    "expected_owner_present": True,
                    "status": "open_default_channel",
                }
            )
            continue

        owners_and_admins = [
            m
            for m in members
            if isinstance(m, dict) and str(m.get("role", "")).lower() in ("owner", "admin")
        ]
        matched_expected = True
        if expected_norm:
            matched_expected = any(
                expected_norm in (
                    str(m.get("pubkey", "")).lower(),
                    str(m.get("npub", "")).lower(),
                )
                for m in owners_and_admins
            )

        entry = {
            "id": ch_id,
            "name": ch_name,
            "member_count": len(members),
            "admin_or_owner_count": len(owners_and_admins),
            "expected_owner_present": matched_expected,
            "status": "ok" if (owners_and_admins and matched_expected) else "governance_gap",
        }
        audited.append(entry)
        if entry["status"] != "ok":
            gaps.append(entry)

    duplicate_channel_names = {
        name: ids for name, ids in seen_shared_names.items() if len(ids) > 1
    }

    return {
        "schema": "legends-buzz.owner-access-audit/v1",
        "relay_url": membership["relay_url"],
        "ok": len(gaps) == 0,
        "membership_status": "member",
        "expected_pubkey_normalized": expected_norm,
        "audited_count": len(audited),
        "gap_count": len(gaps),
        "duplicate_channel_names": duplicate_channel_names,
        "audited_channels": audited,
        "gaps": gaps,
    }


def _parse_imeta_tag(parts: list[Any]) -> dict[str, str]:
    fields: dict[str, str] = {}
    for part in parts:
        raw = str(part)
        key, sep, value = raw.partition(" ")
        if sep and key and value:
            fields[key.lower()] = value
    return fields


def thread_context(
    channel_id: str,
    event_id: str,
    relay_url: str | None = None,
    env_file: Path | None = None,
    limit: int = 20,
    buzz_bin: str | Path | None = None,
    allow_private_network: bool = False,
) -> dict[str, Any]:
    """Reconstruct the connected Nostr kind:9 reply thread for an event without leaking unrelated shared-channel chatter."""
    try:
        canonical_channel = str(uuid.UUID(str(channel_id).strip()))
    except (ValueError, AttributeError) as exc:
        raise BuzzValidationError("channel_id must be a canonical UUID.") from exc

    canonical_event = str(event_id or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", canonical_event):
        raise BuzzValidationError("event_id must be 64 hexadecimal characters.")
    if limit < 1 or limit > 50:
        raise BuzzValidationError("limit must be between 1 and 50.")

    creds = resolve_credentials(env_file=env_file, relay_url=relay_url)
    if not creds["relay_url"]:
        raise BuzzValidationError("Relay URL is required via --relay, BUZZ_RELAY_URL, or --env-file.")
    if not creds["key_classification"]["valid"]:
        raise BuzzValidationError("A valid BUZZ_PRIVATE_KEY is required for thread-context.")

    validated = validate_relay_url(creds["relay_url"], allow_private_network=allow_private_network)
    base_url = validated["http_url"]

    msg_res = run_buzz_cli(
        ["messages", "get", "--channel", canonical_channel, "--limit", "200", "--format", "json"],
        relay_url=base_url,
        private_key=creds["private_key"],
        federated_token=creds["federated_token"],
        federated_adapter=creds["federated_adapter"],
        buzz_bin=buzz_bin,
    )
    if not msg_res["ok"] or not isinstance(msg_res["json"], list):
        raise BuzzOperationError(f"Failed to read channel messages: {msg_res['stderr'] or msg_res['stdout']}")

    events = [item for item in msg_res["json"] if isinstance(item, dict)]
    by_id = {str(item.get("id", "")).lower(): item for item in events if item.get("id")}
    if canonical_event not in by_id:
        raise BuzzOperationError(f"Target event {canonical_event} was not found in recent history for channel {canonical_channel}.")

    connected = {canonical_event}
    changed = True
    while changed:
        changed = False
        for item in events:
            item_id = str(item.get("id", "")).lower()
            tags = item.get("tags") if isinstance(item.get("tags"), list) else []
            replies = {
                str(tag[1]).lower()
                for tag in tags
                if isinstance(tag, list) and len(tag) >= 2 and tag[0] == "e"
            }
            if item_id in connected or (replies & connected):
                before = len(connected)
                connected.add(item_id)
                connected.update(reply for reply in replies if reply in by_id)
                if len(connected) != before:
                    changed = True

    dm_fallback_used = False
    if len(connected) <= 1:
        ch_meta = run_buzz_cli(
            ["channels", "get", "--channel", canonical_channel, "--format", "json"],
            relay_url=base_url,
            private_key=creds["private_key"],
            federated_token=creds["federated_token"],
            federated_adapter=creds["federated_adapter"],
            buzz_bin=buzz_bin,
        )
        is_dm = False
        if ch_meta["ok"] and isinstance(ch_meta["json"], dict):
            ch_obj = ch_meta["json"]
            is_dm = (
                str(ch_obj.get("name", "")).strip().upper() == "DM"
                or str(ch_obj.get("channel_type", "")).strip().lower() == "dm"
            )
        if is_dm:
            dm_fallback_used = True
            thread_items = sorted(events, key=lambda x: int(x.get("created_at", 0)))[-limit:]
        else:
            thread_items = [by_id[canonical_event]]
    else:
        thread_items = sorted(
            (item for item in events if str(item.get("id", "")).lower() in connected),
            key=lambda x: int(x.get("created_at", 0)),
        )[-limit:]

    messages_out: list[dict[str, Any]] = []
    attachments_out: list[dict[str, str]] = []
    participants: list[str] = []
    transcript_lines = [f"Buzz Thread Context ({len(thread_items)} messages):"]

    for item in thread_items:
        ev_id = str(item.get("id", "")).lower()
        author = str(item.get("pubkey", "unknown")).lower()
        if author not in participants:
            participants.append(author)
        created_at = int(item.get("created_at", 0))
        iso_stamp = dt.datetime.fromtimestamp(created_at, tz=dt.timezone.utc).isoformat()
        content = re.sub(r"\s+", " ", str(item.get("content", ""))).strip()[:2000]
        tags = item.get("tags") if isinstance(item.get("tags"), list) else []
        ev_attachments: list[dict[str, str]] = []
        for tag in tags:
            if isinstance(tag, list) and len(tag) >= 2 and tag[0] == "imeta":
                parsed_imeta = _parse_imeta_tag(tag[1:])
                if parsed_imeta.get("url"):
                    att = {
                        "event_id": ev_id,
                        "url": parsed_imeta.get("url", ""),
                        "sha256": parsed_imeta.get("x", "").lower(),
                        "mime": parsed_imeta.get("m", "").lower(),
                    }
                    ev_attachments.append(att)
                    attachments_out.append(att)

        messages_out.append(
            {
                "id": ev_id,
                "pubkey": author,
                "created_at": created_at,
                "timestamp": iso_stamp,
                "content": content,
                "attachments": ev_attachments,
            }
        )
        transcript_lines.append(f"[{iso_stamp}] author={author[:12]} event={ev_id[:12]}: {content}")

    return {
        "schema": "legends-buzz.thread-context/v1",
        "ok": True,
        "relay_url": base_url,
        "channel_id": canonical_channel,
        "target_event_id": canonical_event,
        "isolation_mode": "dm_chronological_fallback" if dm_fallback_used else "connected_reply_component",
        "dm_chronological_fallback": dm_fallback_used,
        "message_count": len(messages_out),
        "participant_count": len(participants),
        "participants": participants,
        "attachments": attachments_out,
        "messages": messages_out,
        "transcript": "\n".join(transcript_lines),
    }


MAX_MEDIA_DOCUMENT_BYTES = 30 * 1024 * 1024
MAX_EXTRACTED_TEXT_CHARS = 30_000
ALLOWED_MEDIA_MIMES = frozenset(
    {
        "text/plain",
        "text/markdown",
        "text/csv",
        "application/json",
        "application/xml",
        "text/xml",
        "application/pdf",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/octet-stream",
        "audio/mpeg",
        "audio/wav",
        "audio/x-wav",
        "audio/mp4",
        "audio/x-m4a",
        "audio/ogg",
        "audio/flac",
        "audio/webm",
        "video/mp4",
    }
)


def validate_media_url(relay_url: str, media_url: str, expected_sha256: str) -> dict[str, str]:
    """Enforce same-relay HTTPS origin and /media/<64hex> content-addressed path binding."""
    sha_norm = str(expected_sha256 or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", sha_norm):
        raise BuzzValidationError("expected_sha256 must be 64 hexadecimal characters.")

    relay_parts = urllib.parse.urlsplit(relay_url.replace("wss://", "https://", 1))
    media_parts = urllib.parse.urlsplit(str(media_url or "").strip())
    if (
        relay_parts.scheme != "https"
        or media_parts.scheme != "https"
        or not relay_parts.hostname
        or not media_parts.hostname
        or relay_parts.hostname.lower() != media_parts.hostname.lower()
        or (relay_parts.port or 443) != (media_parts.port or 443)
        or media_parts.username
        or media_parts.password
        or media_parts.query
        or media_parts.fragment
    ):
        raise BuzzSecurityError("Refusing media URL: only same-relay HTTPS Buzz media URLs are accepted.")

    match = re.fullmatch(r"/media/([0-9a-fA-F]{64})(?:\.([A-Za-z0-9]{1,8}))?", media_parts.path)
    if not match or match.group(1).lower() != sha_norm:
        raise BuzzSecurityError("Refusing media URL: path does not match /media/<expected_sha256>.")

    return {
        "normalized_url": urllib.parse.urlunsplit(
            ("https", media_parts.netloc, media_parts.path, "", "")
        ),
        "sha256": sha_norm,
        "extension": (match.group(2) or "").lower(),
    }


def verify_media_magic_bytes(data: bytes, mime_type: str, filename: str = "") -> bool:
    """Verify file magic bytes match the declared MIME type before parsing."""
    probe = data[:4096]
    head = probe[:16]
    mime = mime_type.strip().lower()
    if mime == "application/pdf":
        return head.startswith(b"%PDF-")
    if mime.endswith("wordprocessingml.document") or mime.endswith("spreadsheetml.sheet"):
        return head.startswith(b"PK\x03\x04")
    if mime in {"text/plain", "text/markdown", "text/csv", "application/json", "application/xml", "text/xml"}:
        return b"\x00" not in probe
    if mime == "application/octet-stream":
        ext = Path(filename).suffix.lower()
        return ext in {".txt", ".md", ".csv", ".tsv", ".json", ".xml"} and (b"\x00" not in probe)
    if mime in {"audio/wav", "audio/x-wav"}:
        return head.startswith(b"RIFF") and head[8:12] == b"WAVE"
    if mime == "audio/mpeg":
        return head.startswith(b"ID3") or (len(head) >= 2 and head[0] == 0xFF and (head[1] & 0xE0) == 0xE0)
    if mime in {"audio/mp4", "audio/x-m4a", "video/mp4"}:
        return len(head) >= 12 and head[4:8] == b"ftyp"
    if mime == "audio/ogg":
        return head.startswith(b"OggS")
    if mime == "audio/flac":
        return head.startswith(b"fLaC")
    if mime == "audio/webm":
        return head.startswith(b"\x1aE\xdf\xa3")
    return False


def _safe_parse_xml_bytes(data: bytes) -> ET.Element:
    upper = data[:4096].upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise BuzzSecurityError("Refusing XML payload containing DOCTYPE or ENTITY declarations (XXE guard).")
    return ET.fromstring(data)


def _open_bounded_zip(path: Path) -> zipfile.ZipFile:
    archive = zipfile.ZipFile(path)
    total_uncompressed = sum(info.file_size for info in archive.infolist())
    if len(archive.infolist()) > 5000 or total_uncompressed > 60 * 1024 * 1024:
        archive.close()
        raise BuzzSecurityError("Refusing Office archive that exceeds 5,000 entries or 60 MB uncompressed (zip-bomb guard).")
    return archive


def _extract_docx_text(path: Path) -> str:
    with _open_bounded_zip(path) as archive:
        try:
            root = _safe_parse_xml_bytes(archive.read("word/document.xml"))
        except KeyError as exc:
            raise BuzzOperationError("DOCX archive contains no word/document.xml body.") from exc
    paragraphs: list[str] = []
    for node in root.iter():
        if node.tag.endswith("}p"):
            text = "".join((child.text or "") for child in node.iter() if child.tag.endswith("}t")).strip()
            if text:
                paragraphs.append(text)
    return "\n".join(paragraphs)


def _extract_xlsx_rows(path: Path, max_rows: int = 2000, max_cols: int = 100) -> list[list[str]]:
    with _open_bounded_zip(path) as archive:
        shared: list[str] = []
        if "xl/sharedStrings.xml" in archive.namelist():
            s_root = _safe_parse_xml_bytes(archive.read("xl/sharedStrings.xml"))
            for item in s_root:
                shared.append("".join(node.text or "" for node in item.iter() if node.tag.endswith("}t")))
        sheets = sorted(name for name in archive.namelist() if re.fullmatch(r"xl/worksheets/sheet\d+\.xml", name))[:5]
        rows: list[list[str]] = []
        for sheet in sheets:
            w_root = _safe_parse_xml_bytes(archive.read(sheet))
            for row in (node for node in w_root.iter() if node.tag.endswith("}row")):
                values: list[str] = []
                for cell in (node for node in row if node.tag.endswith("}c")):
                    val_node = next((node for node in cell if node.tag.endswith("}v")), None)
                    val = "" if val_node is None else (val_node.text or "")
                    if cell.attrib.get("t") == "s" and val.isdigit() and int(val) < len(shared):
                        val = shared[int(val)]
                    values.append(val)
                    if len(values) >= max_cols:
                        break
                rows.append(values)
                if len(rows) >= max_rows:
                    return rows
        return rows


def _profile_dataset_rows(rows: list[list[str]], filename: str) -> str:
    if not rows:
        return "Dataset contains 0 rows."
    width = min(max(len(r) for r in rows), 100)
    normalized = [(r + [""] * width)[:width] for r in rows[:10_001]]
    header = [c.strip() or f"column_{i + 1}" for i, c in enumerate(normalized[0])]
    data = normalized[1:] if len(normalized) > 1 else []
    lines = [f"Dataset: {filename}", f"Rows analyzed: {len(data)}", f"Columns: {width}"]
    for idx, col_name in enumerate(header):
        vals = [r[idx].strip() for r in data]
        present = [v for v in vals if v]
        nums: list[float] = []
        for v in present:
            cleaned = v.replace(",", "")
            if re.fullmatch(r"[-+]?(?:\d+(?:\.\d*)?|\.\d+)", cleaned):
                nums.append(float(cleaned))
        summary = f"- {col_name}: present={len(present)}, missing={len(vals) - len(present)}, unique={len(set(present))}"
        if present and len(nums) >= max(2, int(len(present) * 0.8)):
            summary += f", min={min(nums):g}, max={max(nums):g}, mean={statistics.fmean(nums):g}"
        lines.append(summary)
    return "\n".join(lines)[:MAX_EXTRACTED_TEXT_CHARS]


def inspect_media_attachment(
    channel_id: str,
    event_id: str,
    media_url: str,
    expected_sha256: str,
    mime_type: str,
    filename: str = "attachment",
    extract_mode: str = "document",
    relay_url: str | None = None,
    env_file: Path | None = None,
    buzz_bin: str | Path | None = None,
    allow_private_network: bool = False,
) -> dict[str, Any]:
    """Verify a content-addressed Buzz attachment across 5 zero-trust gates and optionally extract bounded text/data."""
    try:
        canonical_channel = str(uuid.UUID(str(channel_id).strip()))
    except (ValueError, AttributeError) as exc:
        raise BuzzValidationError("channel_id must be a canonical UUID.") from exc

    canonical_event = str(event_id or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", canonical_event):
        raise BuzzValidationError("event_id must be 64 hexadecimal characters.")

    mime_norm = str(mime_type or "").strip().lower()
    if mime_norm not in ALLOWED_MEDIA_MIMES:
        raise BuzzSecurityError(f"Unsupported or disallowed attachment MIME type: {mime_norm}")

    creds = resolve_credentials(env_file=env_file, relay_url=relay_url)
    if not creds["relay_url"]:
        raise BuzzValidationError("Relay URL is required via --relay, BUZZ_RELAY_URL, or --env-file.")
    if not creds["key_classification"]["valid"]:
        raise BuzzValidationError("A valid BUZZ_PRIVATE_KEY is required for media-inspect.")

    validated = validate_relay_url(creds["relay_url"], allow_private_network=allow_private_network)
    base_url = validated["http_url"]
    url_check = validate_media_url(base_url, media_url, expected_sha256)
    sha_norm = url_check["sha256"]

    # Gate 3: Verify imeta tag binding on the referenced event if present in recent history
    msg_res = run_buzz_cli(
        ["messages", "get", "--channel", canonical_channel, "--limit", "200", "--format", "json"],
        relay_url=base_url,
        private_key=creds["private_key"],
        federated_token=creds["federated_token"],
        federated_adapter=creds["federated_adapter"],
        buzz_bin=buzz_bin,
    )
    imeta_bound = False
    if msg_res["ok"] and isinstance(msg_res["json"], list):
        target_ev = next(
            (item for item in msg_res["json"] if isinstance(item, dict) and str(item.get("id", "")).lower() == canonical_event),
            None,
        )
        if target_ev is not None:
            tags = target_ev.get("tags") if isinstance(target_ev.get("tags"), list) else []
            for tag in tags:
                if isinstance(tag, list) and len(tag) >= 2 and tag[0] == "imeta":
                    fields = _parse_imeta_tag(tag[1:])
                    if (
                        fields.get("url") == url_check["normalized_url"]
                        and fields.get("x", "").lower() == sha_norm
                        and fields.get("m", "").lower() == mime_norm
                    ):
                        imeta_bound = True
                        break
            if not imeta_bound:
                raise BuzzSecurityError(
                    "Refusing attachment: the referenced Buzz event does not contain a matching imeta tag."
                )

    with tempfile.TemporaryDirectory(prefix="legends-buzz-media-") as tmp_dir:
        out_path = Path(tmp_dir) / "attachment.bin"
        dl_res = run_buzz_cli(
            ["media", "get", url_check["normalized_url"], "--output", str(out_path)],
            relay_url=base_url,
            private_key=creds["private_key"],
            federated_token=creds["federated_token"],
            federated_adapter=creds["federated_adapter"],
            buzz_bin=buzz_bin,
            timeout=90.0,
        )
        if not dl_res["ok"] or not out_path.is_file():
            raise BuzzOperationError(f"Failed to download media via buzz CLI: {dl_res['stderr'] or dl_res['stdout']}")

        size_bytes = out_path.stat().st_size
        if size_bytes == 0 or size_bytes > MAX_MEDIA_DOCUMENT_BYTES:
            raise BuzzSecurityError(f"Downloaded media size ({size_bytes} bytes) is empty or exceeds {MAX_MEDIA_DOCUMENT_BYTES} bytes.")

        raw_bytes = out_path.read_bytes()
        actual_sha256 = hashlib.sha256(raw_bytes).hexdigest()
        if actual_sha256 != sha_norm:
            raise BuzzSecurityError(
                f"Downloaded media SHA-256 ({actual_sha256}) does not match expected hash ({sha_norm})."
            )

        if not verify_media_magic_bytes(raw_bytes, mime_norm, filename):
            raise BuzzSecurityError(f"Downloaded media magic bytes do not match declared MIME type '{mime_norm}'.")

        extracted_content: str | None = None
        if extract_mode == "document":
            if mime_norm.endswith("wordprocessingml.document"):
                extracted_content = _extract_docx_text(out_path)[:MAX_EXTRACTED_TEXT_CHARS]
            elif mime_norm.endswith("spreadsheetml.sheet"):
                rows = _extract_xlsx_rows(out_path)
                extracted_content = "\n".join("\t".join(r) for r in rows)[:MAX_EXTRACTED_TEXT_CHARS]
            elif mime_norm in {"text/plain", "text/markdown", "text/csv", "application/json", "application/xml", "text/xml", "application/octet-stream"}:
                extracted_content = raw_bytes.decode("utf-8", errors="replace")[:MAX_EXTRACTED_TEXT_CHARS]
        elif extract_mode == "data":
            if mime_norm.endswith("spreadsheetml.sheet"):
                extracted_content = _profile_dataset_rows(_extract_xlsx_rows(out_path, max_rows=10_001), filename)
            elif mime_norm in {"text/csv", "text/plain", "application/octet-stream"}:
                text = raw_bytes.decode("utf-8", errors="replace")
                rows = list(csv.reader(text.splitlines()))[:10_001]
                extracted_content = _profile_dataset_rows(rows, filename)

    return {
        "schema": "legends-buzz.media-inspect/v1",
        "ok": True,
        "relay_url": base_url,
        "channel_id": canonical_channel,
        "event_id": canonical_event,
        "media_url": url_check["normalized_url"],
        "sha256": actual_sha256,
        "mime_type": mime_norm,
        "size_bytes": size_bytes,
        "imeta_verified": imeta_bound,
        "magic_bytes_verified": True,
        "extract_mode": extract_mode,
        "extracted_content": extracted_content,
    }


def channel_snapshot(
    channel_id: str,
    relay_url: str | None = None,
    env_file: Path | None = None,
    limit: int = 10,
    buzz_bin: str | Path | None = None,
    allow_private_network: bool = False,
) -> dict[str, Any]:
    """Capture a bounded operational snapshot of a channel's metadata, members, canvas, and recent messages."""
    if not channel_id or not str(channel_id).strip():
        raise BuzzValidationError("channel_id is required.")
    if limit < 1 or limit > 100:
        raise BuzzValidationError("limit must be between 1 and 100.")

    creds = resolve_credentials(env_file=env_file, relay_url=relay_url)
    if not creds["relay_url"]:
        raise BuzzValidationError("Relay URL is required via --relay, BUZZ_RELAY_URL, or --env-file.")
    if not creds["key_classification"]["valid"]:
        raise BuzzValidationError("A valid BUZZ_PRIVATE_KEY is required for channel-snapshot.")

    validated = validate_relay_url(creds["relay_url"], allow_private_network=allow_private_network)
    base_url = validated["http_url"]
    inv = cli_inventory(buzz_bin=buzz_bin)

    meta_res = run_buzz_cli(
        ["channels", "get", "--channel", channel_id, "--format", "json"],
        relay_url=base_url,
        private_key=creds["private_key"],
        federated_token=creds["federated_token"],
        federated_adapter=creds["federated_adapter"],
        buzz_bin=buzz_bin,
    )
    members_res = run_buzz_cli(
        ["channels", "members", "--channel", channel_id, "--format", "json"],
        relay_url=base_url,
        private_key=creds["private_key"],
        federated_token=creds["federated_token"],
        federated_adapter=creds["federated_adapter"],
        buzz_bin=buzz_bin,
    )
    canvas_res = run_buzz_cli(
        ["canvas", "get", "--channel", channel_id, "--format", "json"],
        relay_url=base_url,
        private_key=creds["private_key"],
        federated_token=creds["federated_token"],
        federated_adapter=creds["federated_adapter"],
        buzz_bin=buzz_bin,
    )
    messages_res = run_buzz_cli(
        ["messages", "get", "--channel", channel_id, "--limit", str(limit), "--format", "json"],
        relay_url=base_url,
        private_key=creds["private_key"],
        federated_token=creds["federated_token"],
        federated_adapter=creds["federated_adapter"],
        buzz_bin=buzz_bin,
    )

    raw_msgs = messages_res["json"] if messages_res["ok"] else None
    if isinstance(raw_msgs, dict) and isinstance(raw_msgs.get("messages"), list):
        parsed_messages: Any = raw_msgs["messages"]
    elif isinstance(raw_msgs, list):
        parsed_messages = raw_msgs
    elif messages_res["ok"]:
        parsed_messages = []
    else:
        parsed_messages = {"error": messages_res["stderr"] or messages_res["stdout"]}

    ok = bool(meta_res["ok"] and members_res["ok"] and messages_res["ok"])
    return {
        "schema": "legends-buzz.channel-snapshot/v1",
        "ok": ok,
        "relay_url": base_url,
        "channel_id": channel_id,
        "message_format_used": "json",
        "supports_format_agent": bool(inv.get("supports_format_agent")),
        "metadata": meta_res["json"] if meta_res["ok"] else {"error": meta_res["stderr"] or meta_res["stdout"]},
        "members": members_res["json"] if members_res["ok"] else {"error": members_res["stderr"] or members_res["stdout"]},
        "canvas": canvas_res["json"] if canvas_res["ok"] else {"error": canvas_res["stderr"] or canvas_res["stdout"]},
        "messages": parsed_messages,
    }


def message_canary(
    channel_id: str,
    relay_url: str | None = None,
    env_file: Path | None = None,
    buzz_bin: str | Path | None = None,
    apply: bool = False,
    confirm_plan: str | None = None,
    allow_private_network: bool = False,
) -> dict[str, Any]:
    """Preview-first SHA-256 plan-gated disposable message canary (send -> readback -> react -> unreact -> delete)."""
    if not channel_id or not str(channel_id).strip():
        raise BuzzValidationError("channel_id is required.")

    creds = resolve_credentials(env_file=env_file, relay_url=relay_url)
    if not creds["relay_url"]:
        raise BuzzValidationError("Relay URL is required via --relay, BUZZ_RELAY_URL, or --env-file.")
    if not creds["key_classification"]["valid"]:
        raise BuzzValidationError("A valid BUZZ_PRIVATE_KEY is required for message-canary.")

    validated = validate_relay_url(creds["relay_url"], allow_private_network=allow_private_network)
    base_url = validated["http_url"]
    plan_payload = {
        "operation": "message-canary",
        "relay_url": base_url,
        "channel_id": channel_id.strip(),
        "key_fingerprint": creds["key_classification"]["fingerprint"],
        "steps": [
            "messages send --channel <channel> --content <disposable-canary-text> --format json",
            "messages get --channel <channel> --limit 5 --format json",
            "reactions add --event <event-id> --emoji 👍 --format json",
            "reactions remove --event <event-id> --emoji 👍 --format json",
            "messages delete --event <event-id> --format json",
        ],
    }
    plan_canonical = json.dumps(plan_payload, sort_keys=True, separators=(",", ":"))
    plan_sha256 = hashlib.sha256(plan_canonical.encode("utf-8")).hexdigest()

    if not apply:
        return {
            "schema": "legends-buzz.message-canary/v1",
            "mode": "preview",
            "executed": False,
            "plan_sha256": plan_sha256,
            "plan": plan_payload,
            "next_step": (
                f"Re-run with --apply --confirm-plan {plan_sha256} to execute the disposable canary."
            ),
        }

    if not confirm_plan or confirm_plan.strip().lower() != plan_sha256.lower():
        raise BuzzSecurityError(
            f"Refusing live canary mutation: --confirm-plan does not match preview plan_sha256 ({plan_sha256})."
        )

    canary_nonce = hashlib.sha256(f"{time.time_ns()}:{channel_id}".encode("utf-8")).hexdigest()[:10]
    canary_text = f"[legends-buzz canary {canary_nonce}] disposable verification probe"

    send_res = run_buzz_cli(
        ["messages", "send", "--channel", channel_id, "--content", canary_text, "--format", "json"],
        relay_url=base_url,
        private_key=creds["private_key"],
        federated_token=creds["federated_token"],
        federated_adapter=creds["federated_adapter"],
        buzz_bin=buzz_bin,
    )
    if not send_res["ok"] or not isinstance(send_res["json"], dict):
        raise BuzzOperationError(f"Canary send failed: {send_res['stderr'] or send_res['stdout']}")

    sent_obj = send_res["json"]
    event_id = str(sent_obj.get("id") or sent_obj.get("event_id") or "").strip()
    if not event_id:
        raise BuzzOperationError("Canary send succeeded but returned no event id.")

    readback_ok = False
    react_add_ok = False
    react_remove_ok = False
    delete_ok = False
    try:
        get_res = run_buzz_cli(
            ["messages", "get", "--channel", channel_id, "--limit", "5", "--format", "json"],
            relay_url=base_url,
            private_key=creds["private_key"],
            federated_token=creds["federated_token"],
            federated_adapter=creds["federated_adapter"],
            buzz_bin=buzz_bin,
        )
        readback_ok = get_res["ok"] and (event_id in get_res["stdout"])

        react_res = run_buzz_cli(
            ["reactions", "add", "--event", event_id, "--emoji", "👍", "--format", "json"],
            relay_url=base_url,
            private_key=creds["private_key"],
            federated_token=creds["federated_token"],
            federated_adapter=creds["federated_adapter"],
            buzz_bin=buzz_bin,
        )
        react_add_ok = react_res["ok"]

        unreact_res = run_buzz_cli(
            ["reactions", "remove", "--event", event_id, "--emoji", "👍", "--format", "json"],
            relay_url=base_url,
            private_key=creds["private_key"],
            federated_token=creds["federated_token"],
            federated_adapter=creds["federated_adapter"],
            buzz_bin=buzz_bin,
        )
        react_remove_ok = unreact_res["ok"]
    finally:
        del_res = run_buzz_cli(
            ["messages", "delete", "--event", event_id, "--format", "json"],
            relay_url=base_url,
            private_key=creds["private_key"],
            federated_token=creds["federated_token"],
            federated_adapter=creds["federated_adapter"],
            buzz_bin=buzz_bin,
        )
        delete_ok = del_res["ok"]

    all_ok = bool(readback_ok and react_add_ok and react_remove_ok and delete_ok)
    return {
        "schema": "legends-buzz.message-canary/v1",
        "mode": "apply",
        "executed": True,
        "ok": all_ok,
        "plan_sha256": plan_sha256,
        "relay_url": base_url,
        "channel_id": channel_id,
        "canary_event_id": event_id,
        "steps": {
            "send": True,
            "readback": readback_ok,
            "react_add": react_add_ok,
            "react_remove": react_remove_ok,
            "cleanup_delete": delete_ok,
        },
    }


def doctor_report(
    live: bool = False,
    relay_url: str | None = None,
    env_file: Path | None = None,
    buzz_bin: str | Path | None = None,
    install_dir: Path | None = None,
    allow_private_network: bool = False,
) -> dict[str, Any]:
    """Generate an offline or live readiness report for legends-buzz."""
    res = resource_info()
    creds = resolve_credentials(env_file=env_file, relay_url=relay_url)
    cli_info = cli_inventory(buzz_bin=buzz_bin)
    desktop_info = audit_desktop_install(install_dir=install_dir, cli_bin=Path(buzz_bin) if buzz_bin else None)

    live_probe: dict[str, Any] | None = None
    live_membership: dict[str, Any] | None = None
    if live:
        if not creds["relay_url"]:
            raise BuzzValidationError("doctor --live requires a relay URL (--relay, BUZZ_RELAY_URL, or --env-file).")
        live_probe = probe_relay(creds["relay_url"], allow_private_network=allow_private_network)
        if creds["key_classification"]["valid"] and cli_info["found"]:
            live_membership = membership_check(
                relay_url=creds["relay_url"],
                env_file=env_file,
                buzz_bin=buzz_bin,
                allow_private_network=allow_private_network,
            )

    offline_ok = bool(res["complete"] and not desktop_info["ntfs_case_collision_detected"])
    live_ok = True
    if live:
        live_ok = bool(live_probe and live_probe["healthy"])
        if live_membership is not None:
            live_ok = live_ok and (live_membership["status"] == "member")

    return {
        "schema": "legends-buzz.doctor/v1",
        "module": "legends-buzz",
        "ok": offline_ok and live_ok,
        "mode": "live" if live else "offline",
        "resources": {
            "source": res["source"],
            "complete": res["complete"],
            "pack_manifest": res["pack_manifest"],
            "blueprint_count": len(res["blueprints"]),
        },
        "credentials": {
            "relay_url": creds["relay_url"],
            "key": creds["key_classification"],
            "has_federated_token": creds["has_federated_token"],
            "env_file": creds["env_file"],
        },
        "cli": cli_info,
        "desktop": {
            "install_dir": desktop_info["install_dir"],
            "healthy": desktop_info["healthy"],
            "ntfs_case_collision_detected": desktop_info["ntfs_case_collision_detected"],
            "finding_count": len(desktop_info["findings"]),
            "findings": desktop_info["findings"],
        },
        "live_probe": live_probe,
        "live_membership": live_membership,
    }
