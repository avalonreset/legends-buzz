"""legends-buzz: Self-hosted Block Buzz relay operations, 26-domain MCP-to-CLI routing, and desktop/relay verification."""
from __future__ import annotations

__version__ = "0.1.3"

from .api import (
    BuzzOperationError,
    BuzzSecurityError,
    BuzzValidationError,
    channel_snapshot,
    classify_key,
    cli_inventory,
    doctor_report,
    inspect_media_attachment,
    membership_check,
    message_canary,
    normalize_pubkey,
    owner_access_audit,
    parse_env_file,
    probe_relay,
    resolve_buzz_binary,
    run_buzz_cli,
    scrub_secrets,
    thread_context,
    validate_channel_uuid,
    validate_event_hex64,
    validate_media_url,
    validate_relay_url,
    verify_media_magic_bytes,
)
from .blueprints import BLUEPRINTS, build_relay_upgrade_plan, get_blueprint, list_blueprints
from .desktop import audit_desktop_install, inspect_pe_file, scan_embedded_frontend_assets
from .mcp_map import ENV_VARS, EXIT_CODES, MCP_DOMAINS, query_mcp_map, render_mcp_map_markdown
from .resources import resource_info

__all__ = [
    "__version__",
    "BLUEPRINTS",
    "BuzzOperationError",
    "BuzzSecurityError",
    "BuzzValidationError",
    "ENV_VARS",
    "EXIT_CODES",
    "MCP_DOMAINS",
    "audit_desktop_install",
    "build_relay_upgrade_plan",
    "channel_snapshot",
    "classify_key",
    "cli_inventory",
    "doctor_report",
    "get_blueprint",
    "inspect_media_attachment",
    "inspect_pe_file",
    "list_blueprints",
    "membership_check",
    "message_canary",
    "normalize_pubkey",
    "owner_access_audit",
    "parse_env_file",
    "probe_relay",
    "query_mcp_map",
    "render_mcp_map_markdown",
    "resolve_buzz_binary",
    "resource_info",
    "run_buzz_cli",
    "scan_embedded_frontend_assets",
    "scrub_secrets",
    "thread_context",
    "validate_channel_uuid",
    "validate_event_hex64",
    "validate_media_url",
    "validate_relay_url",
    "verify_media_magic_bytes",
]
