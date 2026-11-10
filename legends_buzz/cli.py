"""Command-line interface for legends-buzz."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

from . import __version__
from .api import (
    BuzzOperationError,
    BuzzSecurityError,
    BuzzValidationError,
    channel_snapshot,
    check_no_symlink_chain,
    cli_inventory,
    doctor_report,
    inspect_media_attachment,
    membership_check,
    message_canary,
    owner_access_audit,
    probe_relay,
    scrub_secrets,
    thread_context,
)
from .blueprints import build_relay_upgrade_plan, get_blueprint, list_blueprints
from .desktop import audit_desktop_install
from .mcp_map import query_mcp_map, render_mcp_map_markdown
from .resources import resource_info


def _safe_write_file(target: Path, content: str, *, overwrite: bool = False) -> None:
    check_no_symlink_chain(target)
    if target.exists() and not overwrite:
        raise BuzzSecurityError(f"Refusing to overwrite existing file without --overwrite: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def _emit_json(
    payload: dict[str, Any],
    output_path: Path | None = None,
    *,
    overwrite: bool = False,
) -> None:
    rendered = json.dumps(payload, indent=2, sort_keys=False) + "\n"
    if output_path is not None:
        _safe_write_file(output_path, rendered, overwrite=overwrite)
    sys.stdout.write(rendered)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="legends-buzz",
        description=(
            "Self-hosted Block Buzz relay operations, 26-domain MCP-to-CLI routing, "
            "and desktop/relay verification for AI coding agents."
        ),
    )
    parser.add_argument("--version", action="version", version=f"legends-buzz {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    doc_p = sub.add_parser("doctor", help="Run offline or live readiness diagnostics for legends-buzz.")
    doc_p.add_argument("--live", action="store_true", help="Include live relay readiness and membership checks.")
    doc_p.add_argument("--relay", default=None, help="Target Buzz relay URL (https://...).")
    doc_p.add_argument("--env-file", type=Path, default=None, help="Optional .env file containing BUZZ_PRIVATE_KEY.")
    doc_p.add_argument("--buzz-bin", default=None, help="Explicit path to console buzz CLI binary.")
    doc_p.add_argument("--install-dir", type=Path, default=None, help="Buzz Desktop install directory to audit.")
    doc_p.add_argument("--allow-private-network", action="store_true", help="Allow private/loopback relay URLs in lab tests.")
    doc_p.add_argument("--json", action="store_true", help="Emit structured JSON output.")

    res_p = sub.add_parser("resources", help="Emit machine-readable paths for the knowledge pack, recipe, and blueprints.")
    res_p.add_argument("--output", type=Path, default=None, help="Optional output file path for resources JSON.")
    res_p.add_argument("--overwrite", action="store_true", help="Overwrite --output file if it already exists.")
    res_p.add_argument("--json", action="store_true", help="Emit structured JSON output.")

    mcp_p = sub.add_parser("mcp-map", help="Query the 26-domain / 108-subcommand MCP-to-CLI reference map.")
    mcp_p.add_argument("--domain", default=None, help="Filter to a single Buzz command domain (e.g. messages, projects).")
    mcp_p.add_argument("--intent", default=None, help="Search subcommands by natural-language intent.")
    mcp_p.add_argument("--format", choices=("json", "markdown"), default="json", help="Output format (json or markdown).")
    mcp_p.add_argument("--output", type=Path, default=None, help="Optional file path to write output.")
    mcp_p.add_argument("--overwrite", action="store_true", help="Overwrite --output file if it already exists.")

    inv_p = sub.add_parser("cli-inventory", help="Inspect the installed buzz CLI binary and its command groups.")
    inv_p.add_argument("--buzz-bin", default=None, help="Explicit path to console buzz CLI binary.")
    inv_p.add_argument("--json", action="store_true", help="Emit structured JSON output.")

    desk_p = sub.add_parser(
        "desktop-audit",
        help="Audit a Buzz Desktop installation for Windows NTFS Buzz.exe/buzz.exe collisions and embedded assets.",
    )
    desk_p.add_argument("--install-dir", type=Path, default=None, help="Buzz Desktop installation directory.")
    desk_p.add_argument("--cli-bin", type=Path, default=None, help="Optional explicit buzz CLI binary to inspect.")
    desk_p.add_argument("--json", action="store_true", help="Emit structured JSON output.")

    probe_p = sub.add_parser("relay-probe", help="Probe a Buzz relay's /_readiness, /health, and NIP-11 metadata.")
    probe_p.add_argument("--relay", required=True, help="Target Buzz relay URL (https://... or wss://...).")
    probe_p.add_argument("--allow-private-network", action="store_true", help="Allow private/loopback IPs for local labs.")
    probe_p.add_argument("--timeout", type=float, default=10.0, help="HTTP request timeout in seconds.")
    probe_p.add_argument("--json", action="store_true", help="Emit structured JSON output.")

    mem_p = sub.add_parser(
        "membership-check",
        help="Verify authenticated relay membership and distinguish member access from residual 403 or NIP-FI gates.",
    )
    mem_p.add_argument("--relay", default=None, help="Target Buzz relay URL.")
    mem_p.add_argument("--env-file", type=Path, default=None, help="Optional .env file containing BUZZ_PRIVATE_KEY.")
    mem_p.add_argument("--buzz-bin", default=None, help="Explicit path to console buzz CLI binary.")
    mem_p.add_argument("--allow-private-network", action="store_true", help="Allow private/loopback relay URLs.")
    mem_p.add_argument("--json", action="store_true", help="Emit structured JSON output.")

    own_p = sub.add_parser(
        "owner-access-audit",
        help="Audit active shared channels on a Buzz relay to verify owner/admin governance coverage.",
    )
    own_p.add_argument("--relay", default=None, help="Target Buzz relay URL.")
    own_p.add_argument("--env-file", type=Path, default=None, help="Optional .env file containing BUZZ_PRIVATE_KEY.")
    own_p.add_argument("--expected-pubkey", default=None, help="Expected owner hex pubkey or npub.")
    own_p.add_argument(
        "--allow-channel",
        action="append",
        default=[],
        help="Channel ID or name to allowlist/skip (may be passed multiple times).",
    )
    own_p.add_argument("--buzz-bin", default=None, help="Explicit path to console buzz CLI binary.")
    own_p.add_argument("--allow-private-network", action="store_true", help="Allow private/loopback relay URLs.")
    own_p.add_argument("--json", action="store_true", help="Emit structured JSON output.")

    snap_p = sub.add_parser(
        "channel-snapshot",
        help="Capture a bounded operational snapshot of a channel's metadata, members, canvas, and messages.",
    )
    snap_p.add_argument("--channel", required=True, help="Target channel UUID.")
    snap_p.add_argument("--relay", default=None, help="Target Buzz relay URL.")
    snap_p.add_argument("--env-file", type=Path, default=None, help="Optional .env file containing BUZZ_PRIVATE_KEY.")
    snap_p.add_argument("--limit", type=int, default=10, help="Maximum recent messages to fetch (1..100).")
    snap_p.add_argument("--buzz-bin", default=None, help="Explicit path to console buzz CLI binary.")
    snap_p.add_argument("--allow-private-network", action="store_true", help="Allow private/loopback relay URLs.")
    snap_p.add_argument("--json", action="store_true", help="Emit structured JSON output.")

    thr_p = sub.add_parser(
        "thread-context",
        help="Reconstruct the connected Nostr kind:9 reply thread for an event without leaking unrelated channel chatter.",
    )
    thr_p.add_argument("--channel", required=True, help="Target channel UUID.")
    thr_p.add_argument("--event", required=True, help="Target 64-character hex Nostr event ID.")
    thr_p.add_argument("--relay", default=None, help="Target Buzz relay URL.")
    thr_p.add_argument("--env-file", type=Path, default=None, help="Optional .env file containing BUZZ_PRIVATE_KEY.")
    thr_p.add_argument("--limit", type=int, default=20, help="Maximum connected thread messages to return (1..50).")
    thr_p.add_argument("--buzz-bin", default=None, help="Explicit path to console buzz CLI binary.")
    thr_p.add_argument("--allow-private-network", action="store_true", help="Allow private/loopback relay URLs.")
    thr_p.add_argument("--json", action="store_true", help="Emit structured JSON output.")

    med_p = sub.add_parser(
        "media-inspect",
        help="Verify a content-addressed Buzz attachment across 5 zero-trust gates and extract bounded text/data.",
    )
    med_p.add_argument("--channel", required=True, help="Target channel UUID.")
    med_p.add_argument("--event", required=True, help="Referenced 64-character hex Nostr event ID.")
    med_p.add_argument("--url", required=True, help="Same-relay HTTPS /media/<sha256> attachment URL.")
    med_p.add_argument("--sha256", required=True, help="Expected 64-character hex SHA-256 digest.")
    med_p.add_argument("--mime", required=True, help="Declared MIME type (e.g. text/csv, application/json).")
    med_p.add_argument("--filename", default="attachment", help="Optional display filename.")
    med_p.add_argument(
        "--extract-mode",
        choices=("none", "document", "data"),
        default="document",
        help="Extraction mode after 5-gate verification (none, document, or data).",
    )
    med_p.add_argument("--relay", default=None, help="Target Buzz relay URL.")
    med_p.add_argument("--env-file", type=Path, default=None, help="Optional .env file containing BUZZ_PRIVATE_KEY.")
    med_p.add_argument("--buzz-bin", default=None, help="Explicit path to console buzz CLI binary.")
    med_p.add_argument("--allow-private-network", action="store_true", help="Allow private/loopback relay URLs.")
    med_p.add_argument("--json", action="store_true", help="Emit structured JSON output.")

    can_p = sub.add_parser(
        "message-canary",
        help="Preview-first SHA-256 plan-gated disposable message canary (send -> readback -> react -> delete).",
    )
    can_p.add_argument("--channel", required=True, help="Target test channel UUID.")
    can_p.add_argument("--relay", default=None, help="Target Buzz relay URL.")
    can_p.add_argument("--env-file", type=Path, default=None, help="Optional .env file containing BUZZ_PRIVATE_KEY.")
    can_p.add_argument("--buzz-bin", default=None, help="Explicit path to console buzz CLI binary.")
    can_p.add_argument("--apply", action="store_true", help="Execute the live disposable canary mutation.")
    can_p.add_argument("--confirm-plan", default=None, help="SHA-256 plan hash from preview mode.")
    can_p.add_argument("--allow-private-network", action="store_true", help="Allow private/loopback relay URLs.")
    can_p.add_argument("--json", action="store_true", help="Emit structured JSON output.")

    upg_p = sub.add_parser(
        "relay-upgrade-plan",
        help="Generate an 8-gate zero-downtime self-hosted Buzz relay upgrade and isolated migration rehearsal plan.",
    )
    upg_p.add_argument("--relay", default=None, help="Target Buzz relay URL.")
    upg_p.add_argument("--target-digest", default=None, help="Candidate image digest (ghcr.io/block/buzz@sha256:...).")
    upg_p.add_argument("--format", choices=("json", "markdown"), default="json", help="Output format.")

    bp_p = sub.add_parser("blueprint", help="List or render production server, migration, ACP agent, and bridge blueprints.")
    bp_p.add_argument("--list", action="store_true", help="List all available blueprints.")
    bp_p.add_argument("--name", default=None, help="Blueprint name to render.")
    bp_p.add_argument("--output", type=Path, default=None, help="Optional file path to write blueprint content.")
    bp_p.add_argument("--overwrite", action="store_true", help="Overwrite --output file if it already exists.")
    bp_p.add_argument("--json", action="store_true", help="Emit blueprint metadata and content as JSON.")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "resources":
            _emit_json(resource_info(), output_path=args.output, overwrite=args.overwrite)
            return 0

        if args.command == "doctor":
            report = doctor_report(
                live=args.live,
                relay_url=args.relay,
                env_file=args.env_file,
                buzz_bin=args.buzz_bin,
                install_dir=args.install_dir,
                allow_private_network=args.allow_private_network,
            )
            _emit_json(report)
            return 0 if report["ok"] else 1

        if args.command == "mcp-map":
            payload = query_mcp_map(domain=args.domain, intent=args.intent)
            if args.format == "markdown":
                md = render_mcp_map_markdown(payload)
                if args.output is not None:
                    _safe_write_file(args.output, md, overwrite=args.overwrite)
                sys.stdout.write(md)
            else:
                _emit_json(payload, output_path=args.output, overwrite=args.overwrite)
            return 0

        if args.command == "cli-inventory":
            inv = cli_inventory(buzz_bin=args.buzz_bin)
            _emit_json(inv)
            return 0 if inv["found"] else 1

        if args.command == "desktop-audit":
            audit = audit_desktop_install(install_dir=args.install_dir, cli_bin=args.cli_bin)
            _emit_json(audit)
            return 0 if audit["healthy"] else 1

        if args.command == "relay-probe":
            probe = probe_relay(
                args.relay,
                allow_private_network=args.allow_private_network,
                timeout=args.timeout,
            )
            _emit_json(probe)
            return 0 if probe["healthy"] else 1

        if args.command == "membership-check":
            res = membership_check(
                relay_url=args.relay,
                env_file=args.env_file,
                buzz_bin=args.buzz_bin,
                allow_private_network=args.allow_private_network,
            )
            _emit_json(res)
            return 0 if res["status"] == "member" else 1

        if args.command == "owner-access-audit":
            res = owner_access_audit(
                relay_url=args.relay,
                env_file=args.env_file,
                expected_pubkey=args.expected_pubkey,
                allow_channels=tuple(args.allow_channel or ()),
                buzz_bin=args.buzz_bin,
                allow_private_network=args.allow_private_network,
            )
            _emit_json(res)
            return 0 if res["ok"] else 1

        if args.command == "channel-snapshot":
            res = channel_snapshot(
                channel_id=args.channel,
                relay_url=args.relay,
                env_file=args.env_file,
                limit=args.limit,
                buzz_bin=args.buzz_bin,
                allow_private_network=args.allow_private_network,
            )
            _emit_json(res)
            return 0

        if args.command == "thread-context":
            res = thread_context(
                channel_id=args.channel,
                event_id=args.event,
                relay_url=args.relay,
                env_file=args.env_file,
                limit=args.limit,
                buzz_bin=args.buzz_bin,
                allow_private_network=args.allow_private_network,
            )
            _emit_json(res)
            return 0

        if args.command == "media-inspect":
            res = inspect_media_attachment(
                channel_id=args.channel,
                event_id=args.event,
                media_url=args.url,
                expected_sha256=args.sha256,
                mime_type=args.mime,
                filename=args.filename,
                extract_mode=args.extract_mode,
                relay_url=args.relay,
                env_file=args.env_file,
                buzz_bin=args.buzz_bin,
                allow_private_network=args.allow_private_network,
            )
            _emit_json(res)
            return 0

        if args.command == "message-canary":
            res = message_canary(
                channel_id=args.channel,
                relay_url=args.relay,
                env_file=args.env_file,
                buzz_bin=args.buzz_bin,
                apply=args.apply,
                confirm_plan=args.confirm_plan,
                allow_private_network=args.allow_private_network,
            )
            _emit_json(res)
            if args.apply and not res.get("ok"):
                return 1
            return 0

        if args.command == "relay-upgrade-plan":
            plan = build_relay_upgrade_plan(relay_url=args.relay, target_digest=args.target_digest)
            if args.format == "markdown":
                lines = [
                    "# Block Buzz Zero-Downtime Relay Upgrade Plan",
                    "",
                    f"- **Target relay:** `{plan['relay_url']}`",
                    f"- **Candidate image:** `{plan['target_image']}`",
                    f"- **Digest pinned:** `{plan['digest_pinned']}`",
                    "",
                ]
                if plan.get("warning"):
                    lines.extend([f"> **Warning:** {plan['warning']}", ""])
                lines.extend(["| Gate | Step | Command | Requirement |", "| --- | --- | --- | --- |"])
                for gate in plan["gates"]:
                    lines.append(
                        f"| {gate['gate']} | `{gate['name']}` | `{gate['command']}` | {gate['requirement']} |"
                    )
                sys.stdout.write("\n".join(lines) + "\n")
            else:
                _emit_json(plan)
            return 0

        if args.command == "blueprint":
            if args.list or not args.name:
                _emit_json({"schema": "legends-buzz.blueprints/v1", "blueprints": list_blueprints()})
                return 0
            bp = get_blueprint(args.name)
            if args.output is not None:
                _safe_write_file(args.output, bp["content"], overwrite=args.overwrite)
            if args.json:
                _emit_json(bp)
            else:
                sys.stdout.write(bp["content"])
            return 0

    except (BuzzValidationError, BuzzSecurityError, KeyError) as exc:
        err_payload = {"ok": False, "error_type": type(exc).__name__, "error": scrub_secrets(str(exc))}
        sys.stderr.write(json.dumps(err_payload) + "\n")
        return 2
    except BuzzOperationError as exc:
        err_payload = {"ok": False, "error_type": type(exc).__name__, "error": scrub_secrets(str(exc))}
        sys.stderr.write(json.dumps(err_payload) + "\n")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
