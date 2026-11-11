"""Offline unit tests for legends-buzz security gates, PE inspection, MCP routing, and relay operations."""
from __future__ import annotations

import io
import json
from pathlib import Path
import socket
import struct
import sys
import tempfile
import unittest
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from legends_buzz.api import (
    BuzzSecurityError,
    BuzzValidationError,
    _bech32_hrp_expand,
    _bech32_polymod,
    _BECH32_ALPHABET,
    _safe_parse_xml_bytes,
    channel_snapshot,
    classify_key,
    inspect_media_attachment,
    membership_check,
    message_canary,
    normalize_pubkey,
    owner_access_audit,
    parse_env_file,
    resolve_buzz_binary,
    scrub_secrets,
    thread_context,
    validate_channel_uuid,
    validate_event_hex64,
    validate_media_url,
    validate_relay_url,
    verify_media_magic_bytes,
)
from legends_buzz.blueprints import BLUEPRINTS, build_relay_upgrade_plan, get_blueprint, list_blueprints
from legends_buzz.cli import main as cli_main
from legends_buzz.desktop import audit_desktop_install, inspect_pe_file, scan_embedded_frontend_assets
from legends_buzz.mcp_map import EXIT_CODES, MCP_DOMAINS, query_mcp_map, render_mcp_map_markdown
from legends_buzz.resources import resource_info


def _build_synthetic_pe(subsystem: int, extra_payload: bytes = b"") -> bytes:
    mz = bytearray(64)
    mz[0:2] = b"MZ"
    pe_offset = 64
    struct.pack_into("<I", mz, 0x3C, pe_offset)
    pe_hdr = bytearray(24 + 96)
    pe_hdr[0:4] = b"PE\x00\x00"
    struct.pack_into("<H", pe_hdr, 24, 0x20B)
    struct.pack_into("<H", pe_hdr, 24 + 68, subsystem)
    return bytes(mz) + bytes(pe_hdr) + extra_payload


def _encode_test_bech32(hrp: str, payload_32: bytes) -> str:
    acc = 0
    bits = 0
    words: list[int] = []
    for byte in payload_32:
        acc = (acc << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            words.append((acc >> bits) & 31)
    if bits:
        words.append((acc << (5 - bits)) & 31)
    values = _bech32_hrp_expand(hrp) + words
    polymod = _bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    checksum = [(polymod >> (5 * (5 - i))) & 31 for i in range(6)]
    return hrp + "1" + "".join(_BECH32_ALPHABET[w] for w in words + checksum)


class KeyAndSecretScrubbingTests(unittest.TestCase):
    def test_classify_key_supports_nsec_and_hex64(self) -> None:
        fake_nsec = _encode_test_bech32("nsec", b"\x11" * 32)
        res_nsec = classify_key(fake_nsec)
        self.assertTrue(res_nsec["valid"])
        self.assertEqual(res_nsec["kind"], "nsec")
        self.assertTrue(str(res_nsec["fingerprint"]).startswith("sha256:"))

        # Corrupted checksum or mixed-case nsec must be rejected
        self.assertFalse(classify_key("nsec1" + ("q" * 58))["valid"])
        self.assertFalse(classify_key(fake_nsec[:10].upper() + fake_nsec[10:])["valid"])

        fake_hex = "a1" * 32
        res_hex = classify_key(fake_hex)
        self.assertTrue(res_hex["valid"])
        self.assertEqual(res_hex["kind"], "hex64")

        self.assertEqual(classify_key("")["kind"], "missing")
        self.assertEqual(classify_key("not-a-valid-key")["kind"], "invalid")

    def test_scrub_secrets_redacts_nsec_hex_and_tokens(self) -> None:
        fake_nsec = "nsec1" + ("p" * 58)
        fake_hex = "b2" * 32
        raw = (
            f"Error with key {fake_nsec} and BUZZ_PRIVATE_KEY={fake_hex} "
            "plus BUZZ_FEDERATED_IDENTITY_TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        )
        scrubbed = scrub_secrets(raw)
        self.assertNotIn(fake_nsec, scrubbed)
        self.assertNotIn(fake_hex, scrubbed)
        self.assertNotIn("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", scrubbed)
        self.assertIn("nsec1[REDACTED]", scrubbed)
        self.assertIn("[REDACTED_HEX64]", scrubbed)
        self.assertIn("[REDACTED_TOKEN]", scrubbed)

    def test_parse_env_file_parses_and_enforces_size_limit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            env_path = Path(tmp) / "buzz.env"
            env_path.write_text(
                "# Comment\nexport BUZZ_RELAY_URL=\"https://buzz.example.com\"\nBUZZ_PRIVATE_KEY='abcd'\n",
                encoding="utf-8",
            )
            parsed = parse_env_file(env_path)
            self.assertEqual(parsed["BUZZ_RELAY_URL"], "https://buzz.example.com")
            self.assertEqual(parsed["BUZZ_PRIVATE_KEY"], "abcd")

            oversized = Path(tmp) / "huge.env"
            oversized.write_bytes(b"A" * (65 * 1024))
            with self.assertRaises(BuzzSecurityError):
                parse_env_file(oversized)


class RelayUrlValidationTests(unittest.TestCase):
    def test_validate_relay_url_blocks_http_and_private_ips(self) -> None:
        with self.assertRaises(BuzzSecurityError):
            validate_relay_url("http://buzz.example.com", resolve_dns=False)

        with self.assertRaises(BuzzSecurityError):
            validate_relay_url("https://user:pass@buzz.example.com", resolve_dns=False)

        fake_loopback = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]
        with mock.patch("socket.getaddrinfo", return_value=fake_loopback):
            with self.assertRaises(BuzzSecurityError):
                validate_relay_url("https://localhost.example.com", allow_private_network=False)

        fake_cgnat = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("100.64.1.25", 443))]
        with mock.patch("socket.getaddrinfo", return_value=fake_cgnat):
            with self.assertRaises(BuzzSecurityError):
                validate_relay_url("https://tailnet.example.com", allow_private_network=False)

        fake_public = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
        with mock.patch("socket.getaddrinfo", return_value=fake_public):
            ok = validate_relay_url("wss://buzz.example.com/")
            self.assertEqual(ok["http_url"], "https://buzz.example.com")
            self.assertEqual(ok["ws_url"], "wss://buzz.example.com")
            self.assertEqual(ok["resolved_ips"], ["93.184.216.34"])


class DesktopPeAndAssetAuditTests(unittest.TestCase):
    def test_inspect_pe_and_detect_ntfs_collision(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # Case 1: Healthy install (GUI buzz-desktop.exe with assets, CUI buzz.exe)
            gui_bytes = _build_synthetic_pe(
                2,
                b"<html>index.html</html> assets/MainScreen-AbCdEf12.js assets/theme-98765432.css",
            )
            cui_bytes = _build_synthetic_pe(3, b"Buzz CLI")
            (root / "buzz-desktop.exe").write_bytes(gui_bytes)
            (root / "buzz.exe").write_bytes(cui_bytes)

            self.assertEqual(inspect_pe_file(root / "buzz-desktop.exe")["subsystem"], "gui")
            self.assertEqual(inspect_pe_file(root / "buzz.exe")["subsystem"], "cui")

            assets = scan_embedded_frontend_assets(root / "buzz-desktop.exe")
            self.assertTrue(assets["has_index_html"])
            self.assertEqual(assets["asset_count"], 2)

            healthy_audit = audit_desktop_install(install_dir=root)
            self.assertTrue(healthy_audit["healthy"])
            self.assertFalse(healthy_audit["ntfs_case_collision_detected"])

            # Case 2: NTFS Buzz.exe collision (root buzz.exe overwritten with GUI binary)
            (root / "buzz.exe").write_bytes(gui_bytes)
            collision_audit = audit_desktop_install(install_dir=root)
            self.assertFalse(collision_audit["healthy"])
            self.assertTrue(collision_audit["ntfs_case_collision_detected"])
            codes = [item["code"] for item in collision_audit["findings"]]
            self.assertIn("ntfs_buzz_exe_case_collision", codes)


class McpMapAndBlueprintTests(unittest.TestCase):
    def test_mcp_map_covers_all_26_domains_and_exit_codes(self) -> None:
        self.assertEqual(len(MCP_DOMAINS), 26)
        self.assertEqual(set(EXIT_CODES.keys()), {0, 1, 2, 3, 4, 5})
        full = query_mcp_map()
        self.assertEqual(full["domain_count"], 26)
        self.assertGreaterEqual(full["subcommand_count"], 100)

        filtered = query_mcp_map(domain="projects")
        self.assertEqual(filtered["domain_count"], 1)
        self.assertEqual(filtered["domains"][0]["domain"], "projects")

        intent_res = query_mcp_map(intent="unread channels and thread replies")
        self.assertGreaterEqual(intent_res["domain_count"], 2)

        md = render_mcp_map_markdown(filtered)
        self.assertIn("# Block Buzz MCP-to-CLI Reference Map", md)
        self.assertNotIn("\u2014", md)
        self.assertNotIn("\u2013", md)

    def test_blueprints_and_relay_upgrade_plan(self) -> None:
        self.assertEqual(len(BLUEPRINTS), 9)
        names = [item["name"] for item in list_blueprints()]
        self.assertIn("docker-compose-traefik", names)
        self.assertIn("docker-compose-caddy", names)
        self.assertIn("mobile-invite-edge", names)
        self.assertIn("postgres-migration-49-60-preflight", names)
        self.assertIn("stage-upgrade-verify", names)
        self.assertIn("acp-subscription-agent", names)
        self.assertIn("isolated-subscription-acp-launcher", names)
        self.assertIn("durable-bridge-guard", names)
        self.assertIn("systemd-alert-timer", names)

        bp = get_blueprint("docker-compose-traefik")
        self.assertIn("postgres:17-alpine", bp["content"])
        self.assertIn("pairing-relay:", bp["content"])
        self.assertIn("invite-edge:", bp["content"])
        self.assertIn("tauri://localhost", bp["content"])

        unpinned = build_relay_upgrade_plan("https://buzz.example.com", "ghcr.io/block/buzz:latest")
        self.assertFalse(unpinned["digest_pinned"])
        self.assertIsNotNone(unpinned["warning"])

        pinned = build_relay_upgrade_plan(
            "https://buzz.example.com",
            "ghcr.io/block/buzz@sha256:" + ("a" * 64),
        )
        self.assertTrue(pinned["digest_pinned"])
        self.assertIsNone(pinned["warning"])
        self.assertEqual(len(pinned["gates"]), 8)


class ThreadContextAndMediaTests(unittest.TestCase):
    def test_thread_context_isolates_connected_component_in_shared_channel(self) -> None:
        fake_public = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
        ev_root = "1" * 64
        ev_reply = "2" * 64
        ev_unrelated = "3" * 64
        fake_messages = [
            {"id": ev_root, "pubkey": "aa" * 32, "created_at": 1000, "content": "Root question", "tags": []},
            {"id": ev_unrelated, "pubkey": "bb" * 32, "created_at": 1005, "content": "Unrelated chatter", "tags": []},
            {
                "id": ev_reply,
                "pubkey": "cc" * 32,
                "created_at": 1010,
                "content": "Thread reply",
                "tags": [["e", ev_root], ["imeta", "url https://buzz.example.com/media/" + ("f" * 64) + ".csv", "x " + ("f" * 64), "m text/csv"]],
            },
        ]
        fake_cli_res = {
            "ok": True,
            "exit_code": 0,
            "stdout": json.dumps(fake_messages),
            "stderr": "",
            "json": fake_messages,
        }
        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / "buzz.env"
            env_file.write_text(
                f"BUZZ_RELAY_URL=https://buzz.example.com\nBUZZ_PRIVATE_KEY={'a1' * 32}\n",
                encoding="utf-8",
            )
            with (
                mock.patch("socket.getaddrinfo", return_value=fake_public),
                mock.patch("legends_buzz.api.run_buzz_cli", return_value=fake_cli_res),
            ):
                ctx = thread_context(
                    channel_id="5ff0675d-acdd-5468-9b80-7a9bee474e56",
                    event_id=ev_reply,
                    env_file=env_file,
                )
                self.assertEqual(ctx["message_count"], 2)
                ids = [m["id"] for m in ctx["messages"]]
                self.assertEqual(ids, [ev_root, ev_reply])
                self.assertNotIn(ev_unrelated, ids)
                self.assertEqual(len(ctx["attachments"]), 1)
                self.assertFalse(ctx["dm_chronological_fallback"])

    def test_validate_media_url_and_magic_bytes(self) -> None:
        sha = "a" * 64
        ok = validate_media_url(
            "https://buzz.example.com",
            f"https://buzz.example.com/media/{sha}.csv",
            sha,
        )
        self.assertEqual(ok["sha256"], sha)
        self.assertEqual(ok["extension"], "csv")

        with self.assertRaises(BuzzSecurityError):
            validate_media_url(
                "https://buzz.example.com",
                f"https://evil.example.com/media/{sha}.csv",
                sha,
            )

        with self.assertRaises(BuzzSecurityError):
            validate_media_url(
                "https://buzz.example.com",
                f"https://buzz.example.com/media/{'b' * 64}.csv",
                sha,
            )

        self.assertTrue(verify_media_magic_bytes(b"%PDF-1.7 sample", "application/pdf"))
        self.assertFalse(verify_media_magic_bytes(b"not a pdf", "application/pdf"))
        self.assertTrue(verify_media_magic_bytes(b"col1,col2\n1,2\n", "text/csv"))
        self.assertFalse(verify_media_magic_bytes(b"binary\x00null", "text/csv"))

    def test_inspect_media_attachment_verifies_5_gates_and_profiles_csv(self) -> None:
        fake_public = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
        csv_bytes = b"metric,score\nlatency,10\nlatency,20\nlatency,30\n"
        import hashlib as _hl
        csv_sha = _hl.sha256(csv_bytes).hexdigest()
        ev_id = "9" * 64
        media_url = f"https://buzz.example.com/media/{csv_sha}.csv"
        fake_events = [
            {
                "id": ev_id,
                "pubkey": "aa" * 32,
                "created_at": 1000,
                "content": "Dataset attached",
                "tags": [["imeta", f"url {media_url}", f"x {csv_sha}", "m text/csv"]],
            }
        ]

        def fake_cli_runner(args, **kwargs):
            if args[:2] == ["messages", "get"]:
                return {"ok": True, "exit_code": 0, "stdout": "[]", "stderr": "", "json": fake_events}
            if args[:2] == ["media", "get"]:
                out_idx = args.index("--output") + 1
                Path(args[out_idx]).write_bytes(csv_bytes)
                return {"ok": True, "exit_code": 0, "stdout": "", "stderr": "", "json": None}
            raise AssertionError(f"Unexpected CLI args: {args}")

        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / "buzz.env"
            env_file.write_text(
                f"BUZZ_RELAY_URL=https://buzz.example.com\nBUZZ_PRIVATE_KEY={'b2' * 32}\n",
                encoding="utf-8",
            )
            with (
                mock.patch("socket.getaddrinfo", return_value=fake_public),
                mock.patch("legends_buzz.api.run_buzz_cli", side_effect=fake_cli_runner),
            ):
                res = inspect_media_attachment(
                    channel_id="5ff0675d-acdd-5468-9b80-7a9bee474e56",
                    event_id=ev_id,
                    media_url=media_url,
                    expected_sha256=csv_sha,
                    mime_type="text/csv",
                    filename="metrics.csv",
                    extract_mode="data",
                    env_file=env_file,
                )
                self.assertTrue(res["ok"])
                self.assertTrue(res["imeta_verified"])
                self.assertTrue(res["magic_bytes_verified"])
                self.assertIn("mean=20", res["extracted_content"])


class MembershipAuditAndCanaryTests(unittest.TestCase):
    def test_membership_check_classifies_residual_403_and_member(self) -> None:
        fake_probe = {
            "relay_url": "https://buzz.example.com",
            "healthy": True,
            "nip11": {"requires_nip_fi": False},
        }
        fake_403_cli = {
            "ok": False,
            "exit_code": 3,
            "stdout": "",
            "stderr": '{"error":"auth_error","message":"HTTP 403 relay_membership_required"}',
            "json": None,
        }
        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / "buzz.env"
            env_file.write_text(
                f"BUZZ_RELAY_URL=https://buzz.example.com\nBUZZ_PRIVATE_KEY={'c3' * 32}\n",
                encoding="utf-8",
            )
            with (
                mock.patch("legends_buzz.api.probe_relay", return_value=fake_probe),
                mock.patch("legends_buzz.api.run_buzz_cli", return_value=fake_403_cli),
            ):
                res_403 = membership_check(env_file=env_file)
                self.assertEqual(res_403["status"], "residual_403")
                self.assertIn("/invite/<token>", res_403["remediation"])

            fake_ok_cli = {
                "ok": True,
                "exit_code": 0,
                "stdout": '[{"id":"ch-1","name":"general","channel_type":"stream","visibility":"open"}]',
                "stderr": "",
                "json": [{"id": "ch-1", "name": "general", "channel_type": "stream", "visibility": "open"}],
            }
            fake_inv = {"generation": "1.0.0+"}
            with (
                mock.patch("legends_buzz.api.probe_relay", return_value=fake_probe),
                mock.patch("legends_buzz.api.run_buzz_cli", return_value=fake_ok_cli),
                mock.patch("legends_buzz.api.cli_inventory", return_value=fake_inv),
            ):
                res_ok = membership_check(env_file=env_file)
                self.assertEqual(res_ok["status"], "member")
                self.assertEqual(res_ok["channel_count"], 1)

    def test_owner_access_audit_flags_missing_owner(self) -> None:
        ch_uuid = "5ff0675d-acdd-5468-9b80-7a9bee474e56"
        fake_membership = {
            "relay_url": "https://buzz.example.com",
            "status": "member",
            "channels": [{"id": ch_uuid, "name": "ops"}],
            "remediation": None,
        }
        fake_members_cli = {
            "ok": True,
            "exit_code": 0,
            "stdout": '[{"pubkey":"' + ("a" * 64) + '","role":"owner"}]',
            "stderr": "",
            "json": [{"pubkey": "a" * 64, "role": "owner"}],
        }
        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / "buzz.env"
            env_file.write_text(
                f"BUZZ_RELAY_URL=https://buzz.example.com\nBUZZ_PRIVATE_KEY={'d4' * 32}\n",
                encoding="utf-8",
            )
            with (
                mock.patch("legends_buzz.api.membership_check", return_value=fake_membership),
                mock.patch("legends_buzz.api.run_buzz_cli", return_value=fake_members_cli),
            ):
                audit = owner_access_audit(env_file=env_file, expected_pubkey="f" * 64)
                self.assertFalse(audit["ok"])
                self.assertEqual(audit["gap_count"], 1)

    def test_normalize_pubkey_and_owner_access_audit_npub_matching(self) -> None:
        npub = "npub1lpadtgy9alcc9xwggzwuzwl93pzy4f7m04lwg8hjmcparrmyqr9ss7hkse"
        expected_hex = "f87ad5a085eff18299c8409dc13be588444aa7db7d7ee41ef2de03d18f6400cb"
        self.assertEqual(normalize_pubkey(npub), expected_hex)
        self.assertEqual(normalize_pubkey(expected_hex.upper()), expected_hex)
        with self.assertRaises(BuzzValidationError):
            normalize_pubkey("npub1lpadtgy9alcc9xwggzwuzwl93pzy4f7m04lwg8hjmcparrmyqr9ss7hksf")
        with self.assertRaises(BuzzValidationError):
            normalize_pubkey(npub[:10].upper() + npub[10:])
        with self.assertRaises(BuzzValidationError):
            normalize_pubkey("not-a-hex64-pubkey")

        ch_uuid = "5ff0675d-acdd-5468-9b80-7a9bee474e56"
        fake_membership = {
            "relay_url": "https://buzz.example.com",
            "status": "member",
            "channels": [{"id": ch_uuid, "name": "general"}],
            "remediation": None,
        }
        fake_members_cli = {
            "ok": True,
            "exit_code": 0,
            "stdout": "",
            "stderr": "",
            "json": [{"pubkey": expected_hex, "role": "owner"}],
        }
        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / "buzz.env"
            env_file.write_text(
                f"BUZZ_RELAY_URL=https://buzz.example.com\nBUZZ_PRIVATE_KEY={'d4' * 32}\n",
                encoding="utf-8",
            )
            with (
                mock.patch("legends_buzz.api.membership_check", return_value=fake_membership),
                mock.patch("legends_buzz.api.run_buzz_cli", return_value=fake_members_cli),
            ):
                audit = owner_access_audit(env_file=env_file, expected_pubkey=npub)
                self.assertTrue(audit["ok"])
                self.assertEqual(audit["gap_count"], 0)
                self.assertEqual(audit["expected_pubkey_normalized"], expected_hex)

    def test_message_canary_preview_and_apply_lifecycle(self) -> None:
        fake_public = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
        ch_uuid = "5ff0675d-acdd-5468-9b80-7a9bee474e56"
        ev_hex = "e" * 64
        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / "buzz.env"
            env_file.write_text(
                f"BUZZ_RELAY_URL=https://buzz.example.com\nBUZZ_PRIVATE_KEY={'e5' * 32}\n",
                encoding="utf-8",
            )
            with mock.patch("socket.getaddrinfo", return_value=fake_public):
                preview = message_canary(channel_id=ch_uuid, env_file=env_file, apply=False)
                self.assertEqual(preview["mode"], "preview")
                self.assertFalse(preview["executed"])
                plan_hash = preview["plan_sha256"]

                with self.assertRaises(BuzzSecurityError):
                    message_canary(
                        channel_id=ch_uuid,
                        env_file=env_file,
                        apply=True,
                        confirm_plan="wrong_hash",
                    )

                side_effects = [
                    {"ok": True, "exit_code": 0, "stdout": f'{{"id":"{ev_hex}"}}', "stderr": "", "json": {"id": ev_hex}},
                    {"ok": True, "exit_code": 0, "stdout": f'[{{"id":"{ev_hex}"}}]', "stderr": "", "json": [{"id": ev_hex}]},
                    {"ok": True, "exit_code": 0, "stdout": "{}", "stderr": "", "json": {}},
                    {"ok": True, "exit_code": 0, "stdout": "{}", "stderr": "", "json": {}},
                    {"ok": True, "exit_code": 0, "stdout": "{}", "stderr": "", "json": {}},
                ]
                with mock.patch("legends_buzz.api.run_buzz_cli", side_effect=side_effects) as mocked_cli:
                    applied = message_canary(
                        channel_id=ch_uuid,
                        env_file=env_file,
                        apply=True,
                        confirm_plan=plan_hash,
                    )
                    self.assertTrue(applied["ok"])
                    self.assertEqual(applied["canary_event_id"], ev_hex)
                    self.assertEqual(mocked_cli.call_count, 5)

    def test_security_hardening_xml_imeta_and_option_injection(self) -> None:
        # 1. XML entity expansion guard beyond 4 KB and UTF-16
        padded_xxe = (b" " * 5000) + b'<!DOCTYPE foo [<!ENTITY xxe "boom">]><root>&xxe;</root>'
        with self.assertRaises(BuzzSecurityError):
            _safe_parse_xml_bytes(padded_xxe)

        utf16_xxe = '<!DOCTYPE foo [<!ENTITY xxe "boom">]><root/>'.encode("utf-16")
        with self.assertRaises(BuzzSecurityError):
            _safe_parse_xml_bytes(utf16_xxe)

        # 2. Option injection rejection on channel_id / event_id
        with self.assertRaises(BuzzValidationError):
            validate_channel_uuid("--relay=https://evil.example.com")
        with self.assertRaises(BuzzValidationError):
            validate_event_hex64("--help")
        with self.assertRaises(BuzzValidationError):
            channel_snapshot(channel_id="--relay=evil")

        # 3. Fail-closed Gate 3 on inspect_media_attachment when event is missing or CLI fails
        fake_public = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
        sha = "a" * 64
        ev_id = "9" * 64
        ch_uuid = "5ff0675d-acdd-5468-9b80-7a9bee474e56"
        media_url = f"https://buzz.example.com/media/{sha}.csv"
        with tempfile.TemporaryDirectory() as tmp:
            env_file = Path(tmp) / "buzz.env"
            env_file.write_text(
                f"BUZZ_RELAY_URL=https://buzz.example.com\nBUZZ_PRIVATE_KEY={'b2' * 32}\n",
                encoding="utf-8",
            )
            with (
                mock.patch("socket.getaddrinfo", return_value=fake_public),
                mock.patch(
                    "legends_buzz.api.run_buzz_cli",
                    return_value={"ok": True, "exit_code": 0, "stdout": "[]", "stderr": "", "json": []},
                ),
            ):
                with self.assertRaises(BuzzSecurityError):
                    inspect_media_attachment(
                        channel_id=ch_uuid,
                        event_id=ev_id,
                        media_url=media_url,
                        expected_sha256=sha,
                        mime_type="text/csv",
                        env_file=env_file,
                    )


class CliSmokeTests(unittest.TestCase):
    def test_cli_resources_and_mcp_map(self) -> None:
        info = resource_info()
        self.assertTrue(info["complete"])

        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            rc = cli_main(["mcp-map", "--domain", "channels"])
        self.assertEqual(rc, 0)
        parsed = json.loads(buf.getvalue())
        self.assertEqual(parsed["domain_count"], 1)

    def test_cli_output_fail_closed_unless_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_file = Path(tmp) / "resources.json"
            buf = io.StringIO()
            with mock.patch("sys.stdout", buf):
                rc1 = cli_main(["resources", "--output", str(out_file)])
            self.assertEqual(rc1, 0)
            self.assertTrue(out_file.exists())

            err_buf = io.StringIO()
            with mock.patch("sys.stdout", io.StringIO()), mock.patch("sys.stderr", err_buf):
                rc2 = cli_main(["resources", "--output", str(out_file)])
            self.assertEqual(rc2, 2)
            self.assertIn("Refusing to overwrite existing file", err_buf.getvalue())

            with mock.patch("sys.stdout", io.StringIO()):
                rc3 = cli_main(["resources", "--output", str(out_file), "--overwrite"])
            self.assertEqual(rc3, 0)


if __name__ == "__main__":
    unittest.main()
