# Security Policy

## Supported Versions

| Version | Supported |
| --- | --- |
| 0.1.x | Yes |

## Credential, Subprocess, and Network Hardening

- `legends-buzz` reads `BUZZ_PRIVATE_KEY`, `BUZZ_NSEC`, `BUZZ_PRIVATE_KEY_HEX`, `BUZZ_RELAY_URL`, and `BUZZ_FEDERATED_IDENTITY_TOKEN` from the process environment or an explicit `--env-file <path>` argument.
- Secret keys (`nsec1...` Bech32 keys, 64-character hex private keys, and bearer tokens) are automatically scrubbed and never echoed in CLI output, exception messages, or generated Markdown receipts.
- Outbound relay probes (`relay-probe`) enforce `https://` by default, verify that target hostnames resolve exclusively to globally routable public IP addresses (blocking loopback, RFC1918 private, link-local, and cloud metadata IPs unless `--allow-private-network` is explicitly passed for a local lab), and disable automatic HTTP redirects (`_NoRedirectHandler`).
- External `buzz` CLI subprocess calls use explicit argument vectors (`shell=False`), pass credentials strictly through child process environment variables (`BUZZ_PRIVATE_KEY`) rather than command-line flags, verify Windows PE subsystem headers (`IMAGE_SUBSYSTEM_WINDOWS_CUI`) before invoking `buzz.exe` so a GUI binary is never accidentally launched by an automation check, and never pass hidden-window process creation flags.
- Local file reads and writes reject symbolic links and enforce explicit file size bounds.

## Reporting a Vulnerability

Please report security issues privately through [GitHub Security Advisories](https://github.com/avalonreset/legends-buzz/security/advisories/new) rather than opening a public issue containing sensitive details.

- **Initial acknowledgment target:** within 48 hours.
- **Triage and remediation update target:** within 7 days.
- See [SUPPORT.md](SUPPORT.md) for general non-security usage questions.
