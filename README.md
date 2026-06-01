# m365-admin-tool

A terminal-first Microsoft 365 and Entra investigation CLI for compromised-user triage. Built for the first hour after a confirmed BEC or token-theft incident in tenants that don't have a SOC or Defender for Office 365 E5 license to fall back on.

> The first hour after a confirmed compromise is mostly mechanical: check sign-ins, check rules, check OAuth, revoke, document. This tool collapses that into a few minutes of CLI with reproducible JSON output for the handoff.

[![CI](https://github.com/Gluthoric/m365-admin-tool/actions/workflows/ci.yml/badge.svg)](https://github.com/Gluthoric/m365-admin-tool/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

## What it does

A four-command workflow built around the standard compromised-user playbook:

| Command    | Purpose                                                                                                                                                                                               |
| ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `doctor`   | Pre-flight tenant, permission, and API readiness checks — tells you which datasets will work before you waste time on a half-broken investigation                                                     |
| `diagnose` | One-shot account diagnostic with compromise indicators, remediation history, evidence gaps, identity, mailbox, delegation, audit, apps, outbound, and permissions, all in a single structured payload |
| `timeline` | Merged sign-ins, directory audits, message-trace rows, and mailbox events in chronological order over a configurable window                                                                           |
| `contain`  | Dry-run and confirmed containment actions — revoke sessions, disable inbox rules, disable mailbox forwarding, block sign-in                                                                           |

Supporting drill-down commands cover sign-ins, audits, inbox rules, risk detections, message trace, mailbox messages, enterprise-app review, and a combined outbound-alert review.

Every command emits plain terminal output by default and full structured JSON with `--json`. The pretty output and the JSON come from the same payload, so anything you see in the terminal can be piped through `jq`, stored in a SIEM, or diffed between runs.

## Why I built this

I do incident response for small-to-mid M365 tenants where there's no SOC and no Defender for Office 365 E5 license to lean on. The triage is always the same shape — check sign-ins, check rules, check OAuth, revoke, document — but doing it through the admin center takes 30+ minutes per user, scrolling through paginated UIs that drop your context every time you click into a record. This tool collapses that into a few minutes of CLI with output you can paste into a ticket or hand to an attorney.

It is intentionally narrow. It does not replace Defender, Sentinel, or a proper SOC. It is the thing you reach for when you have neither and the clock is ticking.

## How it's wired

```mermaid
flowchart LR
    op([Operator]) -->|cli| triage{{m365-admin}}
    triage -->|MSAL device-code or client cert| auth[Microsoft Identity Platform]
    auth -->|access token| graph[Microsoft Graph API]
    auth -->|access token| exch[Exchange Admin API]
    triage --> doctor[doctor]
    triage --> diag[diagnose]
    triage --> tl[timeline]
    triage --> cont[contain]
    diag --> graph
    diag --> exch
    tl --> graph
    cont --> graph
    cont --> exch
    diag --> report[(JSON output)]
    tl --> report
    report --> op
```

Authentication uses MSAL with two supported flows: **device-code** for interactive one-off use (cached at `~/.config/m365-admin-tool/token-cache.json`) and **client-secret** for unattended runs. Required Graph scopes are documented below — the tool fails loudly if a token is missing a scope rather than silently producing partial results.

Every Graph and Exchange Admin request goes through a thin client (`GraphClient`, `ExchangeAdminClient`) so the entire test suite runs against JSON fixtures with no `requests-mock` or VCR machinery.

## Module layout

```
src/m365_admin_tool/
├── cli.py             # Argument parsing, output formatting, command dispatch
├── auth.py            # MSAL token acquisition (delegated + app), scope management
├── config.py          # Environment variables, .env loading, tenant profiles
├── graph.py           # Low-level Graph API wrapper (GET/POST, pagination, error handling)
├── exchange_admin.py  # Exchange Admin API cmdlet wrapper
├── doctor.py          # Pre-flight probes and optional helper fixes
├── diagnosis.py       # Structured diagnostic payload assembly, verdict, compromise report
├── identity.py        # User profile, licenses, memberships, auth methods
├── investigation.py   # Sign-ins, directory audits, inbox rules, risk detections
├── outbound.py        # Message traces, mailbox messages, app review, mailbox snapshot
├── containment.py     # Containment actions and rule discovery
└── timeline.py        # Timeline event normalization and merge
```

## Quickstart

```bash
git clone https://github.com/Gluthoric/m365-admin-tool
cd m365-admin-tool
cp .env.example .env  # fill in M365_TENANT_ID and M365_CLIENT_ID
uv sync

uv run m365-admin doctor --target user@yourtenant.com
uv run m365-admin diagnose user@yourtenant.com --json
uv run m365-admin timeline user@yourtenant.com --hours 4
uv run m365-admin contain user@yourtenant.com --dry-run
```

Run `doctor` first. It tells you which datasets will work before you start an investigation. If `diagnose` is invoked interactively without arguments, the CLI prompts for tenant profile, admin account, and target user.

Multi-tenant operators: create `tenants.json` in the repo root or `~/.config/m365-admin-tool/tenants.json` based on [`tenants.example.json`](tenants.example.json).

## Sample output

```
$ uv run m365-admin diagnose alice@yourtenant.com

Diagnosis for alice@yourtenant.com (yourtenant)
═══════════════════════════════════════════════════════════════════════════

Verdict: COMPROMISED (high confidence)

Confirmed compromise indicators
  ✗ 1 hidden inbox rule named " " forwarding to evil@gmail.com
  ✗ SMTP forwarding configured to mailbox+exfil@protonmail.com
  ✗ 1 OAuth grant in the last 24h: "PDF Reader Pro" (Mail.ReadWrite, offline_access)
     publisher: unverified, consented at 2026-05-31 14:21:03Z
  ✗ 3 risky sign-ins from previously-unseen ASNs in the last 24h

Suspected indicators
  ? 47 download events in 8 minutes from OneDrive
  ? Atypical user agent ("Mac" first-time on this account)

Remediation already taken
  ✓ MFA was reset 2026-05-31 16:08Z (auto-resolved by admin)

Recommended actions
  → revoke sign-in sessions
  → disable and delete inbox rule (×3)
  → remove SMTP forwarding
  → revoke OAuth grant ("PDF Reader Pro")
  → force password reset
  → re-enroll MFA

Unavailable evidence
  ⚠ ExchangeMessageTrace.Read.All scope not granted — message trace omitted
  ⚠ Risk detection scope not granted — risky-user verdict omitted

6 findings · re-run with --json for full payload
```

## Detection coverage

Findings have a stable JSON shape so they survive being stored, diffed, or piped:

```json
{
  "user": "alice@yourtenant.com",
  "detection": "mailbox_rules.suspicious_forward",
  "severity": "high",
  "first_seen": "2026-05-31T14:22:08Z",
  "evidence": {
    "rule_id": "AAMkADc4...",
    "rule_name": " ",
    "actions": {
      "forwardTo": [{ "emailAddress": { "address": "evil@gmail.com" } }]
    },
    "hidden": true
  },
  "remediation": "delete_inbox_rule"
}
```

| Category      | What it looks for                                                                                                             |
| ------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| Sign-ins      | risky sign-ins, impossible travel, atypical user agents, foreign-country sign-ins, legacy-auth clients                        |
| Mailbox rules | forward-to-external, redirect-to-external, forwardAsAttachment, hidden-name rules, move-to-RSS-Feeds                          |
| Forwarding    | SMTP forwarding config, Exchange transport rule forwarding, send-on-behalf grants                                             |
| OAuth grants  | recently-consented apps, unverified publishers, dangerous-scope grants (Mail.ReadWrite, Mail.Send, Files.ReadWrite.All, etc.) |
| Delegates     | mailbox FullAccess / SendAs / Send-On-Behalf grants                                                                           |
| Outbound      | message-trace bursts, sender mismatches, Sent Items vs Deleted Items deltas                                                   |
| Audit         | identity-touching directory audits across the investigation window                                                            |

## Containment actions

| Action                     | What it does                                                                              | Required scope                      |
| -------------------------- | ----------------------------------------------------------------------------------------- | ----------------------------------- |
| Revoke sessions            | `revokeSignInSessions` — invalidates refresh tokens for all of the user's active sessions | `User.RevokeSessions.All`           |
| Disable inbox rule         | Disables a named inbox rule (keeps it for forensics rather than deleting)                 | `MailboxSettings.ReadWrite`         |
| Disable mailbox forwarding | Clears SMTP forwarding and forwardingSMTPAddress                                          | `MailboxSettings.ReadWrite`         |
| Block sign-in              | Sets `accountEnabled: false` on the user object                                           | `User.ReadWrite.All`                |
| List auth methods          | Reads MFA methods to confirm what re-enrollment will reset                                | `UserAuthenticationMethod.Read.All` |

Containment requires `--confirm` and goes through a structured audit log: timestamp, operator UPN, target UPN, action, Graph correlation ID, dry-run-or-real.

## Required Graph permissions

Delegated scopes for the current commands:

- `AuditLog.Read.All`
- `MailboxSettings.Read`
- `MailboxSettings.ReadWrite` for inbox-rule containment
- `ExchangeMessageTrace.Read.All` for outbound trace
- `Directory.Read.All` for enterprise-app and consent review
- `Mail.Read` for Sent Items and Deleted Items review
- `IdentityRiskEvent.Read.All` for `risk` and risk lookups inside `investigate`
- `UserAuthenticationMethod.Read.All` for auth-method inspection
- `User.ReadWrite.All` for containment actions like revoke sessions and block sign-in

The admin you sign in as also needs a supported Entra role (Global Reader and Exchange Administrator cover the read paths; containment requires write-capable roles such as User Administrator).

Recommended application permissions for cross-user mailbox review:

- `Mail.Read`
- `MailboxSettings.Read`
- `Directory.Read.All`
- `AuditLog.Read.All`
- `ExchangeMessageTrace.Read.All`

Optional Exchange Online Admin API permission:

- `Exchange.ManageAsAppV2` for app-only mailbox forwarding / send-on-behalf snapshot
- `Exchange.ManageV2` for delegated Exchange Admin API access

See [`docs/permissions.md`](docs/permissions.md) for the full breakdown including the admin role each scope effectively requires.

## What's technically interesting

- **All Graph and Exchange Admin calls go through one thin client each.** Detections and containment never touch HTTP directly. The whole test suite runs against fixtures.
- **Graceful degradation.** Each data section in `diagnose` fails independently with a warning — investigation continues. If message trace is unavailable, you still get the mailbox-rule, app-consent, and sign-in pieces.
- **Detections are pure functions** of Graph responses. Adding a detection is writing a function from `list[GraphObject] → list[Finding]`. No plumbing.
- **OData escaping is centralized.** A single `escape_odata_string()` helper means sloppy parameter concatenation can't sneak in.
- **Output is JSON-first.** The default human-readable output is rendered from the same payload `--json` emits. Anything you see in the terminal can be piped through `jq`.
- **Containment is opt-in and verbose.** The tool will not act on a tenant unless `--contain --confirm` is set, and every action is logged before it runs. There is no "do everything for me" flag — incident response is not the place for confidently-wrong automation.

## What this is not

- Not a substitute for Microsoft Defender, Sentinel, or a real SIEM. It runs on demand against the Graph API; it does not stream signals.
- Not a hunter. It answers "did this account get compromised, and is the attacker still in?" It does not answer "find compromised accounts I don't know about yet."
- Not a recovery tool. After containment you still need to verify the user's mailbox is clean, check connected devices, audit shared resources, and re-onboard the user properly.

## Command reference

```bash
uv run m365-admin doctor --target user@yourtenant.com
uv run m365-admin doctor --target user@yourtenant.com --fix
uv run m365-admin login
uv run m365-admin diagnose user@yourtenant.com --json
uv run m365-admin investigate --days 7
uv run m365-admin signins user@yourtenant.com --from 2026-03-09T20:30Z --to 2026-03-09T20:50Z
uv run m365-admin trace user@yourtenant.com --hours 48
uv run m365-admin messages user@yourtenant.com --folder sentitems --hours 48 --auth app
uv run m365-admin apps user@yourtenant.com --auth app
uv run m365-admin outbound-review user@yourtenant.com --hours 48 --auth app
uv run m365-admin timeline user@yourtenant.com --hours 48
uv run m365-admin contain user@yourtenant.com --dry-run
uv run m365-admin signins --days 30 --limit 50
uv run m365-admin audits --days 30 --limit 50
uv run m365-admin rules
uv run m365-admin risk --days 30 --limit 50
```

## Roadmap

- [ ] `hunt` mode — sweep all users for a specific IoC (e.g. a malicious OAuth app)
- [ ] Sigma rule export for tenants with a SIEM downstream
- [ ] Defender for Office 365 enrichment when the license is present
- [ ] M365 audit log streaming rather than Graph polling
- [ ] PowerShell parity wrapper for shops that can't install Python on operator laptops

## Related reading

- Microsoft: [Responding to a compromised email account in Microsoft 365](https://learn.microsoft.com/en-us/defender-office-365/responding-to-a-compromised-email-account)
- Mandiant: [Defining and Investigating Business Email Compromise](https://cloud.google.com/blog/topics/threat-intelligence/business-email-compromise-investigations)
- CISA: [Microsoft 365 Hardening Recommendations](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a)

See also:

- [`docs/playbook.md`](docs/playbook.md) — the incident-response playbook this CLI implements
- [`docs/architecture.md`](docs/architecture.md) — module-by-module deep dive with sequence diagrams
- [`docs/permissions.md`](docs/permissions.md) — full Graph and Exchange permission reference

## License

MIT — see [LICENSE](LICENSE).
