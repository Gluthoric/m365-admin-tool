from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .auth import (
    EXCHANGE_RESOURCE,
    GRAPH_RESOURCE,
    AuthError,
    TokenProvider,
    containment_scopes,
    default_login_scopes,
    exchange_delegated_scopes,
    requested_scopes,
)
from .config import ConfigurationError, Settings, load_tenant_profiles
from .containment import (
    block_user_sign_in,
    disable_inbox_rule,
    disable_mailbox_forwarding,
    list_authentication_methods,
    list_suspicious_rules,
    revoke_sign_in_sessions,
)
from .diagnosis import build_diagnostic_payload
from .doctor import run_doctor
from .exchange_admin import ExchangeAdminApiError, ExchangeAdminClient
from .graph import GraphApiError, GraphClient
from .investigation import (
    collect_aliases,
    fetch_directory_audits,
    fetch_inbox_rules,
    fetch_risk_detections,
    fetch_signins,
    fetch_signins_window,
    rule_has_forwarding,
    summarize_rule,
)
from .outbound import (
    address_text,
    describe_message_trace_error,
    fetch_folder_messages,
    fetch_mailbox_snapshot,
    fetch_message_traces,
    fetch_user_app_review,
    find_sender_mismatches,
    recipient_addresses,
    summarize_mailbox_snapshot,
)
from .timeline import build_timeline_events


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be greater than zero")
    return parsed


def iso_datetime(value: str) -> datetime:
    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid datetime: {value}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="m365-admin",
        description="Terminal-first Microsoft 365 and Entra investigation CLI.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    login = subparsers.add_parser(
        "login",
        help="Acquire and cache a token for the common investigation workflow.",
    )
    _add_account_arg(login)
    login.add_argument("--include-risk", action="store_true", help="Also include the risk-detection scope.")
    login.add_argument("--force-device-code", action="store_true", help="Always prompt instead of using cache.")

    login_start = subparsers.add_parser(
        "login-start",
        help="Advanced: start a persisted device-code flow.",
        description="Start device-code auth and persist the flow so it can be finished later.",
    )
    _add_account_arg(login_start)
    login_start.add_argument("--include-risk", action="store_true", help="Also include the risk-detection scope.")

    subparsers.add_parser(
        "login-finish",
        help="Advanced: finish a persisted device-code flow.",
        description="Finish a previously started device-code flow and cache the token.",
    )

    investigate = subparsers.add_parser("investigate", help="Run the core compromised-user investigation flow.")
    _add_identifier_args(investigate)
    investigate.add_argument("--skip-risk", action="store_true", help="Skip risk detections.")

    doctor = subparsers.add_parser(
        "doctor",
        help="Run pre-flight checks and tell you what investigation features will work.",
    )
    doctor.add_argument("--profile", help="Tenant profile name from tenants.json.")
    doctor.add_argument("--target", help="Target user UPN for mailbox and directory probes.")
    doctor.add_argument("--fix", action="store_true", help="Attempt supported automated fixes.")
    _add_account_arg(doctor)
    doctor.add_argument("--json", action="store_true", help="Print raw JSON.")

    diagnose = subparsers.add_parser(
        "diagnose",
        help="Pick a tenant and user, then run the full diagnostic workflow.",
    )
    diagnose.add_argument("identifier", nargs="?", help="User principal name for the target user.")
    diagnose.add_argument("--profile", help="Tenant profile name from tenants.json.")
    _add_window_args(diagnose, default_hours=48)
    diagnose.add_argument("--limit", type=positive_int, default=50, help="Maximum rows for each section.")
    diagnose.add_argument("--trace-limit", type=positive_int, default=200, help="Maximum message trace rows.")
    _add_account_arg(diagnose)
    _add_auth_mode_arg(diagnose)
    diagnose.add_argument("--skip-risk", action="store_true", help="Skip risk detections.")
    diagnose.add_argument("--json", action="store_true", help="Print raw JSON.")
    diagnose.add_argument("--force-device-code", action="store_true", help="Always prompt instead of using cache.")

    signins = subparsers.add_parser("signins", help="List recent sign-ins for a user.")
    signins.add_argument("identifier", nargs="?", help="User principal name for the target user.")
    signins.add_argument("--days", type=positive_int, default=7, help="Trailing time window in days.")
    signins.add_argument("--hours", type=positive_int, help="Trailing time window in hours.")
    signins.add_argument("--from", dest="from_time", type=iso_datetime, help="Explicit UTC start time, e.g. 2026-03-09T20:30Z.")
    signins.add_argument("--to", dest="to_time", type=iso_datetime, help="Explicit UTC end time, defaults to now.")
    signins.add_argument("--limit", type=positive_int, default=25, help="Maximum records to print.")
    _add_account_arg(signins)
    signins.add_argument("--json", action="store_true", help="Print raw JSON.")
    signins.add_argument("--force-device-code", action="store_true", help="Always prompt instead of using cache.")

    audits = subparsers.add_parser("audits", help="List recent directory audit events involving a user.")
    _add_identifier_args(audits)

    rules = subparsers.add_parser("rules", help="List inbox rules for a user mailbox.")
    rules.add_argument("identifier", nargs="?", help="User principal name for the target user.")
    _add_account_arg(rules)
    _add_auth_mode_arg(rules)
    rules.add_argument("--json", action="store_true", help="Print raw JSON.")
    rules.add_argument("--force-device-code", action="store_true", help="Always prompt instead of using cache.")

    risk = subparsers.add_parser("risk", help="List recent identity risk detections for a user.")
    _add_identifier_args(risk)

    trace = subparsers.add_parser("trace", help="Pull outbound message trace for a sender address.")
    trace.add_argument("sender", nargs="?", help="Sender SMTP address to trace.")
    trace.add_argument("--recipient", help="Optional recipient SMTP address filter.")
    trace.add_argument("--status", help="Optional status filter. Omit to include all statuses.")
    _add_window_args(trace, default_hours=48)
    trace.add_argument("--limit", type=positive_int, default=200, help="Maximum trace rows to print.")
    _add_account_arg(trace)
    _add_auth_mode_arg(trace)
    trace.add_argument("--json", action="store_true", help="Print raw JSON.")
    trace.add_argument("--force-device-code", action="store_true", help="Always prompt instead of using cache.")

    messages = subparsers.add_parser("messages", help="Review recent messages in Sent Items or Deleted Items.")
    messages.add_argument("identifier", nargs="?", help="User principal name for the target mailbox.")
    messages.add_argument(
        "--folder",
        choices=("sentitems", "deleteditems"),
        default="sentitems",
        help="Mailbox folder to inspect.",
    )
    _add_window_args(messages, default_hours=48)
    messages.add_argument("--limit", type=positive_int, default=50, help="Maximum messages to print.")
    _add_account_arg(messages)
    _add_auth_mode_arg(messages)
    messages.add_argument("--json", action="store_true", help="Print raw JSON.")
    messages.add_argument("--force-device-code", action="store_true", help="Always prompt instead of using cache.")

    apps = subparsers.add_parser("apps", help="Review enterprise app assignments and delegated app consents for a user.")
    apps.add_argument("identifier", nargs="?", help="User principal name for the target user.")
    apps.add_argument("--limit", type=positive_int, default=100, help="Maximum grants to inspect.")
    _add_account_arg(apps)
    _add_auth_mode_arg(apps)
    apps.add_argument("--json", action="store_true", help="Print raw JSON.")
    apps.add_argument("--force-device-code", action="store_true", help="Always prompt instead of using cache.")

    outbound = subparsers.add_parser(
        "outbound-review",
        help="Run the outbound-alert review flow: trace, mailbox items, rules, app grants, and mailbox config.",
    )
    outbound.add_argument("identifier", nargs="?", help="User principal name for the target mailbox.")
    outbound.add_argument("--sender", help="SMTP sender address for message trace. Defaults to the target user.")
    _add_window_args(outbound, default_hours=48)
    outbound.add_argument("--limit", type=positive_int, default=50, help="Maximum rows for each mailbox section.")
    outbound.add_argument("--trace-limit", type=positive_int, default=200, help="Maximum message trace rows.")
    _add_account_arg(outbound)
    _add_auth_mode_arg(outbound)
    outbound.add_argument("--json", action="store_true", help="Print raw JSON.")
    outbound.add_argument("--force-device-code", action="store_true", help="Always prompt instead of using cache.")

    timeline = subparsers.add_parser("timeline", help="Merge sign-ins, audits, traces, and mailbox items into a chronological timeline.")
    timeline.add_argument("identifier", nargs="?", help="User principal name for the target user.")
    timeline.add_argument("--profile", help="Tenant profile name from tenants.json.")
    timeline.add_argument("--sender", help="SMTP sender address for message trace. Defaults to the target user.")
    timeline.add_argument("--hours", type=positive_int, help="Trailing time window in hours.")
    timeline.add_argument("--from", dest="from_time", type=iso_datetime, help="Explicit UTC start time.")
    timeline.add_argument("--to", dest="to_time", type=iso_datetime, help="Explicit UTC end time, defaults to now.")
    timeline.add_argument("--limit", type=positive_int, default=50, help="Maximum sign-in/audit/message rows.")
    timeline.add_argument("--trace-limit", type=positive_int, default=200, help="Maximum trace rows.")
    _add_account_arg(timeline)
    _add_auth_mode_arg(timeline)
    timeline.add_argument("--json", action="store_true", help="Print raw JSON.")
    timeline.add_argument("--force-device-code", action="store_true", help="Always prompt instead of using cache.")

    contain = subparsers.add_parser("contain", help="Run standard containment actions with dry-run and confirmations.")
    contain.add_argument("identifier", nargs="?", help="User principal name for the target user.")
    contain.add_argument("--profile", help="Tenant profile name from tenants.json.")
    contain.add_argument("--dry-run", action="store_true", help="Plan actions without executing them.")
    contain.add_argument("--yes", action="store_true", help="Skip confirmations and execute planned actions.")
    contain.add_argument("--block-sign-in", action="store_true", help="Also disable the user account after revoking sessions.")
    _add_account_arg(contain)
    _add_auth_mode_arg(contain)
    contain.add_argument("--json", action="store_true", help="Print raw JSON.")
    contain.add_argument("--force-device-code", action="store_true", help="Always prompt instead of using cache.")

    return parser


def _add_identifier_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("identifier", nargs="?", help="User principal name for the target user.")
    parser.add_argument("--days", type=positive_int, default=7, help="Trailing time window in days.")
    parser.add_argument("--limit", type=positive_int, default=25, help="Maximum records to print.")
    _add_account_arg(parser)
    parser.add_argument("--json", action="store_true", help="Print raw JSON.")
    parser.add_argument("--force-device-code", action="store_true", help="Always prompt instead of using cache.")


def _add_account_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--account",
        help="Admin account UPN to prefer for silent token reuse and device-code login.",
    )


def _add_auth_mode_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--auth",
        choices=("auto", "delegated", "app"),
        default="auto",
        help="Auth mode to use. `app` requires M365_CLIENT_SECRET.",
    )


def _add_window_args(parser: argparse.ArgumentParser, *, default_hours: int) -> None:
    parser.add_argument("--hours", type=positive_int, default=default_hours, help="Trailing time window in hours.")
    parser.add_argument("--days", type=positive_int, help="Trailing time window in days.")


def utc_now() -> datetime:
    return datetime.now(UTC)


def resolve_time_window(
    *,
    from_time: datetime | None = None,
    to_time: datetime | None = None,
    hours: int | None = None,
    days: int | None = None,
) -> tuple[datetime, datetime, str]:
    end = to_time or utc_now()
    if from_time and hours is not None:
        raise ConfigurationError("Use either --from/--to or --hours, not both.")
    if from_time:
        start = from_time
    elif hours is not None:
        start = end - timedelta(hours=hours)
    else:
        start = end - timedelta(days=days or 7)
    if start > end:
        raise ConfigurationError("Window start must be before window end.")
    return start, end, f"{start.isoformat()} -> {end.isoformat()}"


def prompt_value(
    label: str,
    *,
    default: str | None = None,
    allow_empty: bool = False,
    prompt: Callable[[str], str] = input,
) -> str | None:
    if not sys.stdin.isatty():
        if default is not None:
            return default
        if allow_empty:
            return None
        raise ConfigurationError(f"{label} is required in non-interactive mode.")

    suffix = f" [{default}]" if default else ""
    while True:
        raw = prompt(f"{label}{suffix}: ").strip()
        if raw:
            return raw
        if default is not None:
            return default
        if allow_empty:
            return None


def choose_option(
    title: str,
    options: list[str],
    *,
    default_index: int | None = None,
    prompt: Callable[[str], str] = input,
) -> str:
    if not options:
        raise ConfigurationError(f"No options available for {title}.")
    if len(options) == 1:
        return options[0]
    if not sys.stdin.isatty():
        if default_index is not None:
            return options[default_index]
        raise ConfigurationError(f"{title} must be specified in non-interactive mode.")

    print(title, file=sys.stderr)
    for index, item in enumerate(options, start=1):
        marker = " (default)" if default_index == index - 1 else ""
        print(f"  {index}. {item}{marker}", file=sys.stderr)

    while True:
        default_hint = f" [{default_index + 1}]" if default_index is not None else ""
        raw = prompt(f"Select option{default_hint}: ").strip()
        if not raw and default_index is not None:
            return options[default_index]
        if raw.isdigit():
            selection = int(raw)
            if 1 <= selection <= len(options):
                return options[selection - 1]
        print("Invalid selection.", file=sys.stderr)


def confirm_action(
    message: str,
    *,
    default: bool = False,
    prompt: Callable[[str], str] = input,
) -> bool:
    if not sys.stdin.isatty():
        return default
    suffix = "Y/n" if default else "y/N"
    raw = prompt(f"{message} [{suffix}]: ").strip().lower()
    if not raw:
        return default
    return raw in {"y", "yes"}


def resolve_identifier(
    identifier: str | None,
    *,
    prompt: Callable[[str], str] = input,
) -> str:
    value = (identifier or "").strip()
    if value:
        return value
    resolved = prompt_value("Target user UPN", prompt=prompt)
    if not resolved:
        raise ConfigurationError("Target user UPN is required.")
    return resolved


def resolve_account(
    account: str | None,
    settings: Settings,
    *,
    prompt: Callable[[str], str] = input,
) -> str | None:
    value = (account or settings.username or "").strip()
    if value:
        return value
    return prompt_value(
        "Admin account UPN for Graph login (leave blank to choose in browser)",
        allow_empty=True,
        prompt=prompt,
    )


def resolve_sender(
    sender: str | None,
    *,
    identifier: str | None = None,
    prompt: Callable[[str], str] = input,
) -> str:
    value = (sender or identifier or "").strip()
    if value:
        return value
    resolved = prompt_value("Sender address for message trace", prompt=prompt)
    if not resolved:
        raise ConfigurationError("Sender address is required.")
    return resolved


def resolve_auth_mode(requested_mode: str, settings: Settings, *, prefer_app: bool = False) -> str:
    if requested_mode == "auto":
        if prefer_app and settings.client_secret:
            return "app"
        return "delegated"
    if requested_mode == "app" and not settings.client_secret:
        raise ConfigurationError("M365_CLIENT_SECRET is required for --auth app.")
    return requested_mode


def resolve_settings_profile(
    settings: Settings,
    profile_name: str | None,
    *,
    cwd: str | None = None,
    prompt: Callable[[str], str] = input,
) -> Settings:
    profiles, default_name, _ = load_tenant_profiles(None if cwd is None else Path(cwd))
    if not profiles:
        return settings

    by_name = {profile.name: profile for profile in profiles}
    selected_name = (profile_name or "").strip() or default_name
    if not selected_name:
        names = [profile.name for profile in profiles]
        selected_name = choose_option("Available tenant profiles:", names, prompt=prompt)

    if selected_name not in by_name:
        available = ", ".join(sorted(by_name))
        raise ConfigurationError(f"Unknown tenant profile '{selected_name}'. Available: {available}")
    return settings.with_profile(by_name[selected_name])


def acquire_graph_token(
    provider: TokenProvider,
    settings: Settings,
    *,
    mode: str,
    scopes: tuple[str, ...],
    force_device_code: bool,
    account: str | None,
) -> str:
    if mode == "app":
        return provider.get_app_access_token(GRAPH_RESOURCE)
    return provider.get_access_token(scopes, force_device_code=force_device_code, username=account)


def acquire_exchange_token(
    provider: TokenProvider,
    settings: Settings,
    *,
    mode: str,
    force_device_code: bool,
    account: str | None,
) -> str:
    if mode == "app":
        return provider.get_app_access_token(EXCHANGE_RESOURCE)
    return provider.get_access_token(
        exchange_delegated_scopes(),
        force_device_code=force_device_code,
        username=account,
    )


def json_dump(payload: Any) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))


def format_location(payload: dict[str, Any] | None) -> str:
    location = payload or {}
    parts = [location.get("city"), location.get("state"), location.get("countryOrRegion")]
    rendered = ", ".join(str(part) for part in parts if part)
    return rendered or "-"


def format_signin(signin: dict[str, Any]) -> str:
    status = signin.get("status") or {}
    error_code = status.get("errorCode")
    if error_code in (None, 0):
        outcome = "success"
    else:
        outcome = f"error={error_code}"

    return " | ".join(
        [
            signin.get("createdDateTime") or "-",
            outcome,
            signin.get("appDisplayName") or "-",
            signin.get("clientAppUsed") or "-",
            signin.get("ipAddress") or "-",
            format_location(signin.get("location")),
            f"risk={signin.get('riskLevelAggregated') or 'none'}",
            f"ca={signin.get('conditionalAccessStatus') or 'unknown'}",
        ]
    )


def format_audit(event: dict[str, Any]) -> str:
    initiated_by = ((event.get("initiatedBy") or {}).get("user") or {}).get("userPrincipalName")
    if not initiated_by:
        initiated_by = ((event.get("initiatedBy") or {}).get("app") or {}).get("displayName")

    targets = []
    for target in event.get("targetResources") or []:
        target_value = target.get("userPrincipalName") or target.get("displayName") or target.get("id")
        if target_value:
            targets.append(str(target_value))

    return " | ".join(
        [
            event.get("activityDateTime") or "-",
            event.get("activityDisplayName") or "-",
            event.get("result") or "-",
            f"by={initiated_by or '-'}",
            f"targets={', '.join(targets[:3]) or '-'}",
        ]
    )


def format_rule(rule: dict[str, Any]) -> str:
    summary = summarize_rule(rule)
    flags = []
    if summary["forwarding"]:
        flags.append("forwarding")
    if summary["hasError"]:
        flags.append("error")
    if summary["isReadOnly"]:
        flags.append("readOnly")
    flag_text = ",".join(flags) if flags else "none"
    return " | ".join(
        [
            f"seq={summary['sequence']}",
            f"enabled={summary['isEnabled']}",
            summary["displayName"],
            f"flags={flag_text}",
            f"if {summary['conditions']}",
            f"then {summary['actions']}",
        ]
    )


def format_trace(trace: dict[str, Any]) -> str:
    return " | ".join(
        [
            trace.get("receivedDateTime") or trace.get("createdDateTime") or "-",
            trace.get("status") or "-",
            trace.get("senderAddress") or "-",
            trace.get("recipientAddress") or "-",
            trace.get("subject") or "-",
            trace.get("networkMessageId") or trace.get("messageTraceId") or trace.get("id") or "-",
        ]
    )


def format_message(message: dict[str, Any], *, folder_name: str) -> str:
    if folder_name == "sentitems":
        timestamp = message.get("sentDateTime") or "-"
    else:
        timestamp = message.get("lastModifiedDateTime") or message.get("receivedDateTime") or "-"

    to_text = ", ".join(recipient_addresses(message.get("toRecipients"))) or "-"
    from_address = address_text(message.get("from"))
    sender_address = address_text(message.get("sender"))
    sender_note = f"sender={sender_address}" if sender_address != from_address else f"from={from_address}"
    return " | ".join(
        [
            timestamp,
            sender_note,
            f"to={to_text}",
            message.get("subject") or "-",
            f"attachments={message.get('hasAttachments')}",
            message.get("internetMessageId") or "-",
        ]
    )


def format_app_role_assignment(item: dict[str, Any]) -> str:
    return " | ".join(
        [
            item.get("resourceDisplayName") or "-",
            item.get("resourceAppId") or "-",
            item.get("appRoleId") or "-",
        ]
    )


def format_delegated_grant(item: dict[str, Any]) -> str:
    return " | ".join(
        [
            item.get("clientDisplayName") or "-",
            item.get("resourceDisplayName") or "-",
            item.get("scope") or "-",
            item.get("consentType") or "-",
        ]
    )


def summarize_trace_statuses(traces: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for trace in traces:
        status = str(trace.get("status") or "unknown")
        counts[status] = counts.get(status, 0) + 1
    return counts


def format_risk_detection(item: dict[str, Any]) -> str:
    return " | ".join(
        [
            item.get("activityDateTime") or "-",
            item.get("riskEventType") or "-",
            item.get("riskLevel") or "-",
            item.get("riskState") or "-",
            item.get("ipAddress") or "-",
            format_location(item.get("location")),
            item.get("requestId") or "-",
        ]
    )


def print_section(title: str, lines: list[str]) -> None:
    print(f"\n{title}")
    if not lines:
        print("(none)")
        return
    for line in lines:
        print(f"- {line}")


def print_doctor_table(checks: list[dict[str, Any]]) -> None:
    headers = ("Status", "Check", "Impact", "Fix")
    rows = [
        (
            str(item.get("status") or ""),
            str(item.get("check") or ""),
            str(item.get("impact") or ""),
            str(item.get("fix_hint") or ""),
        )
        for item in checks
    ]
    widths = [
        max(len(headers[index]), *(len(row[index]) for row in rows)) if rows else len(headers[index])
        for index in range(len(headers))
    ]
    print(" | ".join(header.ljust(widths[index]) for index, header in enumerate(headers)))
    print("-+-".join("-" * width for width in widths))
    for row in rows:
        print(" | ".join(row[index].ljust(widths[index]) for index in range(len(headers))))


def summarize_signins(signins: list[dict[str, Any]]) -> dict[str, Any]:
    failures = sum(1 for item in signins if ((item.get("status") or {}).get("errorCode") or 0) != 0)
    risky = sum(1 for item in signins if (item.get("riskLevelAggregated") or "none") != "none")
    unique_ips = sorted({item.get("ipAddress") for item in signins if item.get("ipAddress")})
    return {
        "total": len(signins),
        "failures": failures,
        "risky": risky,
        "uniqueIpCount": len(unique_ips),
        "uniqueIps": unique_ips,
    }


def summarize_rules(rules: list[dict[str, Any]]) -> dict[str, Any]:
    forwarding = sum(1 for rule in rules if rule_has_forwarding(rule))
    return {
        "total": len(rules),
        "forwarding": forwarding,
    }


def cmd_login(args: argparse.Namespace, settings: Settings) -> int:
    settings = resolve_settings_profile(settings, getattr(args, "profile", None))
    scopes = default_login_scopes(include_risk=args.include_risk)
    provider = TokenProvider(settings)
    account = resolve_account(args.account, settings)
    provider.get_access_token(scopes, force_device_code=args.force_device_code, username=account)
    print("Token acquired and cached for the common investigation scopes.")
    return 0


def cmd_login_start(args: argparse.Namespace, settings: Settings) -> int:
    settings = resolve_settings_profile(settings, getattr(args, "profile", None))
    scopes = default_login_scopes(include_risk=args.include_risk)
    provider = TokenProvider(settings)
    account = resolve_account(args.account, settings)
    payload = provider.start_device_flow(scopes, username=account)
    flow = payload["flow"]
    print(flow["message"], file=sys.stderr)
    print(f"Device flow saved to {settings.device_flow_path}")
    return 0


def cmd_login_finish(args: argparse.Namespace, settings: Settings) -> int:
    provider = TokenProvider(settings)
    provider.finish_device_flow()
    print("Token acquired and cached.")
    return 0


def cmd_signins(args: argparse.Namespace, settings: Settings) -> int:
    identifier = resolve_identifier(args.identifier)
    account = resolve_account(args.account, settings)
    provider = TokenProvider(settings)
    graph = GraphClient(settings)
    token = provider.get_access_token(
        requested_scopes(),
        force_device_code=args.force_device_code,
        username=account,
    )
    if args.from_time or args.to_time or args.hours is not None:
        start, end, window_label = resolve_time_window(
            from_time=args.from_time,
            to_time=args.to_time,
            hours=args.hours,
            days=args.days,
        )
        signins = fetch_signins_window(graph, token, identifier, start, end, args.limit)
    else:
        signins = fetch_signins(graph, token, identifier, args.days, args.limit)
        window_label = f"last {args.days} day(s)"

    if args.json:
        json_dump(signins)
        return 0

    print(f"Sign-ins for {identifier} in {window_label}: {len(signins)}")
    print_section("Recent Sign-ins", [format_signin(item) for item in signins])
    return 0


def cmd_audits(args: argparse.Namespace, settings: Settings) -> int:
    identifier = resolve_identifier(args.identifier)
    account = resolve_account(args.account, settings)
    provider = TokenProvider(settings)
    graph = GraphClient(settings)
    token = provider.get_access_token(
        requested_scopes(),
        force_device_code=args.force_device_code,
        username=account,
    )
    events = fetch_directory_audits(graph, token, [identifier], args.days, args.limit)

    if args.json:
        json_dump(events)
        return 0

    print(f"Directory audit events involving {identifier} in the last {args.days} day(s): {len(events)}")
    print_section("Directory Audits", [format_audit(item) for item in events])
    return 0


def cmd_rules(args: argparse.Namespace, settings: Settings) -> int:
    identifier = resolve_identifier(args.identifier)
    auth_mode = resolve_auth_mode(args.auth, settings, prefer_app=True)
    account = None if auth_mode == "app" else resolve_account(args.account, settings)
    provider = TokenProvider(settings)
    graph = GraphClient(settings)
    token = acquire_graph_token(
        provider,
        settings,
        mode=auth_mode,
        scopes=requested_scopes(),
        force_device_code=args.force_device_code,
        account=account,
    )
    rules = fetch_inbox_rules(graph, token, identifier)

    if args.json:
        json_dump(rules)
        return 0

    print(f"Inbox rules for {identifier}: {len(rules)}")
    print_section("Inbox Rules", [format_rule(item) for item in rules])
    return 0


def cmd_risk(args: argparse.Namespace, settings: Settings) -> int:
    identifier = resolve_identifier(args.identifier)
    account = resolve_account(args.account, settings)
    provider = TokenProvider(settings)
    graph = GraphClient(settings)
    token = provider.get_access_token(
        requested_scopes(include_risk=True),
        force_device_code=args.force_device_code,
        username=account,
    )
    items = fetch_risk_detections(graph, token, identifier, args.days, args.limit)

    if args.json:
        json_dump(items)
        return 0

    print(f"Risk detections for {identifier} in the last {args.days} day(s): {len(items)}")
    print_section("Risk Detections", [format_risk_detection(item) for item in items])
    return 0


def cmd_investigate(args: argparse.Namespace, settings: Settings) -> int:
    identifier = resolve_identifier(args.identifier)
    account = resolve_account(args.account, settings)
    provider = TokenProvider(settings)
    graph = GraphClient(settings)
    token = provider.get_access_token(
        requested_scopes(),
        force_device_code=args.force_device_code,
        username=account,
    )

    signins = fetch_signins(graph, token, identifier, args.days, args.limit)
    aliases = collect_aliases(identifier, signins)

    warnings: list[str] = []
    section_data: dict[str, Any] = {"signins": signins}

    fetchers: list[tuple[str, Callable[[], Any]]] = [
        ("audits", lambda: fetch_directory_audits(graph, token, aliases, args.days, args.limit)),
        ("rules", lambda: fetch_inbox_rules(graph, token, identifier)),
    ]

    for key, fetcher in fetchers:
        try:
            section_data[key] = fetcher()
        except GraphApiError as exc:
            warnings.append(f"{key}: {exc}")
            section_data[key] = []

    if args.skip_risk:
        section_data["riskDetections"] = []
    else:
        try:
            risk_token = provider.get_access_token(
                requested_scopes(include_risk=True),
                force_device_code=args.force_device_code,
                username=account,
            )
            section_data["riskDetections"] = fetch_risk_detections(
                graph,
                risk_token,
                identifier,
                args.days,
                args.limit,
            )
        except (AuthError, GraphApiError) as exc:
            warnings.append(f"riskDetections: {exc}")
            section_data["riskDetections"] = []

    summary = {
        "identifier": identifier,
        "days": args.days,
        "aliases": aliases,
        "signins": summarize_signins(section_data["signins"]),
        "audits": {"total": len(section_data["audits"])},
        "rules": summarize_rules(section_data["rules"]),
        "riskDetections": {"total": len(section_data["riskDetections"])},
        "warnings": warnings,
    }

    payload = {
        "summary": summary,
        "signins": section_data["signins"],
        "audits": section_data["audits"],
        "rules": section_data["rules"],
        "riskDetections": section_data["riskDetections"],
    }

    if args.json:
        json_dump(payload)
        return 0

    print(f"Investigation summary for {identifier}")
    print(f"Window: last {args.days} day(s)")
    print(f"Sign-ins: {summary['signins']['total']} total, {summary['signins']['failures']} failed, {summary['signins']['risky']} risky")
    print(f"Unique IPs: {summary['signins']['uniqueIpCount']}")
    print(f"Directory audits: {summary['audits']['total']}")
    print(f"Inbox rules: {summary['rules']['total']} total, {summary['rules']['forwarding']} forwarding/redirect")
    print(f"Risk detections: {summary['riskDetections']['total']}")

    if warnings:
        print_section("Warnings", warnings)

    print_section("Recent Sign-ins", [format_signin(item) for item in section_data["signins"]])
    print_section("Directory Audits", [format_audit(item) for item in section_data["audits"]])
    print_section("Inbox Rules", [format_rule(item) for item in section_data["rules"]])

    if not args.skip_risk:
        print_section("Risk Detections", [format_risk_detection(item) for item in section_data["riskDetections"]])

    return 0


def cmd_doctor(args: argparse.Namespace, settings: Settings) -> int:
    settings = resolve_settings_profile(settings, args.profile)
    account = resolve_account(args.account, settings)
    payload = run_doctor(
        settings,
        account=account,
        target=(args.target or "").strip() or None,
        fix=args.fix,
    )

    if args.json:
        json_dump(payload)
        return 0

    print(f"Doctor for tenant: {settings.profile_name or settings.tenant_id or '(unknown tenant)'}")
    if payload.get("target"):
        print(f"Target user: {payload['target']}")
    if payload.get("account"):
        print(f"Admin account: {payload['account']}")
    print()
    print_doctor_table(payload["checks"])

    if payload.get("fixes"):
        print_section(
            "Fixes",
            [f"{item['status']}: {item['fix']} | {item['details']}" for item in payload["fixes"]],
        )

    detail_lines = [
        f"{item['check']}: {item['details']}"
        for item in payload["checks"]
        if item.get("details")
    ]
    if detail_lines:
        print_section("Details", detail_lines)
    summary = payload["summary"]
    print(
        f"\nSummary: pass={summary.get('pass', 0)} "
        f"fail={summary.get('fail', 0)} skip={summary.get('skip', 0)} warn={summary.get('warn', 0)}"
    )
    return 0


def build_full_diagnostic_payload(
    identifier: str,
    *,
    sender: str,
    settings: Settings,
    auth_mode: str,
    account: str | None,
    days: int,
    hours: int,
    limit: int,
    trace_limit: int,
    skip_risk: bool,
    force_device_code: bool,
) -> dict[str, Any]:
    provider = TokenProvider(settings)
    graph = GraphClient(settings)
    exchange = ExchangeAdminClient(settings)

    graph_token = acquire_graph_token(
        provider,
        settings,
        mode=auth_mode,
        scopes=default_login_scopes(include_risk=not skip_risk),
        force_device_code=force_device_code,
        account=account,
    )
    exchange_token: str | None = None
    try:
        exchange_token = acquire_exchange_token(
            provider,
            settings,
            mode=auth_mode,
            force_device_code=force_device_code,
            account=account,
        )
    except (AuthError, ExchangeAdminApiError):
        exchange_token = None

    payload = build_diagnostic_payload(
        graph=graph,
        exchange=exchange,
        graph_token=graph_token,
        exchange_token=exchange_token,
        settings_client_id=settings.client_id,
        identifier=identifier,
        sender=sender,
        days=days,
        hours=hours,
        limit=limit,
        trace_limit=trace_limit,
        skip_risk=skip_risk,
    )
    payload["tenantProfile"] = settings.profile_name
    payload["tenantId"] = settings.tenant_id
    payload["account"] = account or settings.username
    if exchange_token is None:
        payload["warnings"].append("exchange: Exchange token unavailable; Exchange-backed mailbox and delegation checks may be incomplete.")
        payload["summary"]["warnings"] = payload["warnings"]
    return payload


def cmd_diagnose(args: argparse.Namespace, settings: Settings) -> int:
    settings = resolve_settings_profile(settings, args.profile)
    identifier = resolve_identifier(args.identifier)
    auth_mode = resolve_auth_mode(args.auth, settings, prefer_app=True)
    account = None if auth_mode == "app" else resolve_account(args.account, settings)
    sender = resolve_sender(None, identifier=identifier)
    days = args.days or max(1, (args.hours + 23) // 24)
    payload = build_full_diagnostic_payload(
        identifier,
        sender=sender,
        settings=settings,
        auth_mode=auth_mode,
        account=account,
        days=days,
        hours=args.hours,
        limit=args.limit,
        trace_limit=args.trace_limit,
        skip_risk=args.skip_risk,
        force_device_code=args.force_device_code,
    )

    if args.json:
        json_dump(payload)
        return 0

    print(f"Diagnostic summary for {identifier}")
    print(f"Tenant profile: {settings.profile_name or '(env)'}")
    print(f"Tenant ID: {settings.tenant_id}")
    print(f"Verdict: {payload['summary']['verdict']}")
    print(f"Reason: {payload['summary']['verdictReason']}")
    print(f"Sign-ins: {payload['signins']['summary']['total']}")
    print(f"Directory audits: {payload['audit']['summary']['total']}")
    print(f"Inbox rules: {payload['mailbox']['summary']['ruleCount']}")
    print(f"Risk detections: {payload['identity']['riskSummary']['count']}")
    print(f"Trace rows: {payload['outbound']['summary']['traceCount']}")
    print(f"Sent Items: {payload['mailbox']['summary']['sentItemCount']}")
    print(f"Deleted Items: {payload['mailbox']['summary']['deletedItemCount']}")
    print(f"Suspicious app grants: {payload['apps']['summary']['suspiciousGrantCount']}")
    print(f"Delegation present: {payload['delegation']['summary']['hasDelegation']}")
    if payload["confirmedCompromiseIndicators"]:
        print_section(
            "Confirmed Indicators",
            [f"{item['severity']}: {item['title']} | {item['explanation']}" for item in payload["confirmedCompromiseIndicators"]],
        )
    if payload["suspectedIndicators"]:
        print_section(
            "Suspected Indicators",
            [f"{item['severity']}: {item['title']} | {item['explanation']}" for item in payload["suspectedIndicators"]],
        )
    if payload["remediationAlreadyTaken"]:
        print_section(
            "Remediation Already Taken",
            [
                " | ".join(
                    part
                    for part in (
                        str(item.get("timestamp") or "-"),
                        str(item.get("title") or "-"),
                        str(item.get("explanation") or "-"),
                    )
                    if part
                )
                for item in payload["remediationAlreadyTaken"]
            ],
        )
    if payload["unavailableEvidence"]:
        print_section(
            "Unavailable Evidence",
            [
                " | ".join(
                    part
                    for part in (
                        str(item.get("status") or "-"),
                        str(item.get("title") or "-"),
                        str(item.get("details") or "-"),
                    )
                    if part
                )
                for item in payload["unavailableEvidence"]
            ],
        )
    if payload["recommendedActions"]:
        print_section(
            "Recommended Actions",
            [f"{item['title']} | {item['explanation']}" for item in payload["recommendedActions"]],
        )
    elif payload["warnings"]:
        print_section("Warnings", payload["warnings"])
    return 0


def cmd_trace(args: argparse.Namespace, settings: Settings) -> int:
    sender = resolve_sender(args.sender)
    auth_mode = resolve_auth_mode(args.auth, settings)
    account = None if auth_mode == "app" else resolve_account(args.account, settings)
    provider = TokenProvider(settings)
    graph = GraphClient(settings)
    token = acquire_graph_token(
        provider,
        settings,
        mode=auth_mode,
        scopes=requested_scopes(include_trace=True),
        force_device_code=args.force_device_code,
        account=account,
    )
    try:
        traces = fetch_message_traces(
            graph,
            token,
            sender=sender,
            recipient=args.recipient,
            hours=args.hours,
            days=args.days,
            status=args.status,
            limit=args.limit,
        )
    except GraphApiError as exc:
        raise describe_message_trace_error(exc, configured_client_id=settings.client_id) from exc

    if args.json:
        json_dump(traces)
        return 0

    status_counts = summarize_trace_statuses(traces)
    print(f"Message trace for {sender}: {len(traces)} row(s)")
    print(f"Window: last {args.days or args.hours} {'day(s)' if args.days else 'hour(s)'}")
    if status_counts:
        print(f"Statuses: {', '.join(f'{key}={value}' for key, value in sorted(status_counts.items()))}")
    print_section("Trace Rows", [format_trace(item) for item in traces])
    return 0


def cmd_timeline(args: argparse.Namespace, settings: Settings) -> int:
    settings = resolve_settings_profile(settings, args.profile)
    identifier = resolve_identifier(args.identifier)
    sender = resolve_sender(args.sender, identifier=identifier)
    auth_mode = resolve_auth_mode(args.auth, settings, prefer_app=True)
    account = None if auth_mode == "app" else resolve_account(args.account, settings)
    start, end, window_label = resolve_time_window(from_time=args.from_time, to_time=args.to_time, hours=args.hours, days=2)

    provider = TokenProvider(settings)
    graph = GraphClient(settings)
    token = acquire_graph_token(
        provider,
        settings,
        mode=auth_mode,
        scopes=default_login_scopes(),
        force_device_code=args.force_device_code,
        account=account,
    )
    events, warnings = build_timeline_events(
        graph=graph,
        token=token,
        identifier=identifier,
        sender=sender,
        start=start,
        end=end,
        limit=args.limit,
        trace_limit=args.trace_limit,
    )

    payload = {
        "identifier": identifier,
        "sender": sender,
        "window": {"start": start.isoformat(), "end": end.isoformat()},
        "events": events,
        "warnings": warnings,
    }
    if args.json:
        json_dump(payload)
        return 0

    print(f"Timeline for {identifier}")
    print(f"Window: {window_label}")
    if warnings:
        print_section("Warnings", warnings)
    print_section(
        "Events",
        [
            " | ".join(
                [
                    str(item.get("timestamp") or "-"),
                    str(item.get("source") or "-"),
                    str(item.get("event_type") or "-"),
                    str(item.get("summary") or "-"),
                    str(item.get("status") or "-"),
                ]
            )
            for item in events
        ],
    )
    return 0


def cmd_contain(args: argparse.Namespace, settings: Settings) -> int:
    settings = resolve_settings_profile(settings, args.profile)
    identifier = resolve_identifier(args.identifier)
    auth_mode = resolve_auth_mode(args.auth, settings, prefer_app=True)
    account = None if auth_mode == "app" else resolve_account(args.account, settings)

    provider = TokenProvider(settings)
    graph = GraphClient(settings)
    exchange = ExchangeAdminClient(settings)
    graph_token: str | None
    exchange_token: str | None
    if args.dry_run:
        if auth_mode == "app":
            try:
                graph_token = provider.get_app_access_token(GRAPH_RESOURCE)
            except AuthError:
                graph_token = None
            try:
                exchange_token = provider.get_app_access_token(EXCHANGE_RESOURCE)
            except AuthError:
                exchange_token = None
        else:
            graph_token = provider.get_access_token_silent(default_login_scopes(), username=account)
            exchange_token = provider.get_access_token_silent(exchange_delegated_scopes(), username=account)
    else:
        graph_token = acquire_graph_token(
            provider,
            settings,
            mode=auth_mode,
            scopes=containment_scopes(),
            force_device_code=args.force_device_code,
            account=account,
        )
        try:
            exchange_token = acquire_exchange_token(
                provider,
                settings,
                mode=auth_mode,
                force_device_code=args.force_device_code,
                account=account,
            )
        except (AuthError, ExchangeAdminApiError):
            exchange_token = None

    warnings: list[str] = []
    if graph_token:
        try:
            auth_methods = list_authentication_methods(graph, graph_token, identifier=identifier)
        except GraphApiError as exc:
            auth_methods = []
            warnings.append(f"authMethods: {exc}")

        try:
            suspicious_rules = list_suspicious_rules(graph, graph_token, identifier=identifier)
        except GraphApiError as exc:
            suspicious_rules = []
            warnings.append(f"rules: {exc}")
    else:
        auth_methods = []
        suspicious_rules = []
        warnings.append("graph: No cached Graph token available for planning. Run m365-admin login first.")

    forwarding_active = False
    if exchange_token:
        try:
            mailbox_snapshot = fetch_mailbox_snapshot(exchange, exchange_token, identifier=identifier)
            mailbox_summary = summarize_mailbox_snapshot(mailbox_snapshot)
            forwarding_active = bool(
                mailbox_summary.get("forwardingAddress")
                or mailbox_summary.get("forwardingSmtpAddress")
                or mailbox_summary.get("deliverToMailboxAndForward")
            )
        except ExchangeAdminApiError as exc:
            mailbox_summary = {}
            warnings.append(f"mailboxSnapshot: {exc}")
    else:
        mailbox_summary = {}
        warnings.append("mailboxSnapshot: Exchange token unavailable.")

    planned_actions: list[dict[str, Any]] = [{"action": "list_auth_methods", "status": "info", "details": f"{len(auth_methods)} method(s)"}]
    planned_actions.append({"action": "revoke_sign_in_sessions", "status": "planned", "details": ""})
    if forwarding_active:
        planned_actions.append({"action": "disable_mailbox_forwarding", "status": "planned", "details": ""})
    for rule in suspicious_rules:
        planned_actions.append({"action": "disable_inbox_rule", "status": "planned", "details": str(rule.get("displayName") or rule.get("id") or "")})
    if args.block_sign_in:
        planned_actions.append({"action": "block_sign_in", "status": "planned", "details": ""})

    executed_actions: list[dict[str, Any]] = []
    for action in planned_actions:
        if action["status"] == "info":
            executed_actions.append(action)
            continue

        should_execute = not args.dry_run
        if should_execute and not args.yes:
            should_execute = confirm_action(f"Execute {action['action']} for {identifier}?", default=False)
        if not should_execute:
            executed_actions.append({**action, "status": "skipped"})
            continue

        try:
            if action["action"] == "revoke_sign_in_sessions":
                if not graph_token:
                    raise GraphApiError(401, "Graph token unavailable.")
                revoke_sign_in_sessions(graph, graph_token, identifier=identifier)
            elif action["action"] == "disable_mailbox_forwarding":
                if not exchange_token:
                    raise ExchangeAdminApiError(401, "Exchange token unavailable.")
                disable_mailbox_forwarding(exchange, exchange_token, identifier=identifier)
            elif action["action"] == "disable_inbox_rule":
                if not graph_token:
                    raise GraphApiError(401, "Graph token unavailable.")
                match = next((item for item in suspicious_rules if str(item.get("displayName") or item.get("id") or "") == action["details"]), None)
                if not match or not match.get("id"):
                    raise GraphApiError(404, f"Rule {action['details']} was not found.")
                disable_inbox_rule(graph, graph_token, identifier=identifier, rule_id=str(match["id"]))
            elif action["action"] == "block_sign_in":
                if not graph_token:
                    raise GraphApiError(401, "Graph token unavailable.")
                block_user_sign_in(graph, graph_token, identifier=identifier)
            executed_actions.append({**action, "status": "success"})
        except (GraphApiError, ExchangeAdminApiError) as exc:
            executed_actions.append({**action, "status": "failed", "details": str(exc)})

    payload = {
        "identifier": identifier,
        "account": account or settings.username,
        "dryRun": args.dry_run,
        "authMethods": auth_methods,
        "suspiciousRules": [summarize_rule(item) for item in suspicious_rules],
        "mailboxSnapshot": mailbox_summary,
        "actions": executed_actions,
        "warnings": warnings,
    }
    if args.json:
        json_dump(payload)
        return 0

    print(f"Containment plan for {identifier}")
    if warnings:
        print_section("Warnings", warnings)
    print_section(
        "Actions",
        [f"{item['status']}: {item['action']} {item.get('details', '')}".strip() for item in executed_actions],
    )
    return 0


def cmd_messages(args: argparse.Namespace, settings: Settings) -> int:
    identifier = resolve_identifier(args.identifier)
    auth_mode = resolve_auth_mode(args.auth, settings, prefer_app=True)
    account = None if auth_mode == "app" else resolve_account(args.account, settings)
    provider = TokenProvider(settings)
    graph = GraphClient(settings)
    token = acquire_graph_token(
        provider,
        settings,
        mode=auth_mode,
        scopes=requested_scopes(include_mail=True),
        force_device_code=args.force_device_code,
        account=account,
    )
    date_field = "sentDateTime" if args.folder == "sentitems" else "lastModifiedDateTime"
    messages = fetch_folder_messages(
        graph,
        token,
        mailbox=identifier,
        folder_name=args.folder,
        date_field=date_field,
        hours=args.hours,
        days=args.days,
        limit=args.limit,
    )

    if args.json:
        json_dump(messages)
        return 0

    print(f"{args.folder} review for {identifier}: {len(messages)} message(s)")
    print_section("Messages", [format_message(item, folder_name=args.folder) for item in messages])
    return 0


def cmd_apps(args: argparse.Namespace, settings: Settings) -> int:
    identifier = resolve_identifier(args.identifier)
    auth_mode = resolve_auth_mode(args.auth, settings, prefer_app=True)
    account = None if auth_mode == "app" else resolve_account(args.account, settings)
    provider = TokenProvider(settings)
    graph = GraphClient(settings)
    token = acquire_graph_token(
        provider,
        settings,
        mode=auth_mode,
        scopes=requested_scopes(include_directory=True),
        force_device_code=args.force_device_code,
        account=account,
    )
    review = fetch_user_app_review(graph, token, identifier=identifier, limit=args.limit)

    if args.json:
        json_dump(review)
        return 0

    print(f"Enterprise app review for {identifier}")
    print(f"Delegated app consents: {len(review['delegatedPermissionGrants'])}")
    print(f"App role assignments: {len(review['appRoleAssignments'])}")
    print_section(
        "Delegated App Consents",
        [format_delegated_grant(item) for item in review["delegatedPermissionGrants"]],
    )
    print_section(
        "App Role Assignments",
        [format_app_role_assignment(item) for item in review["appRoleAssignments"]],
    )
    return 0


def cmd_outbound_review(args: argparse.Namespace, settings: Settings) -> int:
    identifier = resolve_identifier(args.identifier)
    sender = resolve_sender(args.sender, identifier=identifier)
    auth_mode = resolve_auth_mode(args.auth, settings, prefer_app=True)
    account = None if auth_mode == "app" else resolve_account(args.account, settings)

    provider = TokenProvider(settings)
    graph = GraphClient(settings)
    exchange = ExchangeAdminClient(settings)

    graph_token = acquire_graph_token(
        provider,
        settings,
        mode=auth_mode,
        scopes=requested_scopes(include_mail=True, include_directory=True, include_trace=True),
        force_device_code=args.force_device_code,
        account=account,
    )

    warnings: list[str] = []
    payload: dict[str, Any] = {}
    trace_error: str | None = None

    try:
        payload["trace"] = fetch_message_traces(
            graph,
            graph_token,
            sender=sender,
            hours=args.hours,
            days=args.days,
            limit=args.trace_limit,
        )
    except GraphApiError as exc:
        wrapped = describe_message_trace_error(exc, configured_client_id=settings.client_id)
        warnings.append(f"trace: {wrapped}. Continuing with mailbox, rules, app, and forwarding checks.")
        payload["trace"] = []
        trace_error = str(wrapped)

    try:
        payload["sentItems"] = fetch_folder_messages(
            graph,
            graph_token,
            mailbox=identifier,
            folder_name="sentitems",
            date_field="sentDateTime",
            hours=args.hours,
            days=args.days,
            limit=args.limit,
        )
    except GraphApiError as exc:
        warnings.append(
            f"sentItems: {exc}. If this is another user's mailbox, configure M365_CLIENT_SECRET and application Mail.Read."
        )
        payload["sentItems"] = []

    try:
        payload["deletedItems"] = fetch_folder_messages(
            graph,
            graph_token,
            mailbox=identifier,
            folder_name="deleteditems",
            date_field="lastModifiedDateTime",
            hours=args.hours,
            days=args.days,
            limit=args.limit,
        )
    except GraphApiError as exc:
        warnings.append(
            f"deletedItems: {exc}. If this is another user's mailbox, configure M365_CLIENT_SECRET and application Mail.Read."
        )
        payload["deletedItems"] = []

    try:
        payload["rules"] = fetch_inbox_rules(graph, graph_token, identifier)
    except GraphApiError as exc:
        warnings.append(
            f"rules: {exc}. Cross-user mailbox rules usually need application MailboxSettings.Read or mailbox delegation."
        )
        payload["rules"] = []

    try:
        payload["apps"] = fetch_user_app_review(graph, graph_token, identifier=identifier, limit=args.limit)
    except GraphApiError as exc:
        warnings.append(f"apps: {exc}")
        payload["apps"] = {"user": {}, "delegatedPermissionGrants": [], "appRoleAssignments": []}

    try:
        exchange_token = acquire_exchange_token(
            provider,
            settings,
            mode=auth_mode,
            force_device_code=args.force_device_code,
            account=account,
        )
        payload["mailboxSnapshot"] = fetch_mailbox_snapshot(exchange, exchange_token, identifier=identifier)
    except (AuthError, ExchangeAdminApiError) as exc:
        warnings.append(
            f"mailboxSnapshot: {exc}. Exchange mailbox forwarding/send-on-behalf checks require Exchange.ManageV2 or Exchange.ManageAsAppV2."
        )
        payload["mailboxSnapshot"] = {}

    payload["summary"] = {
        "identifier": identifier,
        "sender": sender,
        "traceCount": len(payload["trace"]),
        "traceError": trace_error,
        "traceStatuses": summarize_trace_statuses(payload["trace"]),
        "sentItemCount": len(payload["sentItems"]),
        "deletedItemCount": len(payload["deletedItems"]),
        "senderMismatchCount": len(find_sender_mismatches(payload["sentItems"])),
        "inboxRuleCount": len(payload["rules"]),
        "forwardingRuleCount": sum(1 for item in payload["rules"] if rule_has_forwarding(item)),
        "delegatedAppConsentCount": len(payload["apps"]["delegatedPermissionGrants"]),
        "appRoleAssignmentCount": len(payload["apps"]["appRoleAssignments"]),
        "mailboxSnapshot": summarize_mailbox_snapshot(payload["mailboxSnapshot"]),
        "warnings": warnings,
    }

    if args.json:
        json_dump(payload)
        return 0

    mailbox_summary = payload["summary"]["mailboxSnapshot"]
    print(f"Outbound review for {identifier}")
    print(f"Sender traced: {sender}")
    if trace_error:
        print("Trace rows: unavailable")
        print("Trace statuses: unavailable")
    else:
        print(f"Trace rows: {payload['summary']['traceCount']}")
        print(
            "Trace statuses: "
            + ", ".join(f"{key}={value}" for key, value in sorted(payload["summary"]["traceStatuses"].items()))
        )
    print(f"Sent Items: {payload['summary']['sentItemCount']}")
    print(f"Deleted Items: {payload['summary']['deletedItemCount']}")
    print(f"From/Sender mismatches in Sent Items: {payload['summary']['senderMismatchCount']}")
    print(f"Inbox rules: {payload['summary']['inboxRuleCount']}")
    print(f"Forwarding/redirect rules: {payload['summary']['forwardingRuleCount']}")
    print(f"Delegated app consents: {payload['summary']['delegatedAppConsentCount']}")
    print(f"App role assignments: {payload['summary']['appRoleAssignmentCount']}")
    if mailbox_summary:
        print(f"Mailbox forwarding SMTP: {mailbox_summary.get('forwardingSmtpAddress') or '-'}")
        print(f"Mailbox forwarding address: {mailbox_summary.get('forwardingAddress') or '-'}")
        print(f"Deliver and forward: {mailbox_summary.get('deliverToMailboxAndForward')}")
        print(
            "Send on behalf: "
            + (", ".join(mailbox_summary.get("grantSendOnBehalfTo") or []) or "(none)")
        )
        print("Send As assignments: not yet surfaced by this backend; use Exchange PowerShell if you need definitive assignments.")

    if warnings:
        print_section("Warnings", warnings)

    print_section("Trace Rows", [format_trace(item) for item in payload["trace"][: args.trace_limit]])
    print_section("Sent Items", [format_message(item, folder_name="sentitems") for item in payload["sentItems"]])
    print_section(
        "Deleted Items",
        [format_message(item, folder_name="deleteditems") for item in payload["deletedItems"]],
    )
    print_section("Inbox Rules", [format_rule(item) for item in payload["rules"]])
    print_section(
        "Delegated App Consents",
        [format_delegated_grant(item) for item in payload["apps"]["delegatedPermissionGrants"]],
    )
    print_section(
        "App Role Assignments",
        [format_app_role_assignment(item) for item in payload["apps"]["appRoleAssignments"]],
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        settings = Settings.load()
        command_map = {
            "login": cmd_login,
            "login-start": cmd_login_start,
            "login-finish": cmd_login_finish,
            "investigate": cmd_investigate,
            "doctor": cmd_doctor,
            "diagnose": cmd_diagnose,
            "signins": cmd_signins,
            "audits": cmd_audits,
            "rules": cmd_rules,
            "risk": cmd_risk,
            "trace": cmd_trace,
            "messages": cmd_messages,
            "apps": cmd_apps,
            "outbound-review": cmd_outbound_review,
            "timeline": cmd_timeline,
            "contain": cmd_contain,
        }
        return command_map[args.command](args, settings)
    except (ConfigurationError, AuthError, GraphApiError, ExchangeAdminApiError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130
