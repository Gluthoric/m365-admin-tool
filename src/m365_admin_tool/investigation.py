from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import cast
from typing import Any, Iterable
from urllib.parse import quote

from .graph import GraphApiError, GraphClient


def normalize_identifier(value: str | None) -> str:
    return (value or "").strip().lower()


def escape_odata_string(value: str) -> str:
    return value.replace("'", "''")


def format_odata_datetime(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def ensure_utc_datetime(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def build_time_window_filter(field_name: str, start: datetime, end: datetime) -> str:
    start_utc = ensure_utc_datetime(start)
    end_utc = ensure_utc_datetime(end)
    return f"{field_name} ge {format_odata_datetime(start_utc)} and {field_name} le {format_odata_datetime(end_utc)}"


def build_time_filter(field_name: str, days: int, now: datetime | None = None) -> str:
    end = now or datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    return build_time_window_filter(field_name, start, end)


def payload_contains_identifier(payload: Any, identifiers: Iterable[str]) -> bool:
    needles = [normalize_identifier(value) for value in identifiers if normalize_identifier(value)]
    if not needles:
        return False

    if isinstance(payload, dict):
        return any(payload_contains_identifier(value, needles) for value in payload.values())
    if isinstance(payload, list):
        return any(payload_contains_identifier(value, needles) for value in payload)
    if isinstance(payload, str):
        haystack = payload.lower()
        return any(needle in haystack for needle in needles)
    return False


def collect_aliases(identifier: str, signins: list[dict[str, Any]]) -> list[str]:
    aliases = {normalize_identifier(identifier)}
    for signin in signins:
        for key in ("userId", "userPrincipalName"):
            value = normalize_identifier(signin.get(key))
            if value:
                aliases.add(value)
    return sorted(aliases)


def fetch_signins(
    graph: GraphClient,
    token: str,
    identifier: str,
    days: int,
    limit: int,
) -> list[dict[str, Any]]:
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    return fetch_signins_window(graph, token, identifier, start, end, limit)


def fetch_signins_window(
    graph: GraphClient,
    token: str,
    identifier: str,
    start: datetime,
    end: datetime,
    limit: int,
) -> list[dict[str, Any]]:
    time_filter = build_time_window_filter("createdDateTime", start, end)
    scoped_filter = f"{time_filter} and userPrincipalName eq '{escape_odata_string(identifier)}'"
    params = {
        "$filter": scoped_filter,
        "$top": str(min(limit, 1000)),
    }

    try:
        return graph.get_collection(token, "auditLogs/signIns", params=params, limit=limit)
    except GraphApiError as exc:
        if exc.status_code != 400:
            raise

    scan_limit = min(max(limit * 4, 100), 1000)
    fallback = graph.get_collection(
        token,
        "auditLogs/signIns",
        params={"$filter": time_filter, "$top": str(scan_limit)},
        limit=scan_limit,
    )
    target = normalize_identifier(identifier)
    return [item for item in fallback if normalize_identifier(item.get("userPrincipalName")) == target][:limit]


def fetch_directory_audits(
    graph: GraphClient,
    token: str,
    identifiers: Iterable[str],
    days: int,
    limit: int,
) -> list[dict[str, Any]]:
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    return fetch_directory_audits_window(graph, token, identifiers, start, end, limit)


def fetch_directory_audits_window(
    graph: GraphClient,
    token: str,
    identifiers: Iterable[str],
    start: datetime,
    end: datetime,
    limit: int,
) -> list[dict[str, Any]]:
    scan_limit = min(max(limit * 6, 100), 1000)
    params = {
        "$filter": build_time_window_filter("activityDateTime", start, end),
        "$orderby": "activityDateTime desc",
        "$top": str(scan_limit),
    }
    events = graph.get_collection(token, "auditLogs/directoryAudits", params=params, limit=scan_limit)
    return [event for event in events if payload_contains_identifier(event, identifiers)][:limit]


def fetch_inbox_rules(graph: GraphClient, token: str, identifier: str) -> list[dict[str, Any]]:
    encoded = quote(identifier, safe="")
    path = f"users/{encoded}/mailFolders/inbox/messageRules"
    return graph.get_collection(token, path)


def fetch_risk_detections(
    graph: GraphClient,
    token: str,
    identifier: str,
    days: int,
    limit: int,
) -> list[dict[str, Any]]:
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    return fetch_risk_detections_window(graph, token, identifier, start, end, limit)


def fetch_risk_detections_window(
    graph: GraphClient,
    token: str,
    identifier: str,
    start: datetime,
    end: datetime,
    limit: int,
) -> list[dict[str, Any]]:
    time_filter = build_time_window_filter("activityDateTime", start, end)
    scoped_filter = f"{time_filter} and userPrincipalName eq '{escape_odata_string(identifier)}'"
    params = {
        "$filter": scoped_filter,
        "$top": str(min(limit, 500)),
    }

    try:
        return graph.get_collection(token, "identityProtection/riskDetections", params=params, limit=limit)
    except GraphApiError as exc:
        if exc.status_code != 400:
            raise

    scan_limit = min(max(limit * 4, 50), 500)
    fallback = graph.get_collection(
        token,
        "identityProtection/riskDetections",
        params={"$filter": time_filter, "$top": str(scan_limit)},
        limit=scan_limit,
    )
    target = normalize_identifier(identifier)
    return [item for item in fallback if normalize_identifier(item.get("userPrincipalName")) == target][:limit]


def audit_event_touches_authentication(event: dict[str, Any]) -> bool:
    activity = str(event.get("activityDisplayName") or "").lower()
    result_reason = str(event.get("resultReason") or "").lower()

    if any(
        keyword in activity
        for keyword in ("password", "authentication method", "auth method", "credential", "security info", "mfa")
    ):
        return True
    if any(keyword in result_reason for keyword in ("authentication method", "security info", "mfa", "password")):
        return True

    for detail in event.get("additionalDetails") or []:
        key = str((detail or {}).get("key") or "").lower()
        value = str((detail or {}).get("value") or "").lower()
        if any(keyword in key or keyword in value for keyword in ("authentication", "security info", "mfa", "password")):
            return True

    property_keywords = (
        "strongauthentication",
        "authenticationmethod",
        "securityinfo",
        "phone.",
        "microsoftauthenticator",
        "temporaryaccesspass",
        "fido",
        "windowshello",
        "softwareoath",
    )
    for target in event.get("targetResources") or []:
        for prop in (target or {}).get("modifiedProperties") or []:
            display_name = str((prop or {}).get("displayName") or "").replace(" ", "").lower()
            if any(keyword in display_name for keyword in property_keywords):
                return True

    return False


def categorize_directory_audits(events: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    categories: dict[str, list[dict[str, Any]]] = {
        "passwordOrAuthChanges": [],
        "roleChanges": [],
        "groupChanges": [],
        "mailboxPermissionChanges": [],
        "appConsentChanges": [],
        "other": [],
    }

    for event in events:
        activity = str(event.get("activityDisplayName") or "").lower()
        target = categories["other"]
        if audit_event_touches_authentication(event):
            target = categories["passwordOrAuthChanges"]
        elif "role" in activity:
            target = categories["roleChanges"]
        elif "group" in activity:
            target = categories["groupChanges"]
        elif any(keyword in activity for keyword in ("consent", "app role", "service principal", "application")):
            target = categories["appConsentChanges"]
        elif any(keyword in activity for keyword in ("mailbox", "delegate", "permission", "forward", "inbox rule")):
            target = categories["mailboxPermissionChanges"]
        cast(list[dict[str, Any]], target).append(event)

    return categories


def rule_has_forwarding(rule: dict[str, Any]) -> bool:
    actions = rule.get("actions") or {}
    return any(actions.get(key) for key in ("forwardTo", "redirectTo", "forwardAsAttachmentTo"))


def summarize_rule(rule: dict[str, Any]) -> dict[str, Any]:
    conditions = rule.get("conditions") or {}
    actions = rule.get("actions") or {}

    condition_parts: list[str] = []
    for key, value in sorted(conditions.items()):
        if not value:
            continue
        if isinstance(value, list):
            rendered = ", ".join(str(item) for item in value)
        else:
            rendered = str(value)
        condition_parts.append(f"{key}={rendered}")

    action_parts: list[str] = []
    for key in ("forwardTo", "redirectTo", "forwardAsAttachmentTo"):
        entries = actions.get(key) or []
        targets = []
        for entry in entries:
            address = ((entry or {}).get("emailAddress") or {}).get("address")
            if address:
                targets.append(address)
        if targets:
            action_parts.append(f"{key}={', '.join(targets)}")
    if actions.get("delete"):
        action_parts.append("delete")
    if actions.get("moveToFolder"):
        action_parts.append(f"moveToFolder={actions['moveToFolder']}")
    if actions.get("markAsRead"):
        action_parts.append("markAsRead")
    if actions.get("stopProcessingRules"):
        action_parts.append("stopProcessingRules")

    return {
        "id": rule.get("id"),
        "displayName": rule.get("displayName") or "(unnamed)",
        "sequence": rule.get("sequence"),
        "isEnabled": bool(rule.get("isEnabled")),
        "hasError": bool(rule.get("hasError")),
        "isReadOnly": bool(rule.get("isReadOnly")),
        "forwarding": rule_has_forwarding(rule),
        "conditions": "; ".join(condition_parts) or "any",
        "actions": "; ".join(action_parts) or "none",
    }
