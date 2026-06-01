from __future__ import annotations

from datetime import datetime
from typing import Any

from .graph import GraphApiError, GraphClient
from .investigation import collect_aliases, fetch_directory_audits_window, fetch_signins_window
from .outbound import address_text, fetch_folder_messages, fetch_message_traces, recipient_addresses


def parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def build_timeline_events(
    *,
    graph: GraphClient,
    token: str,
    identifier: str,
    sender: str,
    start: datetime,
    end: datetime,
    limit: int,
    trace_limit: int,
) -> tuple[list[dict[str, Any]], list[str]]:
    warnings: list[str] = []
    events: list[dict[str, Any]] = []

    try:
        signins = fetch_signins_window(graph, token, identifier, start, end, limit)
    except GraphApiError as exc:
        warnings.append(f"signins: {exc}")
        signins = []

    aliases = collect_aliases(identifier, signins)
    try:
        audits = fetch_directory_audits_window(graph, token, aliases, start, end, limit)
    except GraphApiError as exc:
        warnings.append(f"audits: {exc}")
        audits = []

    try:
        traces = fetch_message_traces(graph, token, sender=sender, start=start, end=end, limit=trace_limit)
    except GraphApiError as exc:
        warnings.append(f"trace: {exc}")
        traces = []

    try:
        sent_items = fetch_folder_messages(
            graph,
            token,
            mailbox=identifier,
            folder_name="sentitems",
            date_field="sentDateTime",
            start=start,
            end=end,
            limit=limit,
        )
    except GraphApiError as exc:
        warnings.append(f"sentItems: {exc}")
        sent_items = []

    try:
        deleted_items = fetch_folder_messages(
            graph,
            token,
            mailbox=identifier,
            folder_name="deleteditems",
            date_field="lastModifiedDateTime",
            start=start,
            end=end,
            limit=limit,
        )
    except GraphApiError as exc:
        warnings.append(f"deletedItems: {exc}")
        deleted_items = []

    for signin in signins:
        status = signin.get("status") or {}
        error_code = status.get("errorCode") or 0
        created = signin.get("createdDateTime")
        events.append(
            {
                "timestamp": created,
                "source": "SIGNIN",
                "event_type": "login_failure" if error_code else "login_success",
                "summary": " | ".join(
                    [
                        identifier,
                        signin.get("clientAppUsed") or "-",
                        signin.get("ipAddress") or "-",
                        signin.get("conditionalAccessStatus") or "unknown",
                    ]
                ),
                "ip": signin.get("ipAddress"),
                "status": "failure" if error_code else "success",
            }
        )

    for trace in traces:
        timestamp = trace.get("receivedDateTime") or trace.get("createdDateTime")
        events.append(
            {
                "timestamp": timestamp,
                "source": "TRACE",
                "event_type": "message_trace",
                "summary": " | ".join(
                    [
                        trace.get("subject") or "-",
                        f"{trace.get('senderAddress') or '-'} -> {trace.get('recipientAddress') or '-'}",
                        trace.get("status") or "unknown",
                    ]
                ),
                "ip": trace.get("sourceIPAddress") or trace.get("originalClientIPAddress"),
                "status": trace.get("status"),
            }
        )

    for audit in audits:
        events.append(
            {
                "timestamp": audit.get("activityDateTime"),
                "source": "AUDIT",
                "event_type": str(audit.get("activityDisplayName") or "audit"),
                "summary": " | ".join(
                    [
                        audit.get("activityDisplayName") or "-",
                        audit.get("result") or "-",
                    ]
                ),
                "ip": ((audit.get("initiatedBy") or {}).get("user") or {}).get("ipAddress"),
                "status": audit.get("result"),
            }
        )

    for message in sent_items:
        events.append(
            {
                "timestamp": message.get("sentDateTime"),
                "source": "SENT",
                "event_type": "mail_sent",
                "summary": " | ".join(
                    [
                        message.get("subject") or "-",
                        ", ".join(recipient_addresses(message.get("toRecipients"))) or "-",
                        address_text(message.get("sender")),
                    ]
                ),
                "ip": None,
                "status": "sent",
            }
        )

    for message in deleted_items:
        events.append(
            {
                "timestamp": message.get("lastModifiedDateTime") or message.get("receivedDateTime"),
                "source": "DELETED",
                "event_type": "mail_deleted",
                "summary": " | ".join(
                    [
                        message.get("subject") or "-",
                        ", ".join(recipient_addresses(message.get("toRecipients"))) or "-",
                        address_text(message.get("sender")),
                    ]
                ),
                "ip": None,
                "status": "deleted",
            }
        )

    events = [item for item in events if item.get("timestamp")]
    events.sort(key=lambda item: parse_timestamp(str(item["timestamp"])) or datetime.min)
    return events, warnings
