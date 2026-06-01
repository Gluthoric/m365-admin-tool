from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import quote

from .exchange_admin import ExchangeAdminClient
from .graph import GraphApiError, GraphClient
from .investigation import escape_odata_string

GRAPH_BETA_BASE_URL = "https://graph.microsoft.com/beta"
MISSING_SP_APP_ID_PATTERN = re.compile(
    r"service principal for App ID (?P<app_id>[0-9a-fA-F-]{36}) was not found",
    re.IGNORECASE,
)
MESSAGE_SELECT = ",".join(
    (
        "id",
        "subject",
        "sentDateTime",
        "receivedDateTime",
        "lastModifiedDateTime",
        "internetMessageId",
        "from",
        "sender",
        "toRecipients",
        "ccRecipients",
        "bccRecipients",
        "replyTo",
        "hasAttachments",
        "importance",
    )
)


def window_bounds(*, hours: int = 48, days: int | None = None, now: datetime | None = None) -> tuple[datetime, datetime]:
    end = now or datetime.now(UTC)
    total_hours = days * 24 if days is not None else hours
    start = end - timedelta(hours=total_hours)
    return start, end


def odata_datetime(value: datetime) -> str:
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def build_range_filter(field_name: str, start: datetime, end: datetime) -> str:
    return f"{field_name} ge {odata_datetime(start)} and {field_name} le {odata_datetime(end)}"


def address_text(value: dict[str, Any] | None) -> str:
    return ((value or {}).get("emailAddress") or {}).get("address") or "-"


def recipient_addresses(values: list[dict[str, Any]] | None) -> list[str]:
    recipients = []
    for entry in values or []:
        address = address_text(entry)
        if address != "-":
            recipients.append(address)
    return recipients


def fetch_message_traces(
    graph: GraphClient,
    token: str,
    *,
    sender: str,
    start: datetime | None = None,
    end: datetime | None = None,
    recipient: str | None = None,
    hours: int = 48,
    days: int | None = None,
    status: str | None = None,
    limit: int = 200,
) -> list[dict[str, Any]]:
    if start is None or end is None:
        start, end = window_bounds(hours=hours, days=days)
    filters = [
        build_range_filter("receivedDateTime", start, end),
        f"senderAddress eq '{escape_odata_string(sender)}'",
    ]
    if recipient:
        filters.append(f"recipientAddress eq '{escape_odata_string(recipient)}'")
    if status and status.lower() != "all":
        filters.append(f"status eq '{escape_odata_string(status)}'")

    params = {
        "$filter": " and ".join(filters),
        "$top": str(min(limit, 500)),
    }
    return graph.get_collection(
        token,
        f"{GRAPH_BETA_BASE_URL}/admin/exchange/tracing/messageTraces",
        params=params,
        limit=limit,
    )


def extract_missing_service_principal_app_id(message: str) -> str | None:
    match = MISSING_SP_APP_ID_PATTERN.search(message)
    if not match:
        return None
    return match.group("app_id").lower()


def describe_message_trace_error(exc: GraphApiError, *, configured_client_id: str | None) -> GraphApiError:
    missing_app_id = extract_missing_service_principal_app_id(exc.message)
    configured = (configured_client_id or "").strip().lower() or None
    if exc.status_code != 401 or not missing_app_id:
        return exc

    if configured and missing_app_id != configured:
        detail = (
            f"{exc.message} Configured client ID is {configured_client_id}, so the missing service principal "
            f"({missing_app_id}) is not this tool's app registration. The message trace API is failing against a "
            "different downstream app/service principal in the tenant."
        )
    elif configured:
        detail = (
            f"{exc.message} Configured client ID is {configured_client_id}, and this failure matches that app "
            "registration."
        )
    else:
        detail = (
            f"{exc.message} The configured client ID is unavailable, so the tool cannot determine whether the missing "
            "service principal matches this app registration."
        )

    return GraphApiError(exc.status_code, detail, code=exc.code)


def fetch_folder_messages(
    graph: GraphClient,
    token: str,
    *,
    mailbox: str,
    folder_name: str,
    date_field: str,
    start: datetime | None = None,
    end: datetime | None = None,
    hours: int = 48,
    days: int | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    if start is None or end is None:
        start, end = window_bounds(hours=hours, days=days)
    encoded_mailbox = quote(mailbox, safe="")
    encoded_folder = quote(folder_name, safe="")
    path = f"users/{encoded_mailbox}/mailFolders/{encoded_folder}/messages"
    params = {
        "$select": MESSAGE_SELECT,
        "$filter": build_range_filter(date_field, start, end),
        "$orderby": f"{date_field} desc",
        "$top": str(min(limit, 200)),
    }

    try:
        return graph.get_collection(token, path, params=params, limit=limit)
    except GraphApiError as exc:
        if exc.status_code != 400:
            raise
        fallback_params = dict(params)
        fallback_params.pop("$orderby", None)
        return graph.get_collection(token, path, params=fallback_params, limit=limit)


def fetch_user_profile(graph: GraphClient, token: str, identifier: str) -> dict[str, Any]:
    encoded = quote(identifier, safe="")
    return graph.get_object(
        token,
        f"users/{encoded}",
        params={"$select": "id,displayName,userPrincipalName,mail"},
    )


def fetch_service_principal(graph: GraphClient, token: str, object_id: str) -> dict[str, Any]:
    encoded = quote(object_id, safe="")
    return graph.get_object(
        token,
        f"servicePrincipals/{encoded}",
        params={"$select": "id,appId,displayName"},
    )


def fetch_user_app_review(
    graph: GraphClient,
    token: str,
    *,
    identifier: str,
    limit: int = 100,
) -> dict[str, Any]:
    user = fetch_user_profile(graph, token, identifier)
    user_id = user.get("id")
    if not user_id:
        return {"user": user, "delegatedPermissionGrants": [], "appRoleAssignments": []}

    encoded_user_id = quote(str(user_id), safe="")
    app_role_assignments = graph.get_collection(
        token,
        f"users/{encoded_user_id}/appRoleAssignments",
        params={"$top": str(min(limit, 200))},
        limit=limit,
    )
    oauth_grants = graph.get_collection(
        token,
        "oauth2PermissionGrants",
        params={
            "$filter": f"principalId eq '{escape_odata_string(str(user_id))}' and consentType eq 'Principal'",
            "$top": str(min(limit, 200)),
        },
        limit=limit,
    )

    service_principals: dict[str, dict[str, Any]] = {}

    def resolve_sp(object_id: str | None) -> dict[str, Any]:
        if not object_id:
            return {}
        if object_id not in service_principals:
            try:
                service_principals[object_id] = fetch_service_principal(graph, token, object_id)
            except GraphApiError:
                service_principals[object_id] = {"id": object_id}
        return service_principals[object_id]

    delegated = []
    for grant in oauth_grants:
        client = resolve_sp(grant.get("clientId"))
        resource = resolve_sp(grant.get("resourceId"))
        delegated.append(
            {
                "clientDisplayName": client.get("displayName") or grant.get("clientId"),
                "clientAppId": client.get("appId"),
                "resourceDisplayName": resource.get("displayName") or grant.get("resourceId"),
                "resourceAppId": resource.get("appId"),
                "scope": grant.get("scope"),
                "consentType": grant.get("consentType"),
            }
        )

    app_roles = []
    for assignment in app_role_assignments:
        resource = resolve_sp(assignment.get("resourceId"))
        app_roles.append(
            {
                "resourceDisplayName": assignment.get("resourceDisplayName") or resource.get("displayName"),
                "resourceAppId": resource.get("appId"),
                "appRoleId": assignment.get("appRoleId"),
                "principalDisplayName": assignment.get("principalDisplayName"),
            }
        )

    return {
        "user": user,
        "delegatedPermissionGrants": delegated,
        "appRoleAssignments": app_roles,
    }


def normalize_mailbox_values(value: Any) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        values = [value]
    else:
        values = value

    normalized: list[str] = []
    for item in values:
        if isinstance(item, dict):
            rendered = (
                item.get("PrimarySmtpAddress")
                or item.get("DisplayName")
                or item.get("Name")
                or item.get("Identity")
            )
            if rendered:
                normalized.append(str(rendered))
        else:
            normalized.append(str(item))
    return normalized


def fetch_mailbox_snapshot(
    exchange: ExchangeAdminClient,
    token: str,
    *,
    identifier: str,
) -> dict[str, Any]:
    results = exchange.run_cmdlet(
        token,
        "Mailbox",
        anchor_mailbox=identifier,
        cmdlet_name="Get-Mailbox",
        parameters={"Identity": identifier},
    )
    return results[0] if results else {}


def _normalize_permission_trustee(value: Any) -> str:
    if isinstance(value, dict):
        for key in ("User", "Trustee", "Identity", "DisplayName", "Name", "PrimarySmtpAddress"):
            rendered = value.get(key)
            if rendered:
                return str(rendered)
        return ""
    return str(value or "")


def fetch_mailbox_permissions(
    exchange: ExchangeAdminClient,
    token: str,
    *,
    identifier: str,
) -> list[dict[str, Any]]:
    results = exchange.run_cmdlet(
        token,
        "Mailbox",
        anchor_mailbox=identifier,
        cmdlet_name="Get-MailboxPermission",
        parameters={"Identity": identifier},
    )
    filtered: list[dict[str, Any]] = []
    for item in results:
        access_rights = [str(right) for right in item.get("AccessRights") or []]
        trustee = _normalize_permission_trustee(item.get("User"))
        if "FullAccess" not in access_rights:
            continue
        if trustee.upper() in {"NT AUTHORITY\\SELF", "SELF"}:
            continue
        filtered.append(item)
    return filtered


def fetch_recipient_permissions(
    exchange: ExchangeAdminClient,
    token: str,
    *,
    identifier: str,
) -> list[dict[str, Any]]:
    results = exchange.run_cmdlet(
        token,
        "Mailbox",
        anchor_mailbox=identifier,
        cmdlet_name="Get-RecipientPermission",
        parameters={"Identity": identifier},
    )
    filtered: list[dict[str, Any]] = []
    for item in results:
        access_rights = [str(right) for right in item.get("AccessRights") or []]
        trustee = _normalize_permission_trustee(item.get("Trustee"))
        if "SendAs" not in access_rights:
            continue
        if trustee.upper() == "SELF":
            continue
        filtered.append(item)
    return filtered


def summarize_mailbox_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    return {
        "identity": snapshot.get("UPN") or snapshot.get("UserPrincipalName") or snapshot.get("Identity"),
        "forwardingAddress": snapshot.get("ForwardingAddress"),
        "forwardingSmtpAddress": snapshot.get("ForwardingSmtpAddress"),
        "deliverToMailboxAndForward": bool(snapshot.get("DeliverToMailboxAndForward")),
        "grantSendOnBehalfTo": normalize_mailbox_values(
            snapshot.get("GrantSendOnBehalfToWithDisplayNames") or snapshot.get("GrantSendOnBehalfTo")
        ),
    }


def summarize_delegation(
    snapshot: dict[str, Any],
    mailbox_permissions: list[dict[str, Any]],
    recipient_permissions: list[dict[str, Any]],
) -> dict[str, Any]:
    send_on_behalf = normalize_mailbox_values(
        snapshot.get("GrantSendOnBehalfToWithDisplayNames") or snapshot.get("GrantSendOnBehalfTo")
    )
    full_access = sorted(
        {
            _normalize_permission_trustee(item.get("User"))
            for item in mailbox_permissions
            if _normalize_permission_trustee(item.get("User"))
        }
    )
    send_as = sorted(
        {
            _normalize_permission_trustee(item.get("Trustee"))
            for item in recipient_permissions
            if _normalize_permission_trustee(item.get("Trustee"))
        }
    )
    return {
        "sendOnBehalf": send_on_behalf,
        "fullAccess": full_access,
        "sendAs": send_as,
        "hasDelegation": bool(send_on_behalf or full_access or send_as),
    }


def find_sender_mismatches(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    mismatches = []
    for message in messages:
        from_address = address_text(message.get("from"))
        sender_address = address_text(message.get("sender"))
        if from_address != "-" and sender_address != "-" and from_address.lower() != sender_address.lower():
            mismatches.append(message)
    return mismatches
