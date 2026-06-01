from __future__ import annotations

from dataclasses import asdict, dataclass
import shutil
import subprocess

from .auth import EXCHANGE_RESOURCE, GRAPH_RESOURCE, TokenProvider, default_login_scopes, exchange_delegated_scopes, requested_scopes
from .config import Settings
from .exchange_admin import ExchangeAdminApiError, ExchangeAdminClient
from .graph import GraphApiError, GraphClient
from .outbound import (
    describe_message_trace_error,
    extract_missing_service_principal_app_id,
    fetch_folder_messages,
    fetch_mailbox_snapshot,
    fetch_message_traces,
)


TRACE_SERVICE_PRINCIPAL_APP_ID = "8bd644d1-64a1-4d4b-ae52-2e0cbf64e373"


@dataclass(frozen=True)
class DoctorCheckResult:
    check: str
    status: str
    impact: str
    fix_hint: str
    details: str = ""

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def result(check: str, status: str, impact: str, fix_hint: str, details: str = "") -> DoctorCheckResult:
    return DoctorCheckResult(check=check, status=status, impact=impact, fix_hint=fix_hint, details=details)


def summarize_checks(checks: list[DoctorCheckResult]) -> dict[str, int]:
    summary = {"pass": 0, "fail": 0, "skip": 0, "warn": 0}
    for item in checks:
        summary[item.status] = summary.get(item.status, 0) + 1
    return summary


def ensure_trace_service_principal() -> dict[str, str]:
    if shutil.which("az") is None:
        return {
            "fix": "trace_service_principal",
            "status": "fail",
            "details": "Azure CLI is not installed.",
        }

    show = subprocess.run(
        ["az", "ad", "sp", "show", "--id", TRACE_SERVICE_PRINCIPAL_APP_ID],
        capture_output=True,
        text=True,
        check=False,
    )
    if show.returncode == 0:
        return {
            "fix": "trace_service_principal",
            "status": "noop",
            "details": "Trace service principal already exists.",
        }

    create = subprocess.run(
        ["az", "ad", "sp", "create", "--id", TRACE_SERVICE_PRINCIPAL_APP_ID],
        capture_output=True,
        text=True,
        check=False,
    )
    if create.returncode == 0:
        return {
            "fix": "trace_service_principal",
            "status": "success",
            "details": "Created trace service principal with Azure CLI.",
        }
    return {
        "fix": "trace_service_principal",
        "status": "fail",
        "details": (create.stderr or create.stdout or "Unknown Azure CLI failure").strip(),
    }


def _probe_graph_read(
    graph: GraphClient,
    token: str | None,
    *,
    check: str,
    impact: str,
    fix_hint: str,
    path: str,
    params: dict[str, str] | None = None,
) -> DoctorCheckResult:
    if not token:
        return result(check, "fail", impact, fix_hint, "No cached delegated token for the required scopes.")
    try:
        graph.get_object(token, path, params=params)
        return result(check, "pass", impact, fix_hint)
    except GraphApiError as exc:
        lowered = exc.message.lower()
        effective_fix_hint = fix_hint
        if "premium license" in lowered or "licensed for this feature" in lowered:
            effective_fix_hint = "The tenant is missing the required Entra premium licensing for this dataset."
        return result(check, "fail", impact, effective_fix_hint, str(exc))


def _probe_trace_service_principal(graph: GraphClient, token: str | None) -> DoctorCheckResult:
    impact = "Message trace can fail with misleading service-principal errors."
    fix_hint = f"Create or verify service principal {TRACE_SERVICE_PRINCIPAL_APP_ID}."
    if not token:
        return result("Trace service principal", "fail", impact, fix_hint, "No cached directory-read token.")
    try:
        payload = graph.get_object(
            token,
            "servicePrincipals",
            params={
                "$filter": f"appId eq '{TRACE_SERVICE_PRINCIPAL_APP_ID}'",
                "$select": "id,appId,displayName",
                "$top": "1",
            },
        )
    except GraphApiError as exc:
        return result("Trace service principal", "fail", impact, fix_hint, str(exc))

    matches = payload.get("value", [])
    if matches:
        display_name = matches[0].get("displayName") or TRACE_SERVICE_PRINCIPAL_APP_ID
        return result("Trace service principal", "pass", impact, fix_hint, f"Found {display_name}.")
    return result("Trace service principal", "fail", impact, fix_hint, "Service principal was not found in the tenant.")


def _probe_cross_user_mail(
    graph: GraphClient,
    *,
    app_token: str | None,
    delegated_token: str | None,
    target: str | None,
) -> DoctorCheckResult:
    impact = "Sent Items and Deleted Items review will fail for another user's mailbox."
    fix_hint = "Use app auth with M365_CLIENT_SECRET and application Mail.Read, or mailbox delegation."
    if not target:
        return result("Cross-user mail read", "skip", impact, fix_hint, "Re-run with --target to test mailbox access.")

    token = app_token or delegated_token
    auth_mode = "app" if app_token else "delegated"
    if not token:
        return result("Cross-user mail read", "fail", impact, fix_hint, "No token available for the mailbox read check.")

    try:
        fetch_folder_messages(
            graph,
            token,
            mailbox=target,
            folder_name="sentitems",
            date_field="sentDateTime",
            hours=1,
            limit=1,
        )
        return result("Cross-user mail read", "pass", impact, fix_hint, f"Mailbox read succeeded with {auth_mode} auth.")
    except GraphApiError as exc:
        return result("Cross-user mail read", "fail", impact, fix_hint, f"{auth_mode}: {exc}")


def _probe_trace_api(
    graph: GraphClient,
    token: str | None,
    *,
    settings: Settings,
    target: str | None,
) -> DoctorCheckResult:
    impact = "Outbound trace and outbound-review trace section will fail."
    fix_hint = (
        "Verify trace permissions and tenant-side propagation. If the trace service principal already exists, "
        "treat repeated 'not found' errors as backend caching/auth propagation."
    )
    if not target:
        return result("Trace API", "skip", impact, fix_hint, "Re-run with --target to test message trace.")
    if not token:
        return result("Trace API", "fail", impact, fix_hint, "No cached delegated token for trace scopes.")
    try:
        fetch_message_traces(graph, token, sender=target, hours=1, limit=1)
        return result("Trace API", "pass", impact, fix_hint)
    except GraphApiError as exc:
        wrapped = describe_message_trace_error(exc, configured_client_id=settings.client_id)
        app_id = extract_missing_service_principal_app_id(wrapped.message)
        extra = f" Missing app id: {app_id}." if app_id else ""
        return result("Trace API", "fail", impact, fix_hint, f"{wrapped}{extra}")


def _probe_exchange_admin(
    exchange: ExchangeAdminClient,
    token: str | None,
    *,
    target: str | None,
) -> DoctorCheckResult:
    impact = "Mailbox forwarding and delegation checks through Exchange Admin API will fail."
    fix_hint = "Grant Exchange.ManageV2 or Exchange.ManageAsAppV2 and ensure the token can access the endpoint."
    if not target:
        return result("Exchange Admin API", "skip", impact, fix_hint, "Re-run with --target to test mailbox cmdlets.")
    if not token:
        return result("Exchange Admin API", "fail", impact, fix_hint, "No Exchange token available.")
    try:
        fetch_mailbox_snapshot(exchange, token, identifier=target)
        return result("Exchange Admin API", "pass", impact, fix_hint)
    except ExchangeAdminApiError as exc:
        return result("Exchange Admin API", "fail", impact, fix_hint, str(exc))


def run_doctor(
    settings: Settings,
    *,
    account: str | None = None,
    target: str | None = None,
    fix: bool = False,
) -> dict[str, object]:
    provider = TokenProvider(settings)
    graph = GraphClient(settings)
    exchange = ExchangeAdminClient(settings)

    checks: list[DoctorCheckResult] = [
        result(
            "Config loaded",
            "pass" if settings.tenant_id and settings.client_id else "fail",
            "The CLI cannot authenticate or target the right tenant.",
            "Set M365_TENANT_ID and M365_CLIENT_ID in .env or select a tenant profile.",
            f"tenant_id={settings.tenant_id or '-'} client_id={settings.client_id or '-'}",
        )
    ]

    delegated_base_token = provider.get_access_token_silent(requested_scopes(), username=account)
    if delegated_base_token:
        checks.append(
            result(
                "Delegated token cached",
                "pass",
                "Without this, delegated Graph checks will need interactive login.",
                "Run m365-admin login to cache a delegated token.",
            )
        )
    else:
        checks.append(
            result(
                "Delegated token cached",
                "fail",
                "Without this, delegated Graph checks will need interactive login.",
                "Run m365-admin login to cache a delegated token.",
                "No cached token matched the configured admin account/scopes.",
            )
        )

    if settings.client_secret:
        checks.append(
            result(
                "App-only auth available",
                "pass",
                "App-only Graph and mailbox checks can run without mailbox delegation.",
                "Keep M365_CLIENT_SECRET configured.",
            )
        )
    else:
        checks.append(
            result(
                "App-only auth available",
                "skip",
                "Cross-user mailbox reads will rely on delegated mailbox access and often fail.",
                "Set M365_CLIENT_SECRET to enable app-only auth.",
            )
        )

    app_graph_token: str | None = None
    if settings.client_secret:
        try:
            app_graph_token = provider.get_app_access_token(GRAPH_RESOURCE)
            checks.append(
                result(
                    "App-only token works",
                    "pass",
                    "App-only Graph checks can run.",
                    "If this fails later, verify client secret and app permissions.",
                )
            )
        except AuthError as exc:
            checks.append(
                result(
                    "App-only token works",
                    "fail",
                    "App-only Graph checks will fail.",
                    "Verify M365_CLIENT_SECRET, app registration, and consented app permissions.",
                    str(exc),
                )
            )
    else:
        checks.append(
            result(
                "App-only token works",
                "skip",
                "App-only Graph checks are not configured.",
                "Set M365_CLIENT_SECRET and consent application permissions.",
            )
        )

    checks.append(
        _probe_graph_read(
            graph,
            delegated_base_token,
            check="Sign-in read",
            impact="The signins and diagnose sign-in sections will fail.",
            fix_hint="Consent AuditLog.Read.All and run m365-admin login.",
            path="auditLogs/signIns",
            params={"$top": "1"},
        )
    )

    delegated_directory_token = provider.get_access_token_silent(requested_scopes(include_directory=True), username=account)
    if target:
        checks.append(
            _probe_graph_read(
                graph,
                delegated_directory_token,
                check="Directory read",
                impact="User profile and app-assignment checks will fail.",
                fix_hint="Consent Directory.Read.All and run m365-admin login.",
                path=f"users/{target}",
                params={"$select": "id,displayName,userPrincipalName"},
            )
        )
    else:
        checks.append(
            result(
                "Directory read",
                "skip",
                "User profile and app-assignment checks will not be preflighted.",
                "Re-run with --target to test directory access for a user.",
            )
        )

    delegated_risk_token = provider.get_access_token_silent(requested_scopes(include_risk=True), username=account)
    checks.append(
        _probe_graph_read(
            graph,
            delegated_risk_token,
            check="Risk read",
            impact="Risk detections will be unavailable in diagnose.",
            fix_hint="Consent IdentityRiskEvent.Read.All and run m365-admin login --include-risk.",
            path="identityProtection/riskDetections",
            params={"$top": "1"},
        )
        if delegated_risk_token
        else result(
            "Risk read",
            "skip",
            "Risk detections will be unavailable in diagnose.",
            "Run m365-admin login --include-risk after consenting IdentityRiskEvent.Read.All.",
            "No cached risk token was found.",
        )
    )

    checks.append(
        _probe_cross_user_mail(
            graph,
            app_token=app_graph_token,
            delegated_token=provider.get_access_token_silent(requested_scopes(include_mail=True), username=account),
            target=target,
        )
    )

    checks.append(_probe_trace_service_principal(graph, delegated_directory_token))
    checks.append(
        _probe_trace_api(
            graph,
            provider.get_access_token_silent(requested_scopes(include_trace=True), username=account),
            settings=settings,
            target=target,
        )
    )

    exchange_token: str | None = None
    try:
        exchange_token = provider.get_app_access_token(EXCHANGE_RESOURCE) if settings.client_secret else provider.get_access_token_silent(
            exchange_delegated_scopes(),
            username=account,
        )
    except AuthError:
        exchange_token = None
    checks.append(_probe_exchange_admin(exchange, exchange_token, target=target))

    fixes: list[dict[str, str]] = []
    trace_sp_check = next((item for item in checks if item.check == "Trace service principal"), None)
    if fix and trace_sp_check and trace_sp_check.status == "fail":
        fixes.append(ensure_trace_service_principal())
        refreshed = _probe_trace_service_principal(graph, delegated_directory_token)
        checks = [item if item.check != "Trace service principal" else refreshed for item in checks]

    return {
        "checks": [item.to_dict() for item in checks],
        "fixes": fixes,
        "summary": summarize_checks(checks),
        "target": target,
        "profile": settings.profile_name,
        "tenantId": settings.tenant_id,
        "account": account or settings.username,
    }
