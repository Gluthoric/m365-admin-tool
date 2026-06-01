from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any

from .graph import GraphApiError, GraphClient
from .identity import (
    fetch_user_auth_methods,
    fetch_user_license_details,
    fetch_user_memberships,
    fetch_user_profile,
    summarize_auth_methods,
    summarize_licenses,
    summarize_memberships,
)
from .investigation import (
    audit_event_touches_authentication,
    categorize_directory_audits,
    collect_aliases,
    fetch_directory_audits,
    fetch_inbox_rules,
    fetch_risk_detections,
    fetch_signins,
    rule_has_forwarding,
    summarize_rule,
)
from .outbound import (
    address_text,
    describe_message_trace_error,
    fetch_folder_messages,
    fetch_mailbox_permissions,
    fetch_mailbox_snapshot,
    fetch_message_traces,
    fetch_recipient_permissions,
    fetch_user_app_review,
    find_sender_mismatches,
    summarize_delegation,
    summarize_mailbox_snapshot,
)
from .exchange_admin import ExchangeAdminApiError, ExchangeAdminClient


DANGEROUS_GRANT_SCOPES = {
    "mail.readwrite",
    "mail.send",
    "files.readwrite.all",
    "full_access_as_app",
    "mailboxsettings.readwrite",
}
LEGACY_AUTH_CLIENTS = {
    "other clients",
    "exchange active sync",
    "imap",
    "pop",
    "smtp",
    "smtp auth",
}
EXTERNAL_RULE_KEYS = ("forwardTo", "redirectTo", "forwardAsAttachmentTo")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_graph_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        return datetime.fromisoformat(value).astimezone(timezone.utc)
    except ValueError:
        return None


def email_domain(value: str | None) -> str | None:
    if not value or "@" not in value:
        return None
    return value.rsplit("@", 1)[-1].lower()


def permission_entry(status: str, details: str = "") -> dict[str, str]:
    payload = {"status": status}
    if details:
        payload["details"] = details
    return payload


def summarize_signins_detailed(signins: list[dict[str, Any]], *, now: datetime | None = None) -> dict[str, Any]:
    current = now or utc_now()
    failures = []
    successes = []
    legacy_clients: set[str] = set()
    ips: list[str] = []
    ip_counts: Counter[str] = Counter()
    geo_counts: Counter[str] = Counter()
    ca_failures = 0
    mfa_failures = 0
    mfa_gap = False
    counts_by_window = {"1h": 0, "6h": 0, "24h": 0, "48h": 0}

    for signin in signins:
        created = parse_graph_datetime(signin.get("createdDateTime"))
        if created:
            age = current - created
            if age <= timedelta(hours=1):
                counts_by_window["1h"] += 1
            if age <= timedelta(hours=6):
                counts_by_window["6h"] += 1
            if age <= timedelta(hours=24):
                counts_by_window["24h"] += 1
            if age <= timedelta(hours=48):
                counts_by_window["48h"] += 1

        status = signin.get("status") or {}
        error_code = status.get("errorCode") or 0
        if error_code:
            failures.append(signin)
        else:
            successes.append(signin)

        client = str(signin.get("clientAppUsed") or "").strip()
        if client.lower() in LEGACY_AUTH_CLIENTS:
            legacy_clients.add(client)

        ip = str(signin.get("ipAddress") or "").strip()
        if ip:
            ips.append(ip)
            ip_counts[ip] += 1

        location = signin.get("location") or {}
        geo = ", ".join(str(location.get(key) or "") for key in ("city", "state", "countryOrRegion")).strip(", ")
        if geo:
            geo_counts[geo] += 1

        if str(signin.get("conditionalAccessStatus") or "").lower() == "failure":
            ca_failures += 1
        if str(signin.get("authenticationRequirement") or "").lower() == "multifactorauthentication" and error_code:
            mfa_failures += 1
        if not error_code and str(signin.get("authenticationRequirement") or "").lower() != "multifactorauthentication":
            mfa_gap = True

    unfamiliar_ips = sorted([ip for ip, count in ip_counts.items() if count == 1])
    unfamiliar_locations = sorted([geo for geo, count in geo_counts.items() if count == 1])
    last_success = successes[0].get("createdDateTime") if successes else None
    last_failure = failures[0].get("createdDateTime") if failures else None

    return {
        "total": len(signins),
        "failures": len(failures),
        "risky": sum(1 for item in signins if (item.get("riskLevelAggregated") or "none") != "none"),
        "uniqueIpCount": len(set(ips)),
        "uniqueIps": sorted(set(ips)),
        "lastSuccess": last_success,
        "lastFailure": last_failure,
        "countsByWindow": counts_by_window,
        "legacyAuthUsed": bool(legacy_clients),
        "legacyAuthClients": sorted(legacy_clients),
        "unfamiliarIps": unfamiliar_ips,
        "unfamiliarLocations": unfamiliar_locations,
        "conditionalAccessFailures": ca_failures,
        "mfaFailures": mfa_failures,
        "mfaGap": mfa_gap,
    }


def summarize_mailbox(
    *,
    identifier: str,
    rules: list[dict[str, Any]],
    sent_items: list[dict[str, Any]],
    deleted_items: list[dict[str, Any]],
    snapshot: dict[str, Any],
) -> dict[str, Any]:
    domain = email_domain(identifier)
    suspicious_rules: list[dict[str, Any]] = []
    external_forwarding = False

    for rule in rules:
        summary = summarize_rule(rule)
        rule_domain_targets: list[str] = []
        actions = rule.get("actions") or {}
        for key in EXTERNAL_RULE_KEYS:
            for entry in actions.get(key) or []:
                address = ((entry or {}).get("emailAddress") or {}).get("address")
                if address:
                    rule_domain_targets.append(address)
        if any(summary["forwarding"] or token in summary["actions"] for token in ("delete", "markAsRead", "stopProcessingRules")):
            suspicious_rules.append(summary)
        if domain and any(email_domain(address) and email_domain(address) != domain for address in rule_domain_targets):
            external_forwarding = True

    snapshot_summary = summarize_mailbox_snapshot(snapshot)
    forwarding_smtp = snapshot_summary.get("forwardingSmtpAddress")
    if domain and email_domain(str(forwarding_smtp) if forwarding_smtp else None) not in (None, domain):
        external_forwarding = True

    return {
        "rules": rules,
        "ruleSummaries": [summarize_rule(item) for item in rules],
        "sentItems": sent_items,
        "deletedItems": deleted_items,
        "snapshot": snapshot_summary,
        "summary": {
            "ruleCount": len(rules),
            "forwardingRuleCount": sum(1 for rule in rules if rule_has_forwarding(rule)),
            "suspiciousRuleCount": len(suspicious_rules),
            "suspiciousRules": suspicious_rules,
            "sentItemCount": len(sent_items),
            "deletedItemCount": len(deleted_items),
            "senderMismatchCount": len(find_sender_mismatches(sent_items)),
            "forwardingActive": bool(
                snapshot_summary.get("forwardingAddress")
                or snapshot_summary.get("forwardingSmtpAddress")
                or snapshot_summary.get("deliverToMailboxAndForward")
                or suspicious_rules
            ),
            "externalForwarding": external_forwarding,
        },
    }


def summarize_apps(review: dict[str, Any]) -> dict[str, Any]:
    suspicious_grants = []
    for grant in review.get("delegatedPermissionGrants") or []:
        scopes = {scope.strip().lower() for scope in str(grant.get("scope") or "").split() if scope.strip()}
        matches = sorted(scopes & DANGEROUS_GRANT_SCOPES)
        if matches:
            suspicious_grants.append(
                {
                    "clientDisplayName": grant.get("clientDisplayName"),
                    "resourceDisplayName": grant.get("resourceDisplayName"),
                    "matchedScopes": matches,
                }
            )

    return {
        **review,
        "summary": {
            "delegatedPermissionGrantCount": len(review.get("delegatedPermissionGrants") or []),
            "appRoleAssignmentCount": len(review.get("appRoleAssignments") or []),
            "suspiciousGrantCount": len(suspicious_grants),
            "suspiciousGrants": suspicious_grants,
        },
    }


def summarize_outbound(
    *,
    sender: str,
    traces: list[dict[str, Any]],
) -> dict[str, Any]:
    sender_domain = email_domain(sender)
    recipient_counts: Counter[str] = Counter()
    status_counts: Counter[str] = Counter()
    subject_counts: Counter[str] = Counter()
    external_recipients = 0

    bursts: dict[str, list[datetime]] = {}
    for trace in traces:
        recipient = str(trace.get("recipientAddress") or "").strip()
        subject = str(trace.get("subject") or "").strip()
        status = str(trace.get("status") or "unknown")
        received = parse_graph_datetime(trace.get("receivedDateTime") or trace.get("createdDateTime"))

        if recipient:
            recipient_counts[recipient] += 1
            if sender_domain and email_domain(recipient) not in (None, sender_domain):
                external_recipients += 1
            if received:
                bursts.setdefault(recipient, []).append(received)
        if subject:
            subject_counts[subject] += 1
        status_counts[status] += 1

    burst_detected = False
    for timestamps in bursts.values():
        timestamps.sort()
        for index in range(len(timestamps) - 2):
            if timestamps[index + 2] - timestamps[index] <= timedelta(minutes=5):
                burst_detected = True
                break
        if burst_detected:
            break

    recipient_total = sum(recipient_counts.values())
    top_recipients = [{"recipient": recipient, "count": count} for recipient, count in recipient_counts.most_common(5)]
    repeated_subjects = [{"subject": subject, "count": count} for subject, count in subject_counts.items() if count > 1]

    return {
        "trace": traces,
        "summary": {
            "traceCount": len(traces),
            "traceStatuses": dict(status_counts),
            "topRecipients": top_recipients,
            "externalRecipientRatio": (external_recipients / recipient_total) if recipient_total else 0.0,
            "sendBurstDetected": burst_detected,
            "repeatedSubjects": sorted(repeated_subjects, key=lambda item: item["count"], reverse=True)[:5],
        },
    }


def summarize_audit(events: list[dict[str, Any]]) -> dict[str, Any]:
    categories = categorize_directory_audits(events)
    return {
        "items": events,
        "categories": categories,
        "summary": {
            "total": len(events),
            "passwordOrAuthChanges": len(categories["passwordOrAuthChanges"]),
            "roleChanges": len(categories["roleChanges"]),
            "groupChanges": len(categories["groupChanges"]),
            "mailboxPermissionChanges": len(categories["mailboxPermissionChanges"]),
            "appConsentChanges": len(categories["appConsentChanges"]),
        },
    }


def severity_rank(value: str) -> int:
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    return order.get(value, -1)


def permission_display_name(name: str) -> str:
    labels = {
        "signins": "Sign-in evidence",
        "identity.authMethods": "Authentication methods",
        "mailbox.rules": "Inbox rules",
        "mailbox.sentItems": "Sent Items",
        "mailbox.deletedItems": "Deleted Items",
        "mailbox.snapshot": "Mailbox forwarding snapshot",
        "delegation.fullAccess": "Full Access delegation",
        "delegation.sendAs": "Send As delegation",
        "outbound.trace": "Outbound trace",
        "riskDetections": "Risk detections",
    }
    return labels.get(name, name)


def audit_initiator_label(event: dict[str, Any]) -> str:
    initiated_by = event.get("initiatedBy") or {}
    user = initiated_by.get("user") or {}
    app = initiated_by.get("app") or {}

    user_label = str(user.get("userPrincipalName") or user.get("displayName") or "").strip()
    app_label = str(app.get("displayName") or "").strip()
    if user_label and app_label:
        return f"{user_label} via {app_label}"
    return user_label or app_label or "unknown initiator"


def build_confirmed_indicators(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    confirmed: list[dict[str, Any]] = []
    for finding in findings:
        if finding.get("source") == "audit":
            continue
        if severity_rank(str(finding.get("severity"))) >= severity_rank("high"):
            confirmed.append(dict(finding))
    return confirmed


def build_suspected_indicators(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    suspected: list[dict[str, Any]] = []
    for finding in findings:
        severity = severity_rank(str(finding.get("severity")))
        if finding.get("source") == "audit" or severity < severity_rank("high"):
            suspected.append(dict(finding))
    return suspected


def build_remediation_taken(audit: dict[str, Any]) -> list[dict[str, Any]]:
    remediation: list[dict[str, Any]] = []

    for event in audit.get("items") or []:
        activity = str(event.get("activityDisplayName") or "")
        lowered = activity.lower()
        result_reason = str(event.get("resultReason") or "").strip()
        timestamp = event.get("activityDateTime")
        initiator = audit_initiator_label(event)

        if "deleted security info" in lowered:
            remediation.append(
                {
                    "title": "Authentication methods reset",
                    "timestamp": timestamp,
                    "source": "audit",
                    "evidence": "audit.items",
                    "explanation": (
                        f"{initiator} removed registered security info for the account."
                        + (f" {result_reason}" if result_reason else "")
                    ).strip(),
                }
            )
            continue

        if audit_event_touches_authentication(event):
            app_name = str((((event.get("initiatedBy") or {}).get("app") or {}).get("displayName") or "")).lower()
            if "credential configuration endpoint service" in app_name:
                remediation.append(
                    {
                        "title": "Authentication settings updated after reset",
                        "timestamp": timestamp,
                        "source": "audit",
                        "evidence": "audit.items",
                        "explanation": "Directory authentication settings were updated by Azure Credential Configuration Endpoint Service.",
                    }
                )
                continue

        if "revoke" in lowered and "session" in lowered:
            remediation.append(
                {
                    "title": "Sessions revoked",
                    "timestamp": timestamp,
                    "source": "audit",
                    "evidence": "audit.items",
                    "explanation": f"{initiator} revoked active sessions for the account.",
                }
            )
            continue

        if "reset password" in lowered or "change password" in lowered:
            remediation.append(
                {
                    "title": "Password changed",
                    "timestamp": timestamp,
                    "source": "audit",
                    "evidence": "audit.items",
                    "explanation": f"{initiator} performed a password change/reset action for the account.",
                }
            )

    return remediation


def build_unavailable_evidence(permissions: dict[str, dict[str, str]]) -> list[dict[str, Any]]:
    unavailable: list[dict[str, Any]] = []
    for name, entry in permissions.items():
        status = str(entry.get("status") or "")
        if status not in {"fail", "skip"}:
            continue
        unavailable.append(
            {
                "title": permission_display_name(name),
                "source": name,
                "status": status,
                "details": entry.get("details", ""),
            }
        )
    return unavailable


def build_recommended_actions(
    *,
    findings: list[dict[str, Any]],
    permissions: dict[str, dict[str, str]],
) -> list[dict[str, str]]:
    actions: list[dict[str, str]] = []
    seen: set[str] = set()

    def add(title: str, explanation: str) -> None:
        if title in seen:
            return
        seen.add(title)
        actions.append({"title": title, "explanation": explanation})

    if any(item.get("source") == "outbound" for item in findings):
        add(
            "Review containment for outbound abuse",
            "Run containment planning and verify whether sessions, forwarding, inbox rules, and password/MFA reset steps were completed.",
        )

    signins_status = (permissions.get("signins") or {}).get("status")
    if signins_status in {"fail", "skip"}:
        add(
            "Restore sign-in visibility",
            "Enable tenant access to sign-in logs so incident windows can be tied to real sessions and IPs.",
        )

    if (permissions.get("identity.authMethods") or {}).get("status") in {"fail", "skip"}:
        add(
            "Grant auth-method visibility",
            "Consent UserAuthenticationMethod.Read.All and use an admin role that can read authentication methods.",
        )

    mailbox_related = {"mailbox.rules", "mailbox.sentItems", "mailbox.deletedItems"}
    if any((permissions.get(name) or {}).get("status") in {"fail", "skip"} for name in mailbox_related):
        add(
            "Enable app-only mailbox review",
            "Configure M365_CLIENT_SECRET and consent application Mail.Read plus MailboxSettings.Read for cross-user mailbox diagnostics.",
        )

    exchange_related = {"mailbox.snapshot", "delegation.fullAccess", "delegation.sendAs"}
    if any((permissions.get(name) or {}).get("status") in {"fail", "skip"} for name in exchange_related):
        add(
            "Grant Exchange admin access",
            "Grant Exchange.ManageAsAppV2 or Exchange.ManageV2 so forwarding and delegation checks are authoritative.",
        )

    if (permissions.get("outbound.trace") or {}).get("status") in {"fail", "skip"}:
        add(
            "Stabilize outbound trace collection",
            "Use the Exchange message-trace backend or retry after tenant propagation so trace data is reliable.",
        )

    return actions


def build_compromise_sections(
    *,
    findings: list[dict[str, Any]],
    audit: dict[str, Any],
    permissions: dict[str, dict[str, str]],
) -> dict[str, Any]:
    confirmed = build_confirmed_indicators(findings)
    suspected = build_suspected_indicators(findings)
    remediation = build_remediation_taken(audit)
    unavailable = build_unavailable_evidence(permissions)
    recommended = build_recommended_actions(findings=findings, permissions=permissions)
    return {
        "confirmedCompromiseIndicators": confirmed,
        "suspectedIndicators": suspected,
        "remediationAlreadyTaken": remediation,
        "unavailableEvidence": unavailable,
        "recommendedActions": recommended,
    }


def build_findings(
    *,
    identity: dict[str, Any],
    signins: dict[str, Any],
    mailbox: dict[str, Any],
    delegation: dict[str, Any],
    audit: dict[str, Any],
    apps: dict[str, Any],
    outbound: dict[str, Any],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    auth_section = identity.get("authMethods") or {}
    auth_summary = auth_section.get("summary") or {}
    auth_available = auth_section.get("available", bool(auth_summary))
    if auth_available and auth_summary and not auth_summary.get("hasMfaMethod", True):
        findings.append(
            {
                "severity": "high",
                "title": "No MFA method enrolled",
                "explanation": "The account does not appear to have any MFA-capable authentication methods registered.",
                "evidence": "identity.authMethods.summary",
                "source": "identity",
            }
        )

    if signins["summary"].get("legacyAuthUsed"):
        findings.append(
            {
                "severity": "high",
                "title": "Legacy authentication observed",
                "explanation": "Recent sign-ins used legacy client protocols that are commonly abused.",
                "evidence": "signins.summary.legacyAuthClients",
                "source": "signins",
            }
        )
    if signins["summary"].get("unfamiliarIps"):
        findings.append(
            {
                "severity": "medium",
                "title": "Unfamiliar IPs observed",
                "explanation": "Recent sign-ins include IPs that only appear once in the current lookback window.",
                "evidence": "signins.summary.unfamiliarIps",
                "source": "signins",
            }
        )
    if signins["summary"].get("mfaFailures"):
        findings.append(
            {
                "severity": "medium",
                "title": "MFA failures detected",
                "explanation": "Recent sign-ins show failed MFA attempts during the current investigation window.",
                "evidence": "signins.summary.mfaFailures",
                "source": "signins",
            }
        )

    mailbox_summary = mailbox.get("summary") or {}
    if mailbox_summary.get("externalForwarding"):
        findings.append(
            {
                "severity": "critical",
                "title": "External forwarding detected",
                "explanation": "The mailbox appears to forward mail outside the user's domain.",
                "evidence": "mailbox.summary.externalForwarding",
                "source": "mailbox",
            }
        )
    elif mailbox_summary.get("suspiciousRuleCount"):
        findings.append(
            {
                "severity": "high",
                "title": "Suspicious inbox rules present",
                "explanation": "Forwarding, delete, mark-as-read, or stop-processing rules were found.",
                "evidence": "mailbox.summary.suspiciousRules",
                "source": "mailbox",
            }
        )

    if delegation.get("summary", {}).get("hasDelegation"):
        findings.append(
            {
                "severity": "high",
                "title": "Mailbox delegation detected",
                "explanation": "The mailbox has Send As, Full Access, or Send on Behalf delegates configured.",
                "evidence": "delegation.summary",
                "source": "delegation",
            }
        )

    if apps.get("summary", {}).get("suspiciousGrantCount"):
        findings.append(
            {
                "severity": "high",
                "title": "Suspicious delegated app consent detected",
                "explanation": "Delegated app grants include high-risk scopes such as Mail.ReadWrite or Mail.Send.",
                "evidence": "apps.summary.suspiciousGrants",
                "source": "apps",
            }
        )

    outbound_summary = outbound.get("summary") or {}
    if outbound_summary.get("sendBurstDetected"):
        findings.append(
            {
                "severity": "high",
                "title": "Outbound send burst detected",
                "explanation": "Trace data shows multiple messages sent to the same recipient within a short interval.",
                "evidence": "outbound.summary.topRecipients",
                "source": "outbound",
            }
        )
    elif outbound_summary.get("externalRecipientRatio", 0) >= 0.8 and outbound_summary.get("traceCount", 0) >= 5:
        findings.append(
            {
                "severity": "medium",
                "title": "Predominantly external outbound traffic",
                "explanation": "Most traced messages in the window target external recipients.",
                "evidence": "outbound.summary.externalRecipientRatio",
                "source": "outbound",
            }
        )

    audit_summary = audit.get("summary") or {}
    if audit_summary.get("roleChanges"):
        findings.append(
            {
                "severity": "medium",
                "title": "Recent role changes detected",
                "explanation": "Directory audit logs show recent role assignment activity involving this user.",
                "evidence": "audit.categories.roleChanges",
                "source": "audit",
            }
        )
    if audit_summary.get("passwordOrAuthChanges"):
        findings.append(
            {
                "severity": "medium",
                "title": "Recent password or authentication changes detected",
                "explanation": "Directory audit logs show password or authentication method changes in the lookback window.",
                "evidence": "audit.categories.passwordOrAuthChanges",
                "source": "audit",
            }
        )

    findings.sort(key=lambda item: severity_rank(str(item["severity"])), reverse=True)
    return findings


def build_summary(
    *,
    identifier: str,
    sender: str,
    identity: dict[str, Any],
    signins: dict[str, Any],
    mailbox: dict[str, Any],
    delegation: dict[str, Any],
    audit: dict[str, Any],
    apps: dict[str, Any],
    outbound: dict[str, Any],
    findings: list[dict[str, Any]],
    warnings: list[str],
) -> dict[str, Any]:
    if findings and findings[0]["severity"] == "critical":
        verdict = "likely_compromised"
    elif sum(1 for item in findings if item["severity"] == "high") >= 2:
        verdict = "likely_compromised"
    elif findings and severity_rank(findings[0]["severity"]) >= severity_rank("medium"):
        verdict = "suspicious"
    else:
        verdict = "benign"

    verdict_reason = findings[0]["explanation"] if findings else "No high-signal indicators were detected in the collected data."
    auth_section = identity.get("authMethods") or {}
    auth_summary = auth_section.get("summary") or {}
    auth_available = auth_section.get("available", bool(auth_summary))
    signins_summary = signins.get("summary") or {}
    mailbox_summary = mailbox.get("summary") or {}
    delegation_summary = delegation.get("summary") or {}
    apps_summary = apps.get("summary") or {}
    outbound_summary = outbound.get("summary") or {}

    return {
        "identifier": identifier,
        "sender": sender,
        "verdict": verdict,
        "verdictReason": verdict_reason,
        "forwardingActive": mailbox_summary.get("forwardingActive", False),
        "externalForwarding": mailbox_summary.get("externalForwarding", False),
        "suspiciousRules": mailbox_summary.get("suspiciousRuleCount", 0) > 0,
        "delegationAnomaly": delegation_summary.get("hasDelegation", False),
        "suspiciousApps": apps_summary.get("suspiciousGrantCount", 0) > 0,
        "sendBurstDetected": outbound_summary.get("sendBurstDetected", False),
        "legacyAuthUsed": signins_summary.get("legacyAuthUsed", False),
        "unfamiliarIp": bool(signins_summary.get("unfamiliarIps")),
        "mfaGap": signins_summary.get("mfaGap", False) or (auth_available and not auth_summary.get("hasMfaMethod", True)),
        "warnings": warnings,
    }


def build_diagnostic_payload(
    *,
    graph: GraphClient,
    exchange: ExchangeAdminClient,
    graph_token: str,
    exchange_token: str | None,
    settings_client_id: str | None,
    identifier: str,
    sender: str,
    days: int,
    hours: int,
    limit: int,
    trace_limit: int,
    skip_risk: bool,
) -> dict[str, Any]:
    permissions: dict[str, dict[str, str]] = {}
    warnings: list[str] = []

    def capture_graph(name: str, func):
        try:
            value = func()
            permissions[name] = permission_entry("pass")
            return value
        except GraphApiError as exc:
            wrapped = describe_message_trace_error(exc, configured_client_id=settings_client_id) if name == "outbound.trace" else exc
            permissions[name] = permission_entry("fail", str(wrapped))
            warnings.append(f"{name}: {wrapped}")
            return None

    def capture_exchange(name: str, func):
        try:
            value = func()
            permissions[name] = permission_entry("pass")
            return value
        except ExchangeAdminApiError as exc:
            permissions[name] = permission_entry("fail", str(exc))
            warnings.append(f"{name}: {exc}")
            return None

    signins_raw = capture_graph("signins", lambda: fetch_signins(graph, graph_token, identifier, days, limit)) or []
    signins = {"items": signins_raw, "summary": summarize_signins_detailed(signins_raw)}
    aliases = collect_aliases(identifier, signins_raw)

    user_profile = capture_graph("identity.profile", lambda: fetch_user_profile(graph, graph_token, identifier)) or {}
    user_id = str(user_profile.get("id") or "")
    licenses = capture_graph("identity.licenses", lambda: fetch_user_license_details(graph, graph_token, user_id)) if user_id else None
    memberships = capture_graph("identity.memberships", lambda: fetch_user_memberships(graph, graph_token, user_id)) if user_id else None
    auth_methods = capture_graph("identity.authMethods", lambda: fetch_user_auth_methods(graph, graph_token, user_id)) if user_id else None

    identity = {
        "profile": user_profile,
        "licenses": {
            "items": licenses or [],
            "summary": summarize_licenses(licenses or []),
        },
        "memberships": {
            "items": memberships or [],
            "summary": summarize_memberships(memberships or []),
        },
        "authMethods": {
            "available": auth_methods is not None,
            "items": auth_methods or [],
            "summary": summarize_auth_methods(auth_methods) if auth_methods is not None else {},
        },
    }

    audits_raw = capture_graph("audit", lambda: fetch_directory_audits(graph, graph_token, aliases, days, limit)) or []
    audit = summarize_audit(audits_raw)

    rules = capture_graph("mailbox.rules", lambda: fetch_inbox_rules(graph, graph_token, identifier)) or []
    sent_items = capture_graph(
        "mailbox.sentItems",
        lambda: fetch_folder_messages(
            graph,
            graph_token,
            mailbox=identifier,
            folder_name="sentitems",
            date_field="sentDateTime",
            hours=hours,
            days=days,
            limit=limit,
        ),
    ) or []
    deleted_items = capture_graph(
        "mailbox.deletedItems",
        lambda: fetch_folder_messages(
            graph,
            graph_token,
            mailbox=identifier,
            folder_name="deleteditems",
            date_field="lastModifiedDateTime",
            hours=hours,
            days=days,
            limit=limit,
        ),
    ) or []

    mailbox_snapshot: dict[str, Any] = {}
    mailbox_permissions: list[dict[str, Any]] = []
    recipient_permissions: list[dict[str, Any]] = []
    if exchange_token:
        mailbox_snapshot = capture_exchange(
            "mailbox.snapshot",
            lambda: fetch_mailbox_snapshot(exchange, exchange_token, identifier=identifier),
        ) or {}
        mailbox_permissions = capture_exchange(
            "delegation.fullAccess",
            lambda: fetch_mailbox_permissions(exchange, exchange_token, identifier=identifier),
        ) or []
        recipient_permissions = capture_exchange(
            "delegation.sendAs",
            lambda: fetch_recipient_permissions(exchange, exchange_token, identifier=identifier),
        ) or []
    else:
        permissions["mailbox.snapshot"] = permission_entry("skip", "No Exchange token available.")
        permissions["delegation.fullAccess"] = permission_entry("skip", "No Exchange token available.")
        permissions["delegation.sendAs"] = permission_entry("skip", "No Exchange token available.")

    mailbox = summarize_mailbox(
        identifier=identifier,
        rules=rules,
        sent_items=sent_items,
        deleted_items=deleted_items,
        snapshot=mailbox_snapshot,
    )
    delegation = {
        "mailboxPermissions": mailbox_permissions,
        "recipientPermissions": recipient_permissions,
        "summary": summarize_delegation(mailbox_snapshot, mailbox_permissions, recipient_permissions),
    }

    risk_items = []
    if skip_risk:
        permissions["riskDetections"] = permission_entry("skip", "Risk lookups were skipped by request.")
    else:
        risk_items = capture_graph("riskDetections", lambda: fetch_risk_detections(graph, graph_token, identifier, days, limit)) or []

    apps = summarize_apps(capture_graph("apps", lambda: fetch_user_app_review(graph, graph_token, identifier=identifier, limit=limit)) or {
        "user": {},
        "delegatedPermissionGrants": [],
        "appRoleAssignments": [],
    })

    traces = capture_graph(
        "outbound.trace",
        lambda: fetch_message_traces(graph, graph_token, sender=sender, hours=hours, days=days, limit=trace_limit),
    ) or []
    outbound = summarize_outbound(sender=sender, traces=traces)

    identity["riskSummary"] = {
        "count": len(risk_items),
        "latestRiskLevel": next((item.get("riskLevel") for item in risk_items if item.get("riskLevel")), None),
        "items": risk_items,
    }

    findings = build_findings(
        identity=identity,
        signins=signins,
        mailbox=mailbox,
        delegation=delegation,
        audit=audit,
        apps=apps,
        outbound=outbound,
    )
    summary = build_summary(
        identifier=identifier,
        sender=sender,
        identity=identity,
        signins=signins,
        mailbox=mailbox,
        delegation=delegation,
        audit=audit,
        apps=apps,
        outbound=outbound,
        findings=findings,
        warnings=warnings,
    )
    compromise_sections = build_compromise_sections(findings=findings, audit=audit, permissions=permissions)

    return {
        "identifier": identifier,
        "sender": sender,
        "summary": summary,
        "findings": findings,
        **compromise_sections,
        "identity": identity,
        "signins": signins,
        "mailbox": mailbox,
        "delegation": delegation,
        "audit": audit,
        "apps": apps,
        "outbound": outbound,
        "warnings": warnings,
        "permissions": permissions,
    }
