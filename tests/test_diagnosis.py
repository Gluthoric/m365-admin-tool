from m365_admin_tool.diagnosis import (
    build_compromise_sections,
    build_findings,
    build_summary,
    summarize_outbound,
)


def test_summarize_outbound_detects_burst() -> None:
    traces = [
        {
            "receivedDateTime": "2026-03-09T20:38:21Z",
            "senderAddress": "user@example.com",
            "recipientAddress": "target@example.net",
            "status": "failed",
            "subject": "Invoice 1",
        },
        {
            "receivedDateTime": "2026-03-09T20:39:00Z",
            "senderAddress": "user@example.com",
            "recipientAddress": "target@example.net",
            "status": "failed",
            "subject": "Invoice 2",
        },
        {
            "receivedDateTime": "2026-03-09T20:40:00Z",
            "senderAddress": "user@example.com",
            "recipientAddress": "target@example.net",
            "status": "failed",
            "subject": "Invoice 3",
        },
    ]

    outbound = summarize_outbound(sender="user@example.com", traces=traces)

    assert outbound["summary"]["sendBurstDetected"] is True
    assert outbound["summary"]["externalRecipientRatio"] == 1.0


def test_build_summary_marks_external_forwarding_as_likely_compromised() -> None:
    identity = {"authMethods": {"summary": {"hasMfaMethod": True}}}
    signins = {"summary": {"legacyAuthUsed": False, "unfamiliarIps": [], "mfaGap": False}}
    mailbox = {"summary": {"externalForwarding": True, "forwardingActive": True, "suspiciousRuleCount": 0}}
    delegation = {"summary": {"hasDelegation": False}}
    audit = {"summary": {"roleChanges": 0, "passwordOrAuthChanges": 0}}
    apps = {"summary": {"suspiciousGrantCount": 0}}
    outbound = {"summary": {"sendBurstDetected": False}}
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
        identifier="victim@example.com",
        sender="victim@example.com",
        identity=identity,
        signins=signins,
        mailbox=mailbox,
        delegation=delegation,
        audit=audit,
        apps=apps,
        outbound=outbound,
        findings=findings,
        warnings=[],
    )

    assert findings[0]["severity"] == "critical"
    assert summary["verdict"] == "likely_compromised"


def test_build_findings_ignores_missing_auth_methods_when_unavailable() -> None:
    identity = {"authMethods": {"available": False, "summary": {}}}
    signins = {"summary": {"legacyAuthUsed": False, "unfamiliarIps": [], "mfaGap": False}}
    mailbox = {"summary": {"externalForwarding": False, "forwardingActive": False, "suspiciousRuleCount": 0}}
    delegation = {"summary": {"hasDelegation": False}}
    audit = {"summary": {"roleChanges": 0, "passwordOrAuthChanges": 0}}
    apps = {"summary": {"suspiciousGrantCount": 0}}
    outbound = {"summary": {"sendBurstDetected": False}}

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
        identifier="victim@example.com",
        sender="victim@example.com",
        identity=identity,
        signins=signins,
        mailbox=mailbox,
        delegation=delegation,
        audit=audit,
        apps=apps,
        outbound=outbound,
        findings=findings,
        warnings=[],
    )

    assert findings == []
    assert summary["mfaGap"] is False


def test_build_compromise_sections_separates_confirmed_remediation_and_unavailable() -> None:
    findings = [
        {
            "severity": "high",
            "title": "Outbound send burst detected",
            "explanation": "Trace data shows multiple messages sent to the same recipient within a short interval.",
            "evidence": "outbound.summary.topRecipients",
            "source": "outbound",
        },
        {
            "severity": "medium",
            "title": "Recent password or authentication changes detected",
            "explanation": "Directory audit logs show password or authentication method changes in the lookback window.",
            "evidence": "audit.categories.passwordOrAuthChanges",
            "source": "audit",
        },
    ]
    audit = {
        "items": [
            {
                "activityDateTime": "2026-03-09T21:30:16Z",
                "activityDisplayName": "Admin deleted security info",
                "resultReason": "Admin required re-registration of MFA authentication methods.",
                "initiatedBy": {
                    "user": {"userPrincipalName": "kayla@example.com"},
                    "app": {"displayName": "Capri"},
                },
            }
        ]
    }
    permissions = {
        "signins": {"status": "fail", "details": "premium license required"},
        "mailbox.sentItems": {"status": "fail", "details": "access denied"},
        "outbound.trace": {"status": "pass"},
    }

    sections = build_compromise_sections(findings=findings, audit=audit, permissions=permissions)

    assert [item["title"] for item in sections["confirmedCompromiseIndicators"]] == ["Outbound send burst detected"]
    assert [item["title"] for item in sections["suspectedIndicators"]] == ["Recent password or authentication changes detected"]
    assert sections["remediationAlreadyTaken"][0]["title"] == "Authentication methods reset"
    assert {item["title"] for item in sections["unavailableEvidence"]} == {"Sign-in evidence", "Sent Items"}
    assert {item["title"] for item in sections["recommendedActions"]} >= {
        "Restore sign-in visibility",
        "Enable app-only mailbox review",
        "Review containment for outbound abuse",
    }
