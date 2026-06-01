from datetime import UTC, datetime

from m365_admin_tool.investigation import (
    audit_event_touches_authentication,
    build_time_filter,
    categorize_directory_audits,
    collect_aliases,
    payload_contains_identifier,
    rule_has_forwarding,
    summarize_rule,
)


def test_payload_contains_identifier_matches_nested_values() -> None:
    payload = {
        "initiatedBy": {"user": {"userPrincipalName": "admin@example.com"}},
        "targetResources": [
            {"userPrincipalName": "victim@example.com"},
        ],
    }

    assert payload_contains_identifier(payload, ["victim@example.com"])
    assert not payload_contains_identifier(payload, ["other@example.com"])


def test_collect_aliases_includes_upn_and_object_id() -> None:
    signins = [
        {"userId": "1234-5678", "userPrincipalName": "victim@example.com"},
        {"userId": "1234-5678", "userPrincipalName": "victim@example.com"},
    ]

    aliases = collect_aliases("victim@example.com", signins)

    assert "victim@example.com" in aliases
    assert "1234-5678" in aliases


def test_rule_helpers_detect_forwarding() -> None:
    rule = {
        "displayName": "Forward everything",
        "sequence": 1,
        "isEnabled": True,
        "hasError": False,
        "isReadOnly": False,
        "conditions": {"subjectContains": ["invoice"]},
        "actions": {
            "forwardTo": [
                {"emailAddress": {"address": "attacker@example.net"}},
            ],
            "stopProcessingRules": True,
        },
    }

    assert rule_has_forwarding(rule)

    summary = summarize_rule(rule)
    assert summary["forwarding"] is True
    assert "attacker@example.net" in summary["actions"]


def test_build_time_filter_uses_utc_timestamps() -> None:
    now = datetime(2026, 3, 9, 12, 0, tzinfo=UTC)
    result = build_time_filter("createdDateTime", 7, now=now)

    assert "createdDateTime ge 2026-03-02T12:00:00Z" in result
    assert "createdDateTime le 2026-03-09T12:00:00Z" in result


def test_audit_event_touches_authentication_for_security_info_reset() -> None:
    event = {
        "activityDisplayName": "Admin deleted security info",
        "resultReason": "Admin required re-registration of MFA authentication methods.",
        "targetResources": [
            {
                "modifiedProperties": [
                    {"displayName": "Phone.PhoneNumber", "oldValue": "\"+1 5555550100\"", "newValue": "\"\""},
                ]
            }
        ],
    }

    assert audit_event_touches_authentication(event) is True


def test_categorize_directory_audits_treats_strong_auth_updates_as_auth_changes() -> None:
    event = {
        "activityDisplayName": "Update user",
        "targetResources": [
            {
                "modifiedProperties": [
                    {
                        "displayName": "StrongAuthenticationMethod",
                        "oldValue": "[{\"MethodType\":5}]",
                        "newValue": "[]",
                    }
                ]
            }
        ],
    }

    categories = categorize_directory_audits([event])

    assert categories["passwordOrAuthChanges"] == [event]
