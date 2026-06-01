import argparse
import json
from pathlib import Path

from m365_admin_tool.cli import (
    choose_option,
    cmd_contain,
    cmd_diagnose,
    cmd_outbound_review,
    cmd_timeline,
    resolve_account,
    resolve_auth_mode,
    resolve_identifier,
    resolve_sender,
    resolve_settings_profile,
    resolve_time_window,
)
from m365_admin_tool.config import Settings
from m365_admin_tool.graph import GraphApiError


def make_settings(username: str | None = None, client_secret: str | None = None) -> Settings:
    return Settings(
        profile_name=None,
        tenant_id="tenant",
        client_id="client",
        client_secret=client_secret,
        username=username,
        access_token=None,
        graph_base_url="https://graph.microsoft.com/v1.0",
        exchange_base_url="https://outlook.office365.com",
        authority_host="https://login.microsoftonline.com",
        token_cache_path=Path("/tmp/token-cache.json"),
        device_flow_path=Path("/tmp/device-flow.json"),
        timeout_seconds=30.0,
    )


def test_resolve_identifier_prompts_when_missing(monkeypatch) -> None:
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    assert resolve_identifier(None, prompt=lambda _: "victim@example.com") == "victim@example.com"


def test_resolve_account_prefers_settings_username() -> None:
    settings = make_settings(username="admin@example.com")
    assert resolve_account(None, settings) == "admin@example.com"


def test_resolve_account_allows_blank_prompt(monkeypatch) -> None:
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    settings = make_settings()
    assert resolve_account(None, settings, prompt=lambda _: "") is None


def test_resolve_sender_uses_identifier_default() -> None:
    assert resolve_sender(None, identifier="victim@example.com") == "victim@example.com"


def test_resolve_auth_mode_prefers_app_when_secret_exists() -> None:
    settings = make_settings(client_secret="secret")
    assert resolve_auth_mode("auto", settings, prefer_app=True) == "app"


def test_choose_option_uses_default(monkeypatch) -> None:
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    assert choose_option("Pick one", ["a", "b"], default_index=1, prompt=lambda _: "") == "b"


def test_resolve_settings_profile_from_file(tmp_path) -> None:
    settings = make_settings(username="env-admin@example.com")
    (tmp_path / "tenants.json").write_text(
        json.dumps(
            {
                "default": "tenant-a",
                "profiles": [
                    {
                        "name": "tenant-a",
                        "tenant_id": "tenant-a-id",
                        "client_id": "client-a-id",
                        "username": "admin-a@example.com",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    resolved = resolve_settings_profile(settings, None, cwd=str(tmp_path))

    assert resolved.profile_name == "tenant-a"
    assert resolved.tenant_id == "tenant-a-id"
    assert resolved.client_id == "client-a-id"
    assert resolved.username == "admin-a@example.com"


def test_resolve_time_window_uses_hours() -> None:
    start, end, label = resolve_time_window(
        to_time=__import__("datetime").datetime(2026, 3, 9, 22, 0, tzinfo=__import__("datetime").timezone.utc),
        hours=2,
    )
    assert (end - start).total_seconds() == 7200
    assert "2026-03-09T20:00:00+00:00" in label


def test_cmd_outbound_review_continues_when_trace_fails(monkeypatch, capsys) -> None:
    settings = make_settings(username="admin@example.com")
    args = argparse.Namespace(
        identifier="victim@example.com",
        sender=None,
        hours=48,
        days=None,
        limit=10,
        trace_limit=20,
        account=None,
        auth="delegated",
        json=False,
        force_device_code=False,
    )

    class DummyProvider:
        def get_access_token_silent(self, scopes, username=None):
            return "graph-token"

    monkeypatch.setattr("m365_admin_tool.cli.TokenProvider", lambda settings: DummyProvider())
    monkeypatch.setattr("m365_admin_tool.cli.GraphClient", lambda settings: object())
    monkeypatch.setattr("m365_admin_tool.cli.ExchangeAdminClient", lambda settings: object())
    monkeypatch.setattr("m365_admin_tool.cli.acquire_graph_token", lambda *args, **kwargs: "graph-token")
    monkeypatch.setattr("m365_admin_tool.cli.acquire_exchange_token", lambda *args, **kwargs: "exchange-token")

    def fail_trace(*args, **kwargs):
        raise GraphApiError(
            401,
            (
                "Service principal-less Authentication failed: the service principal for App ID "
                "8bd644d1-64a1-4d4b-ae52-2e0cbf64e373 was not found."
            ),
            code="Unauthorized",
        )

    monkeypatch.setattr("m365_admin_tool.cli.fetch_message_traces", fail_trace)
    monkeypatch.setattr("m365_admin_tool.cli.fetch_folder_messages", lambda *args, **kwargs: [])
    monkeypatch.setattr("m365_admin_tool.cli.fetch_inbox_rules", lambda *args, **kwargs: [])
    monkeypatch.setattr(
        "m365_admin_tool.cli.fetch_user_app_review",
        lambda *args, **kwargs: {"user": {}, "delegatedPermissionGrants": [], "appRoleAssignments": []},
    )
    monkeypatch.setattr("m365_admin_tool.cli.fetch_mailbox_snapshot", lambda *args, **kwargs: {})

    result = cmd_outbound_review(args, settings)
    captured = capsys.readouterr()

    assert result == 0
    assert "Trace rows: unavailable" in captured.out
    assert "Warnings" in captured.out
    assert "Continuing with mailbox, rules, app, and forwarding checks." in captured.out


def test_cmd_diagnose_json_uses_profile_and_returns_payload(monkeypatch, tmp_path, capsys) -> None:
    settings = make_settings(username="env-admin@example.com")
    (tmp_path / "tenants.json").write_text(
        json.dumps(
            {
                "profiles": [
                    {
                        "name": "tenant-a",
                        "tenant_id": "tenant-a-id",
                        "client_id": "client-a-id",
                        "username": "admin-a@example.com",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    args = argparse.Namespace(
        identifier="victim@example.com",
        profile="tenant-a",
        hours=48,
        days=None,
        limit=10,
        trace_limit=20,
        account=None,
        auth="delegated",
        skip_risk=True,
        json=True,
        force_device_code=False,
    )

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("m365_admin_tool.cli.build_full_diagnostic_payload", lambda identifier, **kwargs: {
        "identifier": identifier,
        "tenantProfile": kwargs["settings"].profile_name,
        "tenantId": kwargs["settings"].tenant_id,
        "summary": {"warnings": []},
    })

    result = cmd_diagnose(args, settings)
    captured = capsys.readouterr()

    assert result == 0
    payload = json.loads(captured.out)
    assert payload["identifier"] == "victim@example.com"
    assert payload["tenantProfile"] == "tenant-a"
    assert payload["tenantId"] == "tenant-a-id"


def test_cmd_diagnose_prints_compromise_sections(monkeypatch, capsys) -> None:
    settings = make_settings(username="admin@example.com")
    args = argparse.Namespace(
        identifier="victim@example.com",
        profile=None,
        hours=48,
        days=None,
        limit=10,
        trace_limit=20,
        account=None,
        auth="delegated",
        skip_risk=True,
        json=False,
        force_device_code=False,
    )

    monkeypatch.setattr(
        "m365_admin_tool.cli.build_full_diagnostic_payload",
        lambda identifier, **kwargs: {
            "summary": {"verdict": "suspicious", "verdictReason": "Outbound burst detected."},
            "signins": {"summary": {"total": 0}},
            "audit": {"summary": {"total": 1}},
            "mailbox": {"summary": {"ruleCount": 0, "sentItemCount": 0, "deletedItemCount": 0}},
            "identity": {"riskSummary": {"count": 0}},
            "outbound": {"summary": {"traceCount": 5}},
            "apps": {"summary": {"suspiciousGrantCount": 0}},
            "delegation": {"summary": {"hasDelegation": False}},
            "confirmedCompromiseIndicators": [
                {"severity": "high", "title": "Outbound send burst detected", "explanation": "Trace burst."}
            ],
            "suspectedIndicators": [
                {"severity": "medium", "title": "Recent auth changes", "explanation": "Audit saw auth changes."}
            ],
            "remediationAlreadyTaken": [
                {"timestamp": "2026-03-09T21:30:16Z", "title": "Authentication methods reset", "explanation": "Admin reset MFA."}
            ],
            "unavailableEvidence": [
                {"status": "fail", "title": "Sign-in evidence", "details": "premium license required"}
            ],
            "recommendedActions": [
                {"title": "Restore sign-in visibility", "explanation": "Enable sign-in access."}
            ],
            "warnings": [],
        },
    )

    result = cmd_diagnose(args, settings)
    captured = capsys.readouterr()

    assert result == 0
    assert "Confirmed Indicators" in captured.out
    assert "Suspected Indicators" in captured.out
    assert "Remediation Already Taken" in captured.out
    assert "Unavailable Evidence" in captured.out
    assert "Recommended Actions" in captured.out


def test_cmd_timeline_json_returns_events(monkeypatch, capsys) -> None:
    settings = make_settings(username="admin@example.com")
    args = argparse.Namespace(
        identifier="victim@example.com",
        profile=None,
        sender=None,
        hours=2,
        from_time=None,
        to_time=None,
        limit=10,
        trace_limit=20,
        account=None,
        auth="delegated",
        json=True,
        force_device_code=False,
    )

    class DummyProvider:
        def get_access_token_silent(self, scopes, username=None):
            return "graph-token"

    monkeypatch.setattr("m365_admin_tool.cli.TokenProvider", lambda settings: DummyProvider())
    monkeypatch.setattr("m365_admin_tool.cli.GraphClient", lambda settings: object())
    monkeypatch.setattr("m365_admin_tool.cli.acquire_graph_token", lambda *args, **kwargs: "graph-token")
    monkeypatch.setattr(
        "m365_admin_tool.cli.build_timeline_events",
        lambda **kwargs: ([{"timestamp": "2026-03-09T20:00:00Z", "source": "SIGNIN", "event_type": "login_success", "summary": "ok", "status": "success"}], []),
    )

    result = cmd_timeline(args, settings)
    payload = json.loads(capsys.readouterr().out)

    assert result == 0
    assert payload["identifier"] == "victim@example.com"
    assert payload["events"][0]["source"] == "SIGNIN"


def test_cmd_contain_dry_run_plans_actions(monkeypatch, capsys) -> None:
    settings = make_settings(username="admin@example.com")
    args = argparse.Namespace(
        identifier="victim@example.com",
        profile=None,
        dry_run=True,
        yes=False,
        block_sign_in=True,
        account=None,
        auth="delegated",
        json=True,
        force_device_code=False,
    )

    class DummyProvider:
        def get_access_token_silent(self, scopes, username=None):
            return "graph-token"

    monkeypatch.setattr("m365_admin_tool.cli.TokenProvider", lambda settings: DummyProvider())
    monkeypatch.setattr("m365_admin_tool.cli.GraphClient", lambda settings: object())
    monkeypatch.setattr("m365_admin_tool.cli.ExchangeAdminClient", lambda settings: object())
    monkeypatch.setattr("m365_admin_tool.cli.acquire_graph_token", lambda *args, **kwargs: "graph-token")
    monkeypatch.setattr("m365_admin_tool.cli.acquire_exchange_token", lambda *args, **kwargs: "exchange-token")
    monkeypatch.setattr("m365_admin_tool.cli.list_authentication_methods", lambda *args, **kwargs: [{"@odata.type": "#microsoft.graph.phoneAuthenticationMethod"}])
    monkeypatch.setattr("m365_admin_tool.cli.list_suspicious_rules", lambda *args, **kwargs: [{"id": "rule-1", "displayName": "Forward rule", "actions": {}, "conditions": {}, "isEnabled": True, "hasError": False, "isReadOnly": False, "sequence": 1}])
    monkeypatch.setattr("m365_admin_tool.cli.fetch_mailbox_snapshot", lambda *args, **kwargs: {"ForwardingSmtpAddress": "attacker@example.net"})

    result = cmd_contain(args, settings)
    payload = json.loads(capsys.readouterr().out)

    assert result == 0
    assert any(item["action"] == "revoke_sign_in_sessions" and item["status"] == "skipped" for item in payload["actions"])
    assert any(item["action"] == "block_sign_in" for item in payload["actions"])
