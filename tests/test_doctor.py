from pathlib import Path

from m365_admin_tool.doctor import DoctorCheckResult, run_doctor, summarize_checks
from m365_admin_tool.config import Settings


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


def test_summarize_checks_counts_statuses() -> None:
    summary = summarize_checks(
        [
            DoctorCheckResult("a", "pass", "", ""),
            DoctorCheckResult("b", "fail", "", ""),
            DoctorCheckResult("c", "skip", "", ""),
            DoctorCheckResult("d", "warn", "", ""),
        ]
    )

    assert summary == {"pass": 1, "fail": 1, "skip": 1, "warn": 1}


def test_run_doctor_returns_expected_checks(monkeypatch) -> None:
    settings = make_settings(username="admin@example.com")

    class FakeProvider:
        def __init__(self, settings):
            self.settings = settings

        def get_access_token_silent(self, scopes, username=None):
            scope_set = set(scopes)
            if "IdentityRiskEvent.Read.All" in scope_set:
                return None
            if "https://outlook.office365.com/.default" in scope_set:
                return "exchange-token"
            return "delegated-token"

        def get_app_access_token(self, resource):
            raise AssertionError("app token should not be requested without client secret")

    class FakeGraphClient:
        def __init__(self, settings):
            self.settings = settings

        def get_object(self, token, path, params=None, headers=None):
            if path == "servicePrincipals":
                return {"value": [{"displayName": "Transport Data Platform"}]}
            return {"value": []}

    class FakeExchangeClient:
        def __init__(self, settings):
            self.settings = settings

    monkeypatch.setattr("m365_admin_tool.doctor.TokenProvider", FakeProvider)
    monkeypatch.setattr("m365_admin_tool.doctor.GraphClient", FakeGraphClient)
    monkeypatch.setattr("m365_admin_tool.doctor.ExchangeAdminClient", FakeExchangeClient)
    monkeypatch.setattr("m365_admin_tool.doctor.fetch_folder_messages", lambda *args, **kwargs: [])
    monkeypatch.setattr("m365_admin_tool.doctor.fetch_message_traces", lambda *args, **kwargs: [])
    monkeypatch.setattr("m365_admin_tool.doctor.fetch_mailbox_snapshot", lambda *args, **kwargs: {})

    payload = run_doctor(settings, account="admin@example.com", target="victim@example.com")

    statuses = {item["check"]: item["status"] for item in payload["checks"]}
    assert statuses["Config loaded"] == "pass"
    assert statuses["Delegated token cached"] == "pass"
    assert statuses["App-only auth available"] == "skip"
    assert statuses["Sign-in read"] == "pass"
    assert statuses["Directory read"] == "pass"
    assert statuses["Risk read"] == "skip"
    assert statuses["Cross-user mail read"] == "pass"
    assert statuses["Trace service principal"] == "pass"
    assert statuses["Trace API"] == "pass"
    assert statuses["Exchange Admin API"] == "pass"
