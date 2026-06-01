from m365_admin_tool.auth import (
    choose_cached_account,
    containment_scopes,
    default_login_scopes,
    exchange_delegated_scopes,
    format_account_label,
    normalize_username,
    requested_scopes,
)


def test_choose_cached_account_returns_only_entry() -> None:
    account = {"username": "admin@example.com", "environment": "login.microsoftonline.com"}
    assert choose_cached_account([account]) == account


def test_choose_cached_account_uses_prompt(monkeypatch) -> None:
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    accounts = [
        {"username": "first@example.com", "environment": "login.microsoftonline.com"},
        {"username": "second@example.com", "environment": "login.microsoftonline.com"},
    ]

    selected = choose_cached_account(accounts, prompt=lambda _: "2")
    assert selected["username"] == "second@example.com"


def test_normalize_username_and_label() -> None:
    assert normalize_username(" Admin@Example.com ") == "admin@example.com"
    assert format_account_label({"username": "admin@example.com", "environment": "contoso"}) == (
        "admin@example.com [contoso]"
    )


def test_requested_scopes_are_plain_permissions_without_oidc() -> None:
    assert requested_scopes(include_trace=True) == (
        "AuditLog.Read.All",
        "MailboxSettings.Read",
        "ExchangeMessageTrace.Read.All",
    )


def test_exchange_delegated_scopes_only_request_exchange_default_scope() -> None:
    assert exchange_delegated_scopes() == ("https://outlook.office365.com/.default",)


def test_default_login_scopes_cover_common_investigation_flow() -> None:
    assert default_login_scopes() == (
        "AuditLog.Read.All",
        "MailboxSettings.Read",
        "Mail.Read",
        "Directory.Read.All",
        "ExchangeMessageTrace.Read.All",
    )


def test_containment_scopes_include_write_permissions() -> None:
    assert containment_scopes() == (
        "AuditLog.Read.All",
        "MailboxSettings.Read",
        "Directory.Read.All",
        "MailboxSettings.ReadWrite",
        "UserAuthenticationMethod.Read.All",
        "User.ReadWrite.All",
    )
