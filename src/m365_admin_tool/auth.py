from __future__ import annotations

import json
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

import msal

from .config import Settings

GRAPH_RESOURCE = "https://graph.microsoft.com"
EXCHANGE_RESOURCE = "https://outlook.office365.com"
BASE_GRAPH_PERMISSIONS = (
    "AuditLog.Read.All",
    "MailboxSettings.Read",
)
DIRECTORY_PERMISSION = "Directory.Read.All"
MAIL_PERMISSION = "Mail.Read"
MAILBOX_SETTINGS_READWRITE_PERMISSION = "MailboxSettings.ReadWrite"
RISK_PERMISSION = "IdentityRiskEvent.Read.All"
TRACE_PERMISSION = "ExchangeMessageTrace.Read.All"
USER_AUTH_METHOD_PERMISSION = "UserAuthenticationMethod.Read.All"
USER_WRITE_PERMISSION = "User.ReadWrite.All"


class AuthError(RuntimeError):
    pass


def resource_default_scope(resource: str) -> str:
    return f"{resource.rstrip('/')}/.default"


def requested_scopes(
    *,
    include_mail: bool = False,
    include_directory: bool = False,
    include_mailbox_settings_write: bool = False,
    include_risk: bool = False,
    include_trace: bool = False,
    include_auth_methods: bool = False,
    include_user_write: bool = False,
) -> tuple[str, ...]:
    permissions = list(BASE_GRAPH_PERMISSIONS)
    if include_mail:
        permissions.append(MAIL_PERMISSION)
    if include_directory:
        permissions.append(DIRECTORY_PERMISSION)
    if include_mailbox_settings_write:
        permissions.append(MAILBOX_SETTINGS_READWRITE_PERMISSION)
    if include_risk:
        permissions.append(RISK_PERMISSION)
    if include_trace:
        permissions.append(TRACE_PERMISSION)
    if include_auth_methods:
        permissions.append(USER_AUTH_METHOD_PERMISSION)
    if include_user_write:
        permissions.append(USER_WRITE_PERMISSION)
    return tuple(dict.fromkeys(permissions))


def default_login_scopes(*, include_risk: bool = False) -> tuple[str, ...]:
    return requested_scopes(
        include_mail=True,
        include_directory=True,
        include_trace=True,
        include_risk=include_risk,
    )


def containment_scopes() -> tuple[str, ...]:
    return requested_scopes(
        include_directory=True,
        include_mailbox_settings_write=True,
        include_auth_methods=True,
        include_user_write=True,
    )


def exchange_delegated_scopes() -> tuple[str, ...]:
    return (resource_default_scope(EXCHANGE_RESOURCE),)


def normalize_username(value: str | None) -> str:
    return (value or "").strip().lower()


def format_account_label(account: dict) -> str:
    username = account.get("username") or "(unknown username)"
    environment = account.get("environment")
    return f"{username} [{environment}]" if environment else username


def choose_cached_account(
    accounts: Sequence[dict],
    *,
    prompt: Callable[[str], str] = input,
) -> dict:
    if not accounts:
        raise AuthError("No cached accounts are available.")
    if len(accounts) == 1:
        return accounts[0]
    if not sys.stdin.isatty():
        raise AuthError("Multiple cached accounts found. Re-run with --account to select one explicitly.")

    print("Multiple cached accounts found:", file=sys.stderr)
    for index, account in enumerate(accounts, start=1):
        print(f"  {index}. {format_account_label(account)}", file=sys.stderr)

    while True:
        raw = prompt(f"Select account [1-{len(accounts)}]: ").strip()
        if raw.isdigit():
            selection = int(raw)
            if 1 <= selection <= len(accounts):
                return accounts[selection - 1]
        print("Invalid selection.", file=sys.stderr)


class TokenProvider:
    def __init__(self, settings: Settings):
        self._settings = settings
        self._cache: msal.SerializableTokenCache | None = None
        self._public_app: msal.PublicClientApplication | None = None
        self._confidential_app: msal.ConfidentialClientApplication | None = None

        if not settings.access_token:
            self._cache = msal.SerializableTokenCache()
            self._load_cache(settings.token_cache_path)
            self._public_app = msal.PublicClientApplication(
                client_id=settings.client_id or "",
                authority=settings.authority,
                token_cache=self._cache,
            )
            if settings.client_secret:
                self._confidential_app = msal.ConfidentialClientApplication(
                    client_id=settings.client_id or "",
                    authority=settings.authority,
                    client_credential=settings.client_secret,
                    token_cache=self._cache,
                )

    def _load_cache(self, path: Path) -> None:
        if self._cache is None or not path.exists():
            return
        self._cache.deserialize(path.read_text(encoding="utf-8"))

    def _save_cache(self) -> None:
        if self._cache is None or not self._cache.has_state_changed:
            return
        cache_path = self._settings.token_cache_path
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(self._cache.serialize(), encoding="utf-8")

    def _save_device_flow(self, payload: dict[str, Any]) -> None:
        path = self._settings.device_flow_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    def _load_device_flow(self) -> dict[str, Any]:
        path = self._settings.device_flow_path
        if not path.exists():
            raise AuthError(f"No pending device flow found at {path}.")
        return json.loads(path.read_text(encoding="utf-8"))

    def clear_device_flow(self) -> None:
        path = self._settings.device_flow_path
        if path.exists():
            path.unlink()

    def _matching_cached_accounts(self, username: str | None) -> list[dict]:
        if self._public_app is None:
            return []
        if username:
            return list(self._public_app.get_accounts(username=username))
        return list(self._public_app.get_accounts())

    @property
    def has_app_credentials(self) -> bool:
        return self._confidential_app is not None

    def get_access_token_silent(
        self,
        scopes: Sequence[str],
        username: str | None = None,
    ) -> str | None:
        if self._settings.access_token:
            return self._settings.access_token
        if self._public_app is None:
            return None

        accounts = self._matching_cached_accounts(username or self._settings.username)
        if not accounts:
            return None
        if len(accounts) > 1 and not (username or self._settings.username):
            return None

        result = self._public_app.acquire_token_silent(list(scopes), account=accounts[0])
        if not result or "access_token" not in result:
            return None
        self._save_cache()
        return result["access_token"]

    def get_access_token(
        self,
        scopes: Sequence[str],
        force_device_code: bool = False,
        username: str | None = None,
    ) -> str:
        if self._settings.access_token:
            return self._settings.access_token

        if self._public_app is None:
            raise AuthError("Authentication is not configured.")

        result: dict | None = None
        effective_username = username or self._settings.username

        if not force_device_code:
            accounts = self._matching_cached_accounts(effective_username)
            if accounts:
                selected = choose_cached_account(accounts)
                result = self._public_app.acquire_token_silent(list(scopes), account=selected)

        if not result:
            flow = self._public_app.initiate_device_flow(scopes=list(scopes))
            if "user_code" not in flow:
                raise AuthError(f"Unable to start device-code flow: {json.dumps(flow, indent=2)}")
            print(flow["message"], file=sys.stderr)
            result = self._public_app.acquire_token_by_device_flow(flow)

        if "access_token" not in result:
            description = result.get("error_description") or result.get("error") or "unknown auth error"
            correlation_id = result.get("correlation_id")
            if correlation_id:
                description = f"{description} (correlation_id={correlation_id})"
            raise AuthError(description)

        signed_in_user = normalize_username((result.get("id_token_claims") or {}).get("preferred_username"))
        if effective_username and signed_in_user and signed_in_user != normalize_username(effective_username):
            raise AuthError(
                f"Signed in as {signed_in_user}, but {effective_username} was requested. "
                "Re-run with --force-device-code and complete sign-in with the intended account."
            )

        self._save_cache()
        return result["access_token"]

    def start_device_flow(self, scopes: Sequence[str], username: str | None = None) -> dict[str, Any]:
        if self._settings.access_token:
            raise AuthError("Cannot start device-code flow when M365_ACCESS_TOKEN is set.")
        if self._public_app is None:
            raise AuthError("Authentication is not configured.")

        effective_username = username or self._settings.username
        flow = self._public_app.initiate_device_flow(scopes=list(scopes))
        if "user_code" not in flow:
            raise AuthError(f"Unable to start device-code flow: {json.dumps(flow, indent=2)}")

        payload = {
            "flow": flow,
            "requested_username": effective_username,
            "scopes": list(scopes),
        }
        self._save_device_flow(payload)
        return payload

    def finish_device_flow(self) -> str:
        if self._public_app is None:
            raise AuthError("Authentication is not configured.")

        payload = self._load_device_flow()
        flow = payload.get("flow")
        if not isinstance(flow, dict) or "device_code" not in flow:
            raise AuthError("Saved device flow is invalid.")

        result = self._public_app.acquire_token_by_device_flow(flow)
        if "access_token" not in result:
            description = result.get("error_description") or result.get("error") or "unknown auth error"
            correlation_id = result.get("correlation_id")
            if correlation_id:
                description = f"{description} (correlation_id={correlation_id})"
            raise AuthError(description)

        requested_username = normalize_username(payload.get("requested_username"))
        signed_in_user = normalize_username((result.get("id_token_claims") or {}).get("preferred_username"))
        if requested_username and signed_in_user and signed_in_user != requested_username:
            raise AuthError(
                f"Signed in as {signed_in_user}, but {requested_username} was requested. "
                "Start a new device flow and complete sign-in with the intended account."
            )

        self._save_cache()
        self.clear_device_flow()
        return result["access_token"]

    def get_app_access_token(self, resource: str = GRAPH_RESOURCE) -> str:
        if self._settings.access_token and resource == GRAPH_RESOURCE:
            return self._settings.access_token

        if self._confidential_app is None:
            raise AuthError("M365_CLIENT_SECRET is required for app-only auth.")

        result = self._confidential_app.acquire_token_for_client(scopes=[resource_default_scope(resource)])
        if "access_token" not in result:
            description = result.get("error_description") or result.get("error") or "unknown app auth error"
            correlation_id = result.get("correlation_id")
            if correlation_id:
                description = f"{description} (correlation_id={correlation_id})"
            raise AuthError(description)

        self._save_cache()
        return result["access_token"]
