from __future__ import annotations

from typing import Any

import httpx

from .config import Settings


class ExchangeAdminApiError(RuntimeError):
    def __init__(self, status_code: int, message: str, code: str | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message

    def __str__(self) -> str:
        if self.code:
            return f"Exchange Admin API {self.status_code} ({self.code}): {self.message}"
        return f"Exchange Admin API {self.status_code}: {self.message}"

    @classmethod
    def from_response(cls, response: httpx.Response) -> ExchangeAdminApiError:
        message = response.text
        code: str | None = None
        try:
            payload = response.json()
        except ValueError:
            payload = None
        if isinstance(payload, dict):
            error = payload.get("error", {})
            if isinstance(error, dict):
                message = error.get("message", message)
                code = error.get("code")
        return cls(response.status_code, message, code)


def unwrap_exchange_payload(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        for key in ("value", "Value", "Output", "Results", "result"):
            nested = payload.get(key)
            if isinstance(nested, list):
                return [item for item in nested if isinstance(item, dict)]
            if isinstance(nested, dict):
                return [nested]
        return [payload]
    return []


class ExchangeAdminClient:
    def __init__(self, settings: Settings):
        self._settings = settings
        self._base_url = settings.exchange_base_url.rstrip("/")
        self._client = httpx.Client(
            timeout=settings.timeout_seconds,
            headers={"User-Agent": "m365-admin-tool/0.1.0"},
        )

    def run_cmdlet(
        self,
        token: str,
        endpoint: str,
        *,
        anchor_mailbox: str,
        cmdlet_name: str,
        parameters: dict[str, Any],
        select: str | None = None,
    ) -> list[dict[str, Any]]:
        if not self._settings.tenant_id:
            raise ExchangeAdminApiError(400, "M365_TENANT_ID is required for Exchange Admin API calls.")

        url = f"{self._base_url}/adminapi/v2.0/{self._settings.tenant_id}/{endpoint.lstrip('/')}"
        params = {"$select": select} if select else None
        response = self._client.post(
            url,
            params=params,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "X-AnchorMailbox": anchor_mailbox,
            },
            json={"CmdletInput": {"CmdletName": cmdlet_name, "Parameters": parameters}},
        )
        if response.is_error:
            raise ExchangeAdminApiError.from_response(response)
        payload = response.json() if response.content else {}
        return unwrap_exchange_payload(payload)
