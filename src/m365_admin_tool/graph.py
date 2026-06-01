from __future__ import annotations

from typing import Any, Mapping

import httpx

from .config import Settings


class GraphApiError(RuntimeError):
    def __init__(self, status_code: int, message: str, code: str | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message

    def __str__(self) -> str:
        if self.code:
            return f"Graph API {self.status_code} ({self.code}): {self.message}"
        return f"Graph API {self.status_code}: {self.message}"

    @classmethod
    def from_response(cls, response: httpx.Response) -> "GraphApiError":
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


class GraphClient:
    def __init__(self, settings: Settings):
        self._base_url = settings.graph_base_url.rstrip("/")
        self._client = httpx.Client(
            timeout=settings.timeout_seconds,
            headers={"User-Agent": "m365-admin-tool/0.1.0"},
        )

    def request_json(
        self,
        method: str,
        token: str,
        path_or_url: str,
        params: dict[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
        json_body: Any | None = None,
    ) -> dict[str, Any]:
        url = path_or_url if path_or_url.startswith("http") else f"{self._base_url}/{path_or_url.lstrip('/')}"
        request_headers = {"Authorization": f"Bearer {token}"}
        if headers:
            request_headers.update(headers)
        response = self._client.request(
            method,
            url,
            params=params,
            headers=request_headers,
            json=json_body,
        )
        if response.is_error:
            raise GraphApiError.from_response(response)
        if not response.content:
            return {}
        return response.json()

    def get_object(
        self,
        token: str,
        path_or_url: str,
        params: dict[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        return self.request_json("GET", token, path_or_url, params=params, headers=headers)

    def post_object(
        self,
        token: str,
        path_or_url: str,
        json_body: Any,
        params: dict[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        return self.request_json("POST", token, path_or_url, params=params, headers=headers, json_body=json_body)

    def patch_object(
        self,
        token: str,
        path_or_url: str,
        json_body: Any,
        params: dict[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        return self.request_json("PATCH", token, path_or_url, params=params, headers=headers, json_body=json_body)

    def get_collection(
        self,
        token: str,
        path: str,
        params: dict[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        next_target = path
        next_params = dict(params or {})
        remaining = limit

        while next_target:
            payload = self.get_object(token, next_target, params=next_params, headers=headers)
            next_params = None
            page_items = list(payload.get("value", []))

            if remaining is None:
                items.extend(page_items)
            else:
                items.extend(page_items[:remaining])
                remaining -= len(page_items[:remaining])
                if remaining <= 0:
                    break

            next_link = payload.get("@odata.nextLink")
            if not next_link:
                break
            next_target = next_link

        return items
