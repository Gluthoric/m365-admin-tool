from __future__ import annotations

from typing import Any
from urllib.parse import quote

from .graph import GraphClient

USER_SELECT = ",".join(
    (
        "id",
        "displayName",
        "userPrincipalName",
        "mail",
        "accountEnabled",
        "userType",
        "department",
        "jobTitle",
        "lastPasswordChangeDateTime",
        "createdDateTime",
    )
)

MFA_METHOD_TYPES = {
    "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod",
    "#microsoft.graph.phoneAuthenticationMethod",
    "#microsoft.graph.fido2AuthenticationMethod",
    "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod",
    "#microsoft.graph.softwareOathAuthenticationMethod",
    "#microsoft.graph.emailAuthenticationMethod",
    "#microsoft.graph.temporaryAccessPassAuthenticationMethod",
}


def fetch_user_profile(graph: GraphClient, token: str, identifier: str) -> dict[str, Any]:
    encoded = quote(identifier, safe="")
    return graph.get_object(token, f"users/{encoded}", params={"$select": USER_SELECT})


def fetch_user_license_details(graph: GraphClient, token: str, user_id: str, *, limit: int = 50) -> list[dict[str, Any]]:
    encoded = quote(user_id, safe="")
    return graph.get_collection(
        token,
        f"users/{encoded}/licenseDetails",
        params={"$top": str(min(limit, 100))},
        limit=limit,
    )


def fetch_user_memberships(graph: GraphClient, token: str, user_id: str, *, limit: int = 200) -> list[dict[str, Any]]:
    encoded = quote(user_id, safe="")
    return graph.get_collection(
        token,
        f"users/{encoded}/memberOf",
        params={"$top": str(min(limit, 200))},
        limit=limit,
    )


def fetch_user_auth_methods(graph: GraphClient, token: str, user_id: str, *, limit: int = 50) -> list[dict[str, Any]]:
    encoded = quote(user_id, safe="")
    return graph.get_collection(
        token,
        f"users/{encoded}/authentication/methods",
        params={"$top": str(min(limit, 100))},
        limit=limit,
    )


def normalize_auth_method_type(method: dict[str, Any]) -> str:
    raw = str(method.get("@odata.type") or "")
    if raw.startswith("#microsoft.graph."):
        raw = raw.split(".")[-1]
    return raw or "unknown"


def summarize_auth_methods(methods: list[dict[str, Any]]) -> dict[str, Any]:
    method_types = sorted({normalize_auth_method_type(item) for item in methods})
    has_mfa_method = any(str(item.get("@odata.type") or "") in MFA_METHOD_TYPES for item in methods)
    return {
        "count": len(methods),
        "methodTypes": method_types,
        "hasMfaMethod": has_mfa_method,
    }


def summarize_memberships(memberships: list[dict[str, Any]]) -> dict[str, Any]:
    roles: list[str] = []
    groups: list[str] = []
    other: list[str] = []

    for item in memberships:
        display_name = str(item.get("displayName") or item.get("id") or "")
        kind = str(item.get("@odata.type") or "").lower()
        if kind.endswith("directoryrole"):
            roles.append(display_name)
        elif kind.endswith("group"):
            groups.append(display_name)
        else:
            other.append(display_name)

    return {
        "directoryRoles": sorted(roles),
        "groups": sorted(groups),
        "otherMemberships": sorted(other),
        "groupCount": len(groups),
        "roleCount": len(roles),
    }


def summarize_licenses(licenses: list[dict[str, Any]]) -> dict[str, Any]:
    normalized = sorted({str(item.get("skuPartNumber") or item.get("skuId") or "") for item in licenses if item})
    return {
        "count": len(licenses),
        "licenses": normalized,
    }
