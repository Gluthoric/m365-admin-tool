from __future__ import annotations

from typing import Any
from urllib.parse import quote

from .exchange_admin import ExchangeAdminClient
from .graph import GraphClient
from .identity import fetch_user_auth_methods, fetch_user_profile
from .investigation import fetch_inbox_rules, summarize_rule


def list_authentication_methods(graph: GraphClient, token: str, *, identifier: str) -> list[dict[str, Any]]:
    user = fetch_user_profile(graph, token, identifier)
    user_id = str(user.get("id") or "")
    if not user_id:
        return []
    return fetch_user_auth_methods(graph, token, user_id)


def revoke_sign_in_sessions(graph: GraphClient, token: str, *, identifier: str) -> dict[str, Any]:
    encoded = quote(identifier, safe="")
    return graph.post_object(token, f"users/{encoded}/revokeSignInSessions", json_body={})


def block_user_sign_in(graph: GraphClient, token: str, *, identifier: str) -> dict[str, Any]:
    encoded = quote(identifier, safe="")
    return graph.patch_object(token, f"users/{encoded}", json_body={"accountEnabled": False})


def disable_inbox_rule(graph: GraphClient, token: str, *, identifier: str, rule_id: str) -> dict[str, Any]:
    encoded_identifier = quote(identifier, safe="")
    encoded_rule_id = quote(rule_id, safe="")
    return graph.patch_object(
        token,
        f"users/{encoded_identifier}/mailFolders/inbox/messageRules/{encoded_rule_id}",
        json_body={"isEnabled": False},
    )


def disable_mailbox_forwarding(exchange: ExchangeAdminClient, token: str, *, identifier: str) -> list[dict[str, Any]]:
    return exchange.run_cmdlet(
        token,
        "Mailbox",
        anchor_mailbox=identifier,
        cmdlet_name="Set-Mailbox",
        parameters={
            "Identity": identifier,
            "ForwardingAddress": None,
            "ForwardingSmtpAddress": None,
            "DeliverToMailboxAndForward": False,
        },
    )


def list_suspicious_rules(graph: GraphClient, token: str, *, identifier: str) -> list[dict[str, Any]]:
    suspicious: list[dict[str, Any]] = []
    for rule in fetch_inbox_rules(graph, token, identifier):
        summary = summarize_rule(rule)
        if any(token in summary["actions"] for token in ("forwardTo", "redirectTo", "forwardAsAttachmentTo", "delete", "stopProcessingRules")):
            suspicious.append(rule)
    return suspicious
