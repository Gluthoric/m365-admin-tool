# Microsoft Graph and Exchange Permissions Reference

A complete reference for the Graph and Exchange Admin permissions `m365-admin-tool` uses, what role context each one needs, and how to consent them. The tool fails loudly when a scope is missing rather than producing partial results, so granting everything up front is worth the few minutes.

## Delegated Graph scopes

Use these for interactive operator workflows (device-code auth, signed-in admin).

| Scope                                    | What it enables                                       | Required for                                                     |
| ---------------------------------------- | ----------------------------------------------------- | ---------------------------------------------------------------- |
| `User.Read`                              | Sign-in itself, profile lookup of the signed-in admin | All commands                                                     |
| `User.Read.All`                          | Read other users in the tenant                        | All target-user lookups                                          |
| `User.ReadWrite.All`                     | Mutate user properties                                | `contain` (revoke sessions, block sign-in, force password reset) |
| `AuditLog.Read.All`                      | Sign-in logs, directory audits                        | `signins`, `audits`, `diagnose`, `timeline`                      |
| `MailboxSettings.Read`                   | Inbox rules, mailbox forwarding config (read)         | `rules`, `diagnose`, `outbound-review`                           |
| `MailboxSettings.ReadWrite`              | Inbox rule edits, forwarding clear                    | `contain`                                                        |
| `Mail.Read`                              | Sent Items, Deleted Items, message bodies             | `messages`, `outbound-review`, `diagnose`                        |
| `Directory.Read.All`                     | Enterprise app and OAuth consent review               | `apps`, `diagnose`, `outbound-review`                            |
| `DelegatedPermissionGrant.ReadWrite.All` | Revoke OAuth permission grants                        | `contain` (remove OAuth grants)                                  |
| `IdentityRiskEvent.Read.All`             | Risk detections                                       | `risk`, risky-user verdict in `diagnose`                         |
| `UserAuthenticationMethod.Read.All`      | List MFA methods                                      | `diagnose`, `contain` (re-MFA prep)                              |
| `UserAuthenticationMethod.ReadWrite.All` | Reset MFA methods                                     | `contain` (re-MFA)                                               |
| `ExchangeMessageTrace.Read.All`          | Outbound message trace                                | `trace`, `outbound-review`, `diagnose`                           |

## Application Graph permissions

Use these for app-only flows (client-secret or client-certificate). Required when delegated auth cannot read another user's mailbox.

| Permission                      | Why you'd want it                                                   |
| ------------------------------- | ------------------------------------------------------------------- |
| `Mail.Read`                     | Cross-user mailbox review without a delegated grant from the target |
| `MailboxSettings.Read`          | Cross-user inbox rule and forwarding review                         |
| `Directory.Read.All`            | Tenant-wide enterprise app inventory                                |
| `AuditLog.Read.All`             | Tenant-wide sign-in and directory audit access                      |
| `ExchangeMessageTrace.Read.All` | Tenant-wide message trace                                           |

## Exchange Admin API permissions

The Exchange Online admin REST API is separate from Graph and uses its own permission model.

| Permission               | What it enables                                                                        |
| ------------------------ | -------------------------------------------------------------------------------------- |
| `Exchange.ManageV2`      | Delegated Exchange Admin cmdlet access (Get-Mailbox, Get-InboxRule, Set-Mailbox, etc.) |
| `Exchange.ManageAsAppV2` | App-only Exchange Admin cmdlet access (same surface, app-only auth)                    |

The tool degrades gracefully when neither is present: mailbox delegate, send-on-behalf, and inbox-rule-by-cmdlet checks turn into `unavailableEvidence` entries in `diagnose` rather than aborting the run.

## Entra admin role context

Scope grants alone are not always enough; the signed-in admin also needs an Entra role that effectively allows the read or write.

| Role                                        | Covers                                                                                  |
| ------------------------------------------- | --------------------------------------------------------------------------------------- |
| **Global Reader**                           | Most read paths (sign-ins, audits, user profile, group membership)                      |
| **Exchange Administrator**                  | Mailbox config, inbox rules, mailbox forwarding (Exchange Admin API)                    |
| **User Administrator**                      | `User.ReadWrite.All` write paths — revoke sessions, force password reset, block sign-in |
| **Authentication Administrator**            | MFA method reset                                                                        |
| **Privileged Authentication Administrator** | MFA reset on other admins (rare; usually not needed for end-user triage)                |
| **Cloud Application Administrator**         | OAuth grant management                                                                  |

For a generic compromised-user response role, **Global Reader + User Administrator + Exchange Administrator** is the practical combination. Skip Global Admin — incident response doesn't need it, and standing Global Admin is a separate compliance problem.

## App registration setup

To use this tool you need exactly one public-client app registration in the tenant. Suggested configuration:

1. Entra ID → App registrations → New registration
2. Name: `m365-admin-tool` (or whatever you like)
3. Supported account types: **Single tenant**
4. Redirect URI: leave blank (device code flow doesn't need one)
5. After creation, **Authentication → Allow public client flows → Yes**
6. **API permissions** → Add the delegated scopes listed above → Grant admin consent
7. (Optional) **Certificates & secrets** → New client secret if you want to support app-only auth for cross-user mailbox review

Copy the **Application (client) ID** and **Directory (tenant) ID** into `.env` as `M365_CLIENT_ID` and `M365_TENANT_ID`.

## Consent workflow

Admin consent for delegated scopes:

1. App registration → API permissions
2. Click **Grant admin consent for `<tenant>`**
3. Sign in as a Global Admin or Privileged Role Administrator
4. The grant becomes tenant-wide; individual users no longer need to consent

Without admin consent, the first user to run `m365-admin login` is prompted to consent on behalf of themselves, which works but produces uneven coverage across operators. Granting admin consent is one click and removes a class of "it works on my machine" problems.

## Troubleshooting

**`Authorization_RequestDenied` on `revokeSignInSessions`** — you have the scope but the role doesn't allow the write. Most often: signed in as Global Reader, need User Administrator.

**`PrincipalNotFound` on message trace right after creating the app registration** — the Transport Data Platform service principal hasn't propagated yet. Wait 5–30 minutes; `doctor --fix` can sometimes trigger it. Re-run `doctor` to confirm.

**`InvalidAuthenticationToken` on Exchange Admin API** — likely a scope mismatch. Exchange Admin needs its own audience (`https://outlook.office365.com`), not the Graph audience. `auth.py` handles this automatically; if you've manually injected a token via `M365_ACCESS_TOKEN`, make sure it's the Exchange one for Exchange calls.

**`Throttled` (HTTP 429)** — the client honors `Retry-After`. If you're seeing it consistently, you're probably running `investigate --days 30` against a large tenant; chunk the window down.
