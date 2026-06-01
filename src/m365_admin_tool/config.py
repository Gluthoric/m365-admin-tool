from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import os


DEFAULT_GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"
DEFAULT_AUTHORITY_HOST = "https://login.microsoftonline.com"
DEFAULT_EXCHANGE_BASE_URL = "https://outlook.office365.com"
DEFAULT_TOKEN_CACHE_PATH = Path("~/.config/m365-admin-tool/token-cache.json").expanduser()
DEFAULT_DEVICE_FLOW_PATH = Path("~/.config/m365-admin-tool/device-flow.json").expanduser()
DEFAULT_TENANT_PROFILE_PATH = Path("~/.config/m365-admin-tool/tenants.json").expanduser()


class ConfigurationError(RuntimeError):
    pass


@dataclass(frozen=True)
class TenantProfile:
    name: str
    tenant_id: str
    client_id: str
    username: str | None = None
    client_secret: str | None = None
    access_token: str | None = None


def load_dotenv(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if value and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        values[key] = value
    return values


def merged_env(cwd: Path | None = None) -> dict[str, str]:
    current_dir = cwd or Path.cwd()
    values = load_dotenv(current_dir / ".env")
    values.update(os.environ)
    return values


def load_tenant_profiles(cwd: Path | None = None) -> tuple[list[TenantProfile], str | None, Path | None]:
    current_dir = cwd or Path.cwd()
    candidates = [
        current_dir / "tenants.json",
        DEFAULT_TENANT_PROFILE_PATH,
    ]
    selected_path = next((path for path in candidates if path.exists()), None)
    if selected_path is None:
        return [], None, None

    payload = json.loads(selected_path.read_text(encoding="utf-8"))
    if isinstance(payload, list):
        raw_profiles = payload
        default_name = None
    elif isinstance(payload, dict):
        raw_profiles = payload.get("profiles", [])
        default_name = payload.get("default")
    else:
        raise ConfigurationError(f"Invalid tenant profile file: {selected_path}")

    profiles: list[TenantProfile] = []
    for raw in raw_profiles:
        if not isinstance(raw, dict):
            raise ConfigurationError(f"Invalid tenant profile entry in {selected_path}")
        name = str(raw.get("name") or "").strip()
        tenant_id = str(raw.get("tenant_id") or raw.get("tenantId") or "").strip()
        client_id = str(raw.get("client_id") or raw.get("clientId") or "").strip()
        if not name or not tenant_id or not client_id:
            raise ConfigurationError(
                f"Each tenant profile in {selected_path} must include name, tenant_id, and client_id."
            )
        username = str(raw.get("username") or "").strip() or None
        client_secret = str(raw.get("client_secret") or raw.get("clientSecret") or "").strip() or None
        access_token = str(raw.get("access_token") or raw.get("accessToken") or "").strip() or None
        profiles.append(
            TenantProfile(
                name=name,
                tenant_id=tenant_id,
                client_id=client_id,
                username=username,
                client_secret=client_secret,
                access_token=access_token,
            )
        )

    return profiles, default_name, selected_path


@dataclass(frozen=True)
class Settings:
    profile_name: str | None
    tenant_id: str | None
    client_id: str | None
    client_secret: str | None
    username: str | None
    access_token: str | None
    graph_base_url: str
    exchange_base_url: str
    authority_host: str
    token_cache_path: Path
    device_flow_path: Path
    timeout_seconds: float

    @property
    def authority(self) -> str:
        if not self.tenant_id:
            raise ConfigurationError("M365_TENANT_ID is required unless M365_ACCESS_TOKEN is set.")
        return f"{self.authority_host.rstrip('/')}/{self.tenant_id}"

    def with_profile(self, profile: TenantProfile) -> "Settings":
        return Settings(
            profile_name=profile.name,
            tenant_id=profile.tenant_id,
            client_id=profile.client_id,
            client_secret=profile.client_secret or self.client_secret,
            username=profile.username or self.username,
            access_token=profile.access_token or self.access_token,
            graph_base_url=self.graph_base_url,
            exchange_base_url=self.exchange_base_url,
            authority_host=self.authority_host,
            token_cache_path=self.token_cache_path,
            device_flow_path=self.device_flow_path,
            timeout_seconds=self.timeout_seconds,
        )

    @classmethod
    def load(cls, cwd: Path | None = None) -> "Settings":
        env = merged_env(cwd)
        access_token = env.get("M365_ACCESS_TOKEN", "").strip() or None
        tenant_id = env.get("M365_TENANT_ID", "").strip() or None
        client_id = env.get("M365_CLIENT_ID", "").strip() or None
        client_secret = env.get("M365_CLIENT_SECRET", "").strip() or None
        username = env.get("M365_USERNAME", "").strip() or None

        if not access_token:
            missing: list[str] = []
            if not tenant_id:
                missing.append("M365_TENANT_ID")
            if not client_id:
                missing.append("M365_CLIENT_ID")
            if missing:
                joined = ", ".join(missing)
                raise ConfigurationError(
                    f"Missing required configuration: {joined}. Set them in .env or your shell."
                )

        token_cache_raw = env.get("M365_TOKEN_CACHE_PATH", "").strip()
        token_cache_path = Path(token_cache_raw).expanduser() if token_cache_raw else DEFAULT_TOKEN_CACHE_PATH

        device_flow_raw = env.get("M365_DEVICE_FLOW_PATH", "").strip()
        device_flow_path = Path(device_flow_raw).expanduser() if device_flow_raw else DEFAULT_DEVICE_FLOW_PATH

        timeout_raw = env.get("M365_TIMEOUT_SECONDS", "").strip()
        timeout_seconds = float(timeout_raw) if timeout_raw else 30.0

        graph_base_url = env.get("M365_GRAPH_BASE_URL", "").strip() or DEFAULT_GRAPH_BASE_URL
        exchange_base_url = env.get("M365_EXCHANGE_BASE_URL", "").strip() or DEFAULT_EXCHANGE_BASE_URL
        authority_host = env.get("M365_AUTHORITY_HOST", "").strip() or DEFAULT_AUTHORITY_HOST

        return cls(
            profile_name=None,
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
            username=username,
            access_token=access_token,
            graph_base_url=graph_base_url,
            exchange_base_url=exchange_base_url,
            authority_host=authority_host,
            token_cache_path=token_cache_path,
            device_flow_path=device_flow_path,
            timeout_seconds=timeout_seconds,
        )
