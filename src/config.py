# -*- coding: utf-8 -*-
#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2022 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

"""
Configuration management for Keeper Zoom Integration.

All configuration (Zoom credentials, Commander Service Mode URL / API key and
optional features) is read from a single YAML file. Unlike the Slack app,
Keeper Secrets Manager is not used.
"""

import os
import yaml
from typing import Dict, Any, Optional
from dataclasses import dataclass, field

from .logger import logger
from .utils import fix_service_url_for_docker, is_channel_jid


CONFIG_ENV_VAR = "ZOOM_CONFIG_PATH"

DEFAULT_CONFIG_PATHS = [
    "./zoom_config.yaml",
    "./config/zoom_config.yaml",
    "/app/config/zoom_config.yaml",
    os.path.expanduser("~/.keeper/zoom_config.yaml"),
]


@dataclass
class ZoomConfig:
    """Zoom General App (Team Chat chatbot) configuration."""

    client_id: str
    """App Credentials -> Client ID"""

    client_secret: str
    """App Credentials -> Client Secret"""

    bot_jid: str
    """Features -> Surface -> Team Chat Subscription -> Bot JID"""

    secret_token: str
    """Features -> Access -> Secret Token (verifies x-zm-signature)"""

    approvals_channel_jid: str
    """Channel JID where approval requests are posted (<id>@conference.xmpp.zoom.us)"""

    oauth_redirect_url: Optional[str] = None
    """OAuth Redirect URL configured on the app (stores the adding user's token for email lookup)"""

    user_emails: Dict[str, str] = field(default_factory=dict)
    """Optional Zoom user ID (or JID) -> email, used before Zoom API lookups"""


@dataclass
class ServerConfig:
    """Webhook HTTP server configuration."""

    host: str = "0.0.0.0"
    port: int = 3000
    worker_threads: int = 8


@dataclass
class KeeperConfig:
    """Keeper Service Mode configuration."""

    service_url: str
    """URL of Keeper Commander Service Mode server"""

    api_key: Optional[str] = None
    """API key for authenticating with Service Mode"""


@dataclass
class MultiChannelApproverConfig:
    """Team-based multi-channel approver routing configuration."""

    enabled: bool = False
    """When False, all approval requests go to the default approvals channel."""

    teams: Dict[str, str] = field(default_factory=dict)
    """Mapping of Keeper team name -> Zoom approval channel JID."""


class Config:
    """
    Application configuration manager (YAML only).
    """

    def __init__(self, config_path: Optional[str] = None):
        self._data: Dict[str, Any] = {}
        self.source_file: Optional[str] = None

        path = self._resolve_path(config_path)
        if path:
            self._load_from_file(path)

        self._validate()

    @staticmethod
    def _resolve_path(config_path: Optional[str]) -> Optional[str]:
        """Pick the config file: explicit path, then $ZOOM_CONFIG_PATH, then defaults."""
        candidates = []
        if config_path:
            candidates.append(config_path)
        env_path = os.environ.get(CONFIG_ENV_VAR)
        if env_path:
            candidates.append(env_path)
        candidates.extend(DEFAULT_CONFIG_PATHS)

        for path in candidates:
            if path and os.path.isfile(path):
                return path
        return None

    def _load_from_file(self, config_path: str):
        """Load configuration from YAML file."""
        try:
            with open(config_path, 'r') as f:
                file_config = yaml.safe_load(f)
            if file_config:
                self._data.update(file_config)
                self.source_file = config_path
                logger.info(f"Loaded configuration from {config_path}")
        except Exception as e:
            raise ValueError(f"Could not load config file {config_path}: {e}")

    @staticmethod
    def _is_placeholder(value: str) -> bool:
        """True for empty values and the placeholders in zoom_config.example.yaml."""
        v = value.strip().lower()
        return not v or "your_" in v or "your-" in v or "xxxxxxxx" in v or "<public-host>" in v

    def _validate(self):
        """Validate required configuration fields."""
        required_fields = [
            ('zoom', 'client_id'),
            ('zoom', 'client_secret'),
            ('zoom', 'bot_jid'),
            ('zoom', 'secret_token'),
            ('keeper', 'service_url'),
            ('keeper', 'api_key'),
        ]

        missing = []
        for section, key in required_fields:
            value = (self._data.get(section) or {}).get(key)
            if not value or self._is_placeholder(str(value)):
                missing.append(f"{section}.{key}")

        if missing:
            where = self.source_file or "zoom_config.yaml (not found)"
            raise ValueError(
                f"Missing required configuration in {where}: {', '.join(missing)}\n\n"
                f"Copy zoom_config.example.yaml to zoom_config.yaml and fill in the values, "
                f"or point ${CONFIG_ENV_VAR} at your config file."
            )

        # The approvals channel is not required to start: on first setup the
        # app is run so /keeper request-record can report the channel's JID.
        channel = self.zoom.approvals_channel_jid
        if not channel:
            logger.warning(
                "zoom.approvals_channel_jid is not set. Run /keeper request-record in the "
                "approvals channel to get its JID, then add it to the config and restart."
            )
        elif not is_channel_jid(channel) or channel.count("@") != 1:
            raise ValueError(
                f"zoom.approvals_channel_jid '{channel}' is not a channel JID.\n\n"
                f"It must look like '<channel id>@conference.xmpp.zoom.us'. A JID ending in "
                f"'@xmpp.zoom.us' is a user, not a channel. Run /keeper request-record inside "
                f"the approvals channel (with the app added) to get the channel's JID."
            )

    @property
    def zoom(self) -> ZoomConfig:
        """Get Zoom configuration."""
        z = self._data['zoom']
        return ZoomConfig(
            client_id=str(z['client_id']).strip(),
            client_secret=str(z['client_secret']).strip(),
            bot_jid=str(z['bot_jid']).strip(),
            secret_token=str(z['secret_token']).strip(),
            approvals_channel_jid=(
                "" if self._is_placeholder(str(z.get('approvals_channel_jid') or ""))
                else str(z['approvals_channel_jid']).strip()
            ),
            oauth_redirect_url=(str(z['oauth_redirect_url']).strip() if z.get('oauth_redirect_url') else None),
            user_emails={
                str(k).strip(): str(v).strip()
                for k, v in (z.get('user_emails') or {}).items() if k and v
            },
        )

    @property
    def server(self) -> ServerConfig:
        """Get webhook server configuration."""
        s = self._data.get('server', {}) or {}
        return ServerConfig(
            host=str(s.get('host', '0.0.0.0')),
            port=int(s.get('port', 3000)),
            worker_threads=int(s.get('worker_threads', 8)),
        )

    @property
    def keeper(self) -> KeeperConfig:
        """Get Keeper Commander Service Mode configuration."""
        k = self._data['keeper']
        return KeeperConfig(
            service_url=fix_service_url_for_docker(str(k['service_url']).strip()).rstrip('/'),
            api_key=str(k.get('api_key')).strip() if k.get('api_key') else None,
        )

    @property
    def multichannel_approver(self) -> MultiChannelApproverConfig:
        """
        Get team-based multi-channel approver routing configuration.

        Expected YAML shape (optional section; absence => disabled):

            multichannel_approver:
              enabled: true
              teams:
                - name: "Developer Team"
                  channel_jid: "abc123@conference.xmpp.zoom.us"
        """
        mc_data = self._data.get('multichannel_approver', {}) or {}
        teams_map: Dict[str, str] = {}
        for entry in (mc_data.get('teams', []) or []):
            if not isinstance(entry, dict):
                continue
            name = entry.get('name')
            channel_jid = entry.get('channel_jid')
            if name and channel_jid:
                teams_map[str(name).strip()] = str(channel_jid).strip()
        return MultiChannelApproverConfig(
            enabled=bool(mc_data.get('enabled', False)),
            teams=teams_map,
        )

    @property
    def allow_self_approval(self) -> bool:
        """
        Testing only: let a requester approve their own request (single-user
        test accounts). Off by default, as in the Slack app.
        """
        return bool((self._data.get('approvals', {}) or {}).get('allow_self_approval', False))

    @property
    def data_dir(self) -> str:
        """Directory for persisted state (pending approvals, Zoom OAuth token)."""
        path = (self._data.get('storage', {}) or {}).get('data_dir') or './data'
        return os.path.abspath(os.path.expanduser(path))

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by key."""
        return self._data.get(key, default)
