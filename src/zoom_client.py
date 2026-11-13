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
Zoom Team Chat API client (replaces Slack's WebClient).

- Chatbot token: ``client_credentials`` grant, valid 1 hour, cached.
- Messages: ``POST/PUT /v2/im/chat/messages``.
- User email lookup (user-managed app): ``GET /v2/users/me`` with the OAuth
  token stored when the user adds the app (``/zoom/oauth/callback``). That
  token can only read its owner, so other users need ``zoom.user_emails``.
"""

import base64
import hashlib
import hmac
import json
import os
import threading
import time
from typing import Any, Dict, Optional
from urllib.parse import quote

import requests

from .config import ZoomConfig
from .logger import logger


OAUTH_TOKEN_URL = "https://zoom.us/oauth/token"
API_BASE_URL = "https://api.zoom.us/v2"

# Reject webhook requests whose timestamp is older than this (replay protection)
MAX_REQUEST_AGE_SECONDS = 300


class ZoomAPIError(Exception):
    """Raised when a Zoom API call fails."""

    def __init__(self, message: str, status_code: Optional[int] = None, body: Any = None):
        super().__init__(message)
        self.status_code = status_code
        self.body = body


def verify_webhook_signature(
    secret_token: str,
    raw_body: bytes,
    timestamp: Optional[str],
    signature: Optional[str],
    now: Optional[float] = None,
) -> bool:
    """
    Verify Zoom's ``x-zm-signature`` header.

    ``signature == "v0=" + HMAC_SHA256_hex(secret_token, "v0:{timestamp}:{body}")``
    """
    if not timestamp or not signature:
        return False

    try:
        ts = int(timestamp)
        # Zoom sends milliseconds on some products and seconds on others
        if ts > 10_000_000_000:
            ts //= 1000
    except ValueError:
        return False

    current = now if now is not None else time.time()
    if abs(current - ts) > MAX_REQUEST_AGE_SECONDS:
        logger.warning("Rejected Zoom webhook: timestamp outside allowed window")
        return False

    message = b"v0:" + timestamp.encode() + b":" + raw_body
    expected = "v0=" + hmac.new(secret_token.encode(), message, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def url_validation_response(secret_token: str, plain_token: str) -> Dict[str, str]:
    """Build the response to Zoom's ``endpoint.url_validation`` challenge."""
    encrypted = hmac.new(secret_token.encode(), plain_token.encode(), hashlib.sha256).hexdigest()
    return {"plainToken": plain_token, "encryptedToken": encrypted}


class ZoomClient:
    """
    Thin wrapper over the Zoom Team Chat chatbot REST API.
    """

    def __init__(self, config: ZoomConfig, data_dir: str):
        self.config = config
        self.session = requests.Session()

        self._lock = threading.Lock()
        self._bot_token: Optional[str] = None
        self._bot_token_expires_at: float = 0

        os.makedirs(data_dir, exist_ok=True)
        self._user_token_path = os.path.join(data_dir, "zoom_oauth_token.json")
        self._email_cache: Dict[str, str] = {}

    # ------------------------------------------------------------------
    # Tokens
    # ------------------------------------------------------------------

    def _basic_auth_header(self) -> Dict[str, str]:
        creds = f"{self.config.client_id}:{self.config.client_secret}".encode()
        return {"Authorization": "Basic " + base64.b64encode(creds).decode()}

    def get_bot_token(self) -> str:
        """Return a cached chatbot token, requesting a new one ~60s before expiry."""
        with self._lock:
            if self._bot_token and time.time() < self._bot_token_expires_at - 60:
                return self._bot_token

            response = self.session.post(
                OAUTH_TOKEN_URL,
                params={"grant_type": "client_credentials"},
                headers=self._basic_auth_header(),
                timeout=10,
            )
            if response.status_code != 200:
                raise ZoomAPIError(
                    f"Failed to get Zoom chatbot token: HTTP {response.status_code} {response.text[:200]}",
                    response.status_code,
                )
            data = response.json()
            self._bot_token = data["access_token"]
            self._bot_token_expires_at = time.time() + int(data.get("expires_in", 3600))
            logger.debug("Obtained new Zoom chatbot token")
            return self._bot_token

    def _load_user_token(self) -> Optional[Dict[str, Any]]:
        if not os.path.exists(self._user_token_path):
            return None
        try:
            with open(self._user_token_path, "r") as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Could not read stored Zoom OAuth token: {e}")
            return None

    def _save_user_token(self, data: Dict[str, Any]):
        token = {
            "access_token": data["access_token"],
            "refresh_token": data.get("refresh_token"),
            "expires_at": time.time() + int(data.get("expires_in", 3600)),
            "scope": data.get("scope", ""),
        }
        tmp_path = self._user_token_path + ".tmp"
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(token, f)
        os.replace(tmp_path, self._user_token_path)

    def exchange_oauth_code(self, code: str, redirect_uri: str) -> bool:
        """
        Exchange the ``code`` Zoom sends to the OAuth Redirect URL when the
        user adds the app, and store the token for user email lookups.
        """
        response = self.session.post(
            OAUTH_TOKEN_URL,
            params={"grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri},
            headers=self._basic_auth_header(),
            timeout=10,
        )
        if response.status_code != 200:
            logger.error(f"Zoom OAuth code exchange failed: HTTP {response.status_code} {response.text[:200]}")
            return False
        data = response.json()
        with self._lock:
            self._save_user_token(data)
        logger.ok(f"Stored Zoom OAuth token (scopes: {data.get('scope', '')})")
        return True

    def has_user_token(self) -> bool:
        return self._load_user_token() is not None

    def _get_user_token(self) -> Optional[str]:
        """Return the stored OAuth token, refreshing it when expired."""
        with self._lock:
            token = self._load_user_token()
            if not token:
                return None
            if time.time() < token.get("expires_at", 0) - 60:
                return token["access_token"]
            if not token.get("refresh_token"):
                return None

            response = self.session.post(
                OAUTH_TOKEN_URL,
                params={"grant_type": "refresh_token", "refresh_token": token["refresh_token"]},
                headers=self._basic_auth_header(),
                timeout=10,
            )
            if response.status_code != 200:
                logger.error(
                    f"Zoom OAuth token refresh failed: HTTP {response.status_code}. "
                    f"Re-add the app (Local Test -> Add App Now) to issue a new token."
                )
                return None
            data = response.json()
            self._save_user_token(data)
            return data["access_token"]

    # ------------------------------------------------------------------
    # Users
    # ------------------------------------------------------------------

    def _mapped_email(self, user_id: str) -> Optional[str]:
        """Email from ``zoom.user_emails`` (keys: Zoom user ID or user JID, case-insensitive)."""
        wanted = {user_id.lower(), f"{user_id.lower()}@xmpp.zoom.us"}
        for key, email in self.config.user_emails.items():
            if key.lower() in wanted:
                return email
        return None

    def _email_of_token_owner(self, token: str, user_id: str) -> Optional[str]:
        """
        ``GET /users/me``: returns the email only if the token belongs to
        ``user_id`` (matched on user ID or JID), so it never returns someone else's email.
        """
        try:
            response = self.session.get(
                f"{API_BASE_URL}/users/me",
                headers={"Authorization": f"Bearer {token}"},
                timeout=10,
            )
            if response.status_code != 200:
                logger.debug(f"/users/me returned HTTP {response.status_code}: {response.text[:200]}")
                return None
            me = response.json()
            me_ids = {str(me.get("id", "")).lower(), str(me.get("jid", "")).split("@")[0].lower()}
            if user_id.lower() in me_ids and me.get("email"):
                logger.info(f"Resolved Zoom user {user_id} to email via /users/me: {me['email']}")
                self._email_cache[user_id] = me["email"]
                return me["email"]
            logger.debug(f"/users/me belongs to a different user than {user_id}")
        except Exception as e:
            logger.warning(f"/users/me lookup failed: {e}")
        return None

    def get_user_email(self, user_id: str, hint: Optional[str] = None) -> Optional[str]:
        """
        Resolve a Zoom user's email (used as their Keeper username).

        Order: email included in the event payload, ``zoom.user_emails`` in
        the config, cache, ``/users/me`` with the stored token (the user who
        added the app), then ``/users/{id}`` with the stored and chatbot tokens.
        """
        if hint and "@" in hint:
            self._email_cache[user_id] = hint
            return hint
        mapped = self._mapped_email(user_id)
        if mapped:
            return mapped
        if user_id in self._email_cache:
            return self._email_cache[user_id]

        tokens = []
        user_token = self._get_user_token()
        if user_token:
            email = self._email_of_token_owner(user_token, user_id)
            if email:
                return email
            tokens.append(("oauth", user_token))
        try:
            tokens.append(("bot", self.get_bot_token()))
        except ZoomAPIError as e:
            logger.warning(f"Could not get chatbot token for user lookup: {e}")

        for kind, token in tokens:
            try:
                response = self.session.get(
                    f"{API_BASE_URL}/users/{quote(user_id, safe='')}",
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=10,
                )
                if response.status_code == 200:
                    email = response.json().get("email")
                    if email:
                        logger.info(f"Resolved Zoom user {user_id} to email: {email}")
                        self._email_cache[user_id] = email
                        return email
                logger.debug(
                    f"User lookup with {kind} token returned HTTP {response.status_code}: "
                    f"{response.text[:200]}"
                )
            except Exception as e:
                logger.warning(f"User lookup with {kind} token failed: {e}")

        logger.warning(
            f"Could not resolve email for Zoom user {user_id}. A user-managed app can only "
            f"look up the user who added it; map other users in zoom.user_emails "
            f"(\"{user_id}\": \"<keeper email>\")."
        )
        return None

    # ------------------------------------------------------------------
    # Messages
    # ------------------------------------------------------------------

    def _post(self, method: str, path: str, body: Dict[str, Any]) -> requests.Response:
        token = self.get_bot_token()
        response = self.session.request(
            method,
            f"{API_BASE_URL}{path}",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json=body,
            timeout=10,
        )
        if response.status_code == 401:
            # Token revoked early; retry once with a fresh one
            with self._lock:
                self._bot_token = None
            token = self.get_bot_token()
            response = self.session.request(
                method,
                f"{API_BASE_URL}{path}",
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                json=body,
                timeout=10,
            )
        return response

    def send_message(
        self,
        to_jid: str,
        content: Dict[str, Any],
        user_jid: str,
        account_id: str,
    ) -> str:
        """Send a chatbot message. Returns the Zoom ``message_id``."""
        body: Dict[str, Any] = {
            "robot_jid": self.config.bot_jid,
            "to_jid": to_jid,
            "account_id": account_id,
            "user_jid": user_jid,
            "is_markdown_support": True,
            "content": content,
        }

        response = self._post("POST", "/im/chat/messages", body)
        if response.status_code not in (200, 201):
            raise ZoomAPIError(
                f"Zoom send message failed: HTTP {response.status_code} {response.text[:300]}",
                response.status_code, response.text,
            )
        return (response.json() or {}).get("message_id", "")

    def edit_message(
        self,
        message_id: str,
        to_jid: str,
        content: Dict[str, Any],
        user_jid: str,
        account_id: str,
    ) -> None:
        """Replace the content of a message previously sent by the chatbot."""
        body = {
            "robot_jid": self.config.bot_jid,
            "to_jid": to_jid,
            "account_id": account_id,
            "user_jid": user_jid,
            "is_markdown_support": True,
            "content": content,
        }
        response = self._post("PUT", f"/im/chat/messages/{quote(message_id, safe='')}", body)
        if response.status_code not in (200, 204):
            raise ZoomAPIError(
                f"Zoom edit message failed: HTTP {response.status_code} {response.text[:300]}",
                response.status_code, response.text,
            )

    def send_dm(self, user_jid: str, content: Dict[str, Any], account_id: str) -> bool:
        """Send a message to the user's 1:1 chat with the bot."""
        try:
            self.send_message(to_jid=user_jid, content=content, user_jid=user_jid, account_id=account_id)
            logger.info(f"DM sent to user {user_jid}")
            return True
        except Exception as e:
            logger.error(f"Failed to send DM to {user_jid}: {e}")
            return False

    def send_ephemeral(
        self,
        user_jid: str,
        content: Dict[str, Any],
        account_id: str,
    ) -> bool:
        """Reply only to ``user_jid`` by DM (user-managed apps can't send ``visible_to_user``)."""
        return self.send_dm(user_jid, content, account_id=account_id)
