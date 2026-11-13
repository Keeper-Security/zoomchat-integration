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
Keeper Zoom App - webhook server.

Slack delivers events over Socket Mode; Zoom POSTs them to the Bot Endpoint
URL. Every request is verified with the Secret Token (``x-zm-signature``),
acknowledged immediately (Zoom expects a reply within 3 seconds, like Slack's
``ack()``), and handled on a worker thread.

Routes:
    POST /zoom/webhook         slash commands, button clicks, dropdowns, app events
    GET  /zoom/oauth/callback  OAuth Redirect URL (stores the user's token for email lookup)
    GET  /health               liveness probe
"""

import json
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Dict, Optional

from flask import Flask, jsonify, request

from .approval_store import ApprovalStore
from .commands import handle_command
from .config import Config
from .handlers import handle_form_submit, handle_interactive_action, handle_interactive_select
from .keeper_client import KeeperClient
from .logger import logger
from .views import build_usage_content
from .zoom_client import ZoomClient, url_validation_response, verify_webhook_signature


class KeeperZoomApp:
    """
    Keeper Commander Zoom Team Chat Application.
    """

    def __init__(
        self,
        config_path: Optional[str] = None,
        config: Optional[Config] = None,
        keeper_client=None,
        zoom_client=None,
        store: Optional[ApprovalStore] = None,
        run_async: bool = True,
    ):
        logger.info("Initializing Keeper Commander Zoom App...")

        self.config = config or Config(config_path)
        logger.ok("Configuration loaded")

        self.keeper_client = keeper_client or KeeperClient(self.config.keeper)
        logger.ok(f"Keeper client initialized: {self.config.keeper.service_url}")

        self.zoom_client = zoom_client or ZoomClient(self.config.zoom, self.config.data_dir)
        self.store = store or ApprovalStore(self.config.data_dir)
        logger.ok("Zoom client initialized")

        self.run_async = run_async
        self.executor = ThreadPoolExecutor(
            max_workers=self.config.server.worker_threads, thread_name_prefix="zoom-event"
        )

        self.flask_app = Flask(__name__)
        self._register_routes()
        logger.ok("All handlers registered")
        logger.info(f"Approval channel: {self.config.zoom.approvals_channel_jid}")
        mc = self.config.multichannel_approver
        if mc.enabled:
            logger.info(f"Multi-channel approver routing enabled for {len(mc.teams)} team(s)")

    # ------------------------------------------------------------------
    # Event dispatch
    # ------------------------------------------------------------------

    def _dispatch(self, fn: Callable, payload: Dict[str, Any]):
        def run():
            try:
                fn(payload, self.zoom_client, self.config, self.keeper_client, self.store)
            except Exception as e:
                logger.error(f"Unhandled error in {fn.__name__}: {e}", exc_info=True)

        if self.run_async:
            self.executor.submit(run)
        else:
            run()

    def _handle_bot_installed(self, payload, zoom_client, config, keeper_client, store):
        user_jid = payload.get("userJid")
        if user_jid:
            zoom_client.send_dm(user_jid, build_usage_content(), payload.get("accountId"))

    def handle_event(self, event: Dict[str, Any]):
        """Route a verified Zoom event to its handler."""
        event_type = event.get("event")
        payload = event.get("payload") or {}
        robot_jid = payload.get("robotJid")
        logger.debug(f"Received Zoom event: {event_type} (robotJid: {robot_jid})")

        if robot_jid and robot_jid.lower() != self.config.zoom.bot_jid.lower():
            logger.warning(
                f"Event is for bot {robot_jid} but zoom.bot_jid is {self.config.zoom.bot_jid}. "
                f"Messages are being sent as a different bot (e.g. Production vs Development "
                f"Bot JID); set zoom.bot_jid to {robot_jid}."
            )

        if event_type == "bot_notification":
            # Slash command, or a message typed in the bot's 1:1 chat
            logger.info(
                f"Command from {payload.get('userName')} in "
                f"{payload.get('channelName') or '1:1 chat'} (toJid: {payload.get('toJid')})"
            )
            self._dispatch(handle_command, payload)
        elif event_type == "interactive_message_actions":
            self._dispatch(handle_interactive_action, payload)
        elif event_type == "interactive_message_select":
            self._dispatch(handle_interactive_select, payload)
        elif event_type == "chat_message.submit":
            self._dispatch(handle_form_submit, payload)
        elif event_type == "bot_installed":
            self._dispatch(self._handle_bot_installed, payload)
        elif event_type in ("app_deauthorized", "team_chat.app_uninstalled"):
            logger.warning(f"Zoom app removed from account ({event_type})")
        else:
            logger.debug(f"Ignoring Zoom event: {event_type}")

    # ------------------------------------------------------------------
    # HTTP routes
    # ------------------------------------------------------------------

    def _register_routes(self):
        app = self.flask_app
        secret_token = self.config.zoom.secret_token

        @app.get("/health")
        def health():
            return jsonify({"status": "ok"})

        @app.post("/zoom/webhook")
        def webhook():
            raw_body = request.get_data()
            if not verify_webhook_signature(
                secret_token,
                raw_body,
                request.headers.get("x-zm-request-timestamp"),
                request.headers.get("x-zm-signature"),
            ):
                logger.warning("Rejected Zoom webhook with missing/invalid signature")
                return jsonify({"error": "invalid signature"}), 401

            try:
                event = json.loads(raw_body or b"{}")
            except ValueError:
                return jsonify({"error": "invalid json"}), 400

            if event.get("event") == "endpoint.url_validation":
                plain_token = (event.get("payload") or {}).get("plainToken", "")
                logger.info("Answered Zoom endpoint URL validation")
                return jsonify(url_validation_response(secret_token, plain_token))

            self.handle_event(event)
            return jsonify({"status": "received"})

        @app.get("/zoom/oauth/callback")
        def oauth_callback():
            code = request.args.get("code")
            if not code:
                return "Missing ?code parameter.", 400
            redirect_uri = self.config.zoom.oauth_redirect_url or request.base_url
            if self.zoom_client.exchange_oauth_code(code, redirect_uri):
                return (
                    "<h3>Keeper Security app added.</h3>"
                    "<p>You can close this window and use /keeper request-record in Zoom Team Chat.</p>"
                )
            return "Could not complete authorization. Check the app logs.", 500

    # ------------------------------------------------------------------
    # Start
    # ------------------------------------------------------------------

    def start(self):
        """Start the webhook server."""
        from waitress import serve

        server = self.config.server
        print("\n" + "=" * 60)
        print("Starting Keeper Commander Zoom App")
        print("=" * 60)
        logger.info(f"Listening on http://{server.host}:{server.port}/zoom/webhook")

        if self.keeper_client.health_check():
            logger.ok("Keeper Service Mode is accessible")
        else:
            logger.warning("Cannot reach Keeper Service Mode")
            print(f"   URL: {self.config.keeper.service_url}")
            print("   The app will start but commands may fail.\n")

        try:
            self.zoom_client.get_bot_token()
            logger.ok("Zoom chatbot token obtained")
        except Exception as e:
            logger.warning(f"Could not get Zoom chatbot token: {e}")

        if not self.zoom_client.has_user_token():
            logger.warning(
                "No Zoom OAuth token stored yet. Requester emails are looked up with it; "
                "add/re-add the app so Zoom redirects to /zoom/oauth/callback."
            )
        print("=" * 60 + "\n")

        try:
            serve(self.flask_app, host=server.host, port=server.port, threads=server.worker_threads)
        except KeyboardInterrupt:
            logger.info("Shutting down Keeper Zoom App...")
        finally:
            self.executor.shutdown(wait=False)
