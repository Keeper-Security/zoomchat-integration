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
Routes ``/keeper <sub-command> ...`` (one Zoom slash command per app) to its
handler. The slash command name itself is not in the payload, so a dev app
with a different command name (e.g. ``/keeperdemo``) works the same way.
"""

from typing import Any, Dict

from ..logger import logger
from ..models import RequestType
from ..utils import is_channel_jid
from ..views import build_usage_content, text_content
from .request_access import handle_access_request

ACCESS_SUBCOMMANDS = {
    "request-record": RequestType.RECORD,
    "request_record": RequestType.RECORD,
    "request-folder": RequestType.FOLDER,
    "request_folder": RequestType.FOLDER,
}
HELP_SUBCOMMANDS = ("", "help", "-h", "--help")
PLANNED_SUBCOMMANDS = (
    "one-time-share", "self-destructing-share", "create-record", "create-secret", "request-pamworkflow",
)


def handle_command(payload: Dict[str, Any], zoom_client, config, keeper_client, store):
    """Handle a ``bot_notification`` (slash command or message in the bot's 1:1 chat)."""
    user_jid = payload.get("userJid", "")
    account_id = payload.get("accountId", "")
    reply_to = payload.get("toJid") or user_jid
    parts = (payload.get("cmd") or "").strip().split(None, 1)
    subcommand = parts[0].lower().lstrip("/") if parts else ""
    text = parts[1] if len(parts) > 1 else ""

    def respond(content):
        zoom_client.send_ephemeral(user_jid=user_jid, content=content, account_id=account_id)

    # First-time setup: no approvals channel yet, so report this chat's JID
    if not config.zoom.approvals_channel_jid:
        logger.warning(f"Approvals channel not configured; this chat's JID is {reply_to}")
        if is_channel_jid(reply_to):
            hint = (f"This channel's JID is:\n`{reply_to}`\n\n"
                    f"If this is the approvals channel, set `zoom.approvals_channel_jid` to it "
                    f"in zoom_config.yaml and restart the app.")
        else:
            hint = ("Run this command inside the approvals channel (with the app added to it) "
                    "to see that channel's JID.")
        respond(text_content(f"*Keeper app setup: approvals channel not configured*\n\n{hint}"))
        return

    if subcommand in ACCESS_SUBCOMMANDS:
        handle_access_request(payload, text, ACCESS_SUBCOMMANDS[subcommand],
                              zoom_client, config, keeper_client, store)
    elif subcommand in HELP_SUBCOMMANDS:
        respond(build_usage_content())
    elif subcommand in PLANNED_SUBCOMMANDS:
        respond(build_usage_content(f"`{subcommand}` is not available yet."))
    else:
        respond(build_usage_content(f"Unknown command `{subcommand}`."))
