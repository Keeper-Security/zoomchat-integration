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
Handler for the "Search Records" / "Search Folders" button on description-based requests.

Slack opens a search modal. Zoom chatbots have no modals, so the results are
rendered into the approval card as a radio list. Every search runs
``sync-down`` first so records created in the vault since Commander's last
sync are found.
"""

from typing import Any, Dict, Optional

from ..commander_errors import COMMAND_NOT_ALLOWED, COMMANDER_UNAUTHORIZED
from ..logger import logger
from ..views import build_searching_card
from .approvals import InteractionContext, _check_pending, _is_self_approval, _safe_update_card


SEARCH_RESULT_LIMIT = 20


def _sync_vault(keeper_client) -> Optional[str]:
    """Run ``sync-down``; return a banner for the card if it didn't complete."""
    ok, sync_error = keeper_client.sync_down()
    if sync_error:
        return " ".join(str(sync_error.get("error", "Commander rejected sync-down")).split())
    if not ok:
        return "Vault sync did not complete; showing results from the last sync."
    return None


def handle_search_records(payload: Dict[str, Any], approval_id: str, zoom_client, config, keeper_client, store):
    ctx = InteractionContext(payload, config)

    with store.locked(approval_id) as request:
        if not _check_pending(request, ctx, zoom_client):
            return
        if _is_self_approval(request, ctx, zoom_client):
            return
        if request.is_uid:
            return

        query = request.identifier
        try:
            zoom_client.edit_message(
                message_id=request.message_id, to_jid=request.channel_jid,
                content=build_searching_card(request), user_jid=request.requester_jid,
                account_id=request.account_id,
            )
        except Exception as e:
            logger.warning(f"Could not show searching state for {approval_id}: {e}")
        sync_banner = _sync_vault(keeper_client)

        logger.debug(f"Searching for {request.item_noun}s with query: '{query}'")
        search = keeper_client.search_folders if request.is_folder else keeper_client.search_records
        records, search_error = search(query, limit=SEARCH_RESULT_LIMIT)

        request.searched = True
        request.search_results = [r.to_dict() for r in records]
        request.selected = None
        request.banner = sync_banner

        if search_error and search_error.get("error_code") in (COMMAND_NOT_ALLOWED, COMMANDER_UNAUTHORIZED):
            request.banner = " ".join(str(search_error.get("error", "")).split())
            ctx.reply(
                zoom_client,
                f"*Commander rejected the search*\n\n{search_error.get('error')}\n\n"
                f"*Search query:* `{query}`",
            )

        store.save(request)
        logger.debug(f"Got {len(records)} result(s) for {approval_id}, updating card...")
        _safe_update_card(zoom_client, request)
