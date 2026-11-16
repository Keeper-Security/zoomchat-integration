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

Zoom chatbots have no modals, so the results are rendered into the approval card as a radio list. Every search runs
``sync-down`` first so records created in the vault since Commander's last
sync are found.
"""

from typing import Any, Dict, Optional, Tuple

from ..commander_errors import COMMAND_NOT_ALLOWED, COMMANDER_UNAUTHORIZED
from ..logger import logger
from ..views import build_searching_card
from .approvals import InteractionContext, _check_pending, _is_self_approval, _safe_update_card


SEARCH_RESULT_LIMIT = 20


def _sync_vault(keeper_client) -> Tuple[Optional[str], bool]:
    """
    Run ``sync-down``. Returns ``(banner, blocking)``: ``blocking`` is True when
    Commander rejected it (expired session, not allowed, unauthorized), so a
    search would fail too.
    """
    ok, sync_error = keeper_client.sync_down()
    if sync_error:
        return " ".join(str(sync_error.get("error", "Commander rejected sync-down")).split()), True
    if not ok:
        return "Vault sync did not complete; showing results from the last sync.", False
    return None, False


def _search_failed(request, banner: str, store, zoom_client):
    """Back to the "Search" step with the reason, instead of a misleading "nothing found"."""
    request.searched = False
    request.search_results = []
    request.selected = None
    request.banner = banner
    store.save(request)
    _safe_update_card(zoom_client, request)


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

        sync_banner, blocking = _sync_vault(keeper_client)
        if blocking:
            logger.warning(f"Skipping search for {approval_id}: {sync_banner}")
            _search_failed(request, sync_banner, store, zoom_client)
            return

        logger.debug(f"Searching for {request.item_noun}s with query: '{query}'")
        if request.is_folder:
            records, search_error = keeper_client.search_folders(query, limit=SEARCH_RESULT_LIMIT)
        else:
            records, search_error = keeper_client.search_records(
                query, limit=SEARCH_RESULT_LIMIT, for_one_time_share=request.is_one_time_share,
            )

        if search_error and search_error.get("error_code") in (COMMAND_NOT_ALLOWED, COMMANDER_UNAUTHORIZED):
            error = " ".join(str(search_error.get("error", "")).split())
            ctx.reply(zoom_client, f"*Commander rejected the search*\n\n{error}\n\n*Search query:* `{query}`")
            _search_failed(request, error, store, zoom_client)
            return

        request.searched = True
        request.search_results = [r.to_dict() for r in records]
        request.selected = None
        request.banner = sync_banner

        store.save(request)
        logger.debug(f"Got {len(records)} result(s) for {approval_id}, updating card...")
        _safe_update_card(zoom_client, request)
