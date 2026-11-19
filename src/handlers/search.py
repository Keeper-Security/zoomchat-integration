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

Zoom chatbots have no modals, so the results go into the approval card as a
dropdown, with a "Search for" box the approver can edit (Zoom dropdowns can't be
searched). Searches use Commander's current vault cache; "Re-Sync Vault" runs
``sync-down`` first, for records created or shared since Commander last synced.
"""

from typing import Any, Dict, Optional, Tuple

from ..commander_errors import COMMAND_NOT_ALLOWED, COMMANDER_UNAUTHORIZED
from ..logger import logger
from ..views import MAX_SEARCH_RESULTS, NOTE_ERROR, build_searching_card
from .approvals import InteractionContext, _check_pending, _is_self_approval, _safe_update_card


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


def handle_search_records(payload: Dict[str, Any], approval_id: str, zoom_client, config, keeper_client, store,
                          query: Optional[str] = None, resync: bool = False):
    """
    Search / Re-Sync Vault button. ``query`` is the approver's "Search for" text (otherwise the
    last query is reused); ``resync`` runs ``sync-down`` before searching.
    """
    ctx = InteractionContext(payload, config)

    with store.locked(approval_id) as request:
        if not _check_pending(request, ctx, zoom_client):
            return
        if _is_self_approval(request, ctx, zoom_client):
            return
        if request.is_uid:
            return

        if query is not None:
            query = " ".join(query.split())
            if not query:
                _safe_update_card(zoom_client, request, notice="Enter something to search for.")
                return
            request.search_query = query
        query = request.current_query
        if resync:
            # Progress card only for the slow sync. A plain search answers in about a second, and two
            # edits that close together can reach Zoom clients out of order (leaving "Searching..." shown)
            try:
                zoom_client.edit_message(
                    message_id=request.message_id, to_jid=request.channel_jid,
                    content=build_searching_card(request), user_jid=request.requester_jid,
                    account_id=request.account_id,
                )
            except Exception as e:
                logger.warning(f"Could not show syncing state for {approval_id}: {e}")

        sync_banner, blocking = _sync_vault(keeper_client) if resync else (None, False)
        if blocking:
            logger.warning(f"Skipping search for {approval_id}: {sync_banner}")
            _search_failed(request, sync_banner, store, zoom_client)
            return

        logger.debug(f"Searching for {request.item_noun}s with query: '{query}'")
        if request.is_folder:
            records, search_error = keeper_client.search_folders(query)
        else:
            records, search_error = keeper_client.search_records(
                query, for_one_time_share=request.is_one_time_share,
            )

        if search_error and search_error.get("error_code") in (COMMAND_NOT_ALLOWED, COMMANDER_UNAUTHORIZED):
            error = " ".join(str(search_error.get("error", "")).split())
            ctx.reply(zoom_client, f"*Commander rejected the search*\n\n{error}\n\n*Search query:* `{query}`",
                      NOTE_ERROR)
            _search_failed(request, error, store, zoom_client)
            return

        request.searched = True
        request.search_total = len(records)
        request.search_results = [r.to_dict() for r in records[:MAX_SEARCH_RESULTS]]
        request.selected = None
        request.banner = sync_banner

        store.save(request)
        logger.debug(f"Got {len(records)} result(s) for {approval_id}, updating card...")
        _safe_update_card(zoom_client, request)
