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
Approver "Create New Record" on a description-based record request.

Zoom chatbots have no modals, so the form replaces the search results on the
approval card. There is no folder choice: Commander creates the record in its
default location, then the card returns to the results with the new record selected so the
approver can approve sharing it with the requester.
"""

from typing import Any, Dict, List

from ..logger import logger
from ..models import KeeperRecord
from ..views import (
    SELECT_SELF_DESTRUCT, SELF_DESTRUCT_DURATIONS,
    build_searching_card, can_create_record, decode_value, select_item, update_approval_card,
)
from .approvals import InteractionContext, _check_pending, _is_self_approval, _safe_update_card
from .forms import submitted_values, wants_generated_password


def _set_form(payload: Dict[str, Any], approval_id: str, show: bool, zoom_client, config, store):
    ctx = InteractionContext(payload, config)
    with store.locked(approval_id) as request:
        if not _check_pending(request, ctx, zoom_client) or _is_self_approval(request, ctx, zoom_client):
            return
        if not can_create_record(request):
            return
        request.creating_record = show
        request.new_record_classic = False
        request.banner = None
        store.save(request)
        _safe_update_card(zoom_client, request)


def open_create_record(payload: Dict[str, Any], approval_id: str, zoom_client, config, store):
    """"Create New Record" button: show the form on the approval card."""
    _set_form(payload, approval_id, True, zoom_client, config, store)


def close_create_record(payload: Dict[str, Any], approval_id: str, zoom_client, config, store):
    """"Back" button: return to the search results."""
    _set_form(payload, approval_id, False, zoom_client, config, store)


def choose_permission_model(payload: Dict[str, Any], approval_id: str, model: str, zoom_client, config, store):
    """Permission model button: redraw the form so self-destruct shows only for Classic."""
    ctx = InteractionContext(payload, config)
    with store.locked(approval_id) as request:
        if not _check_pending(request, ctx, zoom_client) or _is_self_approval(request, ctx, zoom_client):
            return
        if not request.creating_record or (model == "classic") == request.new_record_classic:
            return
        request.new_record_classic = model == "classic"
        request.banner = None
        store.save(request)
        _safe_update_card(zoom_client, request)


def _show_form_error(request, error: str, prefill: Dict[str, str], store, zoom_client):
    """Keep the form open with the error and what the approver typed (except the password)."""
    request.creating_record = True
    request.banner = error
    store.save(request)
    try:
        update_approval_card(zoom_client, request, form_prefill=prefill)
    except Exception as e:
        logger.error(f"Failed to update approval card {request.approval_id}: {e}")


def handle_create_record_submit(approval_id: str, items: List[Dict[str, Any]], ctx_payload: Dict[str, Any],
                                zoom_client, config, keeper_client, store):
    """"Create Record" submit on the approval card form."""
    ctx = InteractionContext(ctx_payload, config)
    inputs = submitted_values(items, (SELECT_SELF_DESTRUCT,))
    title = inputs.get("nr_title", "").strip()
    login = inputs.get("nr_login", "").strip()
    password = inputs.get("nr_password", "").strip()
    url = inputs.get("nr_url", "").strip()
    notes = inputs.get("nr_notes", "").strip()
    self_destruct = decode_value(inputs.get(SELECT_SELF_DESTRUCT, ""))[2]
    if self_destruct not in SELF_DESTRUCT_DURATIONS:
        self_destruct = None

    with store.locked(approval_id) as request:
        if not _check_pending(request, ctx, zoom_client) or _is_self_approval(request, ctx, zoom_client):
            return
        if not request.creating_record or not can_create_record(request):
            logger.warning(f"Ignoring create-record submit for {approval_id}: form is not open")
            return

        is_nsf = not request.new_record_classic
        if is_nsf:
            self_destruct = None  # Classic only; the field isn't on the NSF form
        prefill = {"title": title, "login": login, "url": url, "notes": notes,
                   "self_destruct": self_destruct or "off"}

        if not title:
            _show_form_error(request, "Title is required.", prefill, store, zoom_client)
            return
        if not login:
            _show_form_error(request, "Login is required.", prefill, store, zoom_client)
            return

        generate_password = wants_generated_password(password)
        try:
            zoom_client.edit_message(
                message_id=request.message_id, to_jid=request.channel_jid,
                content=build_searching_card(request, ":hourglass_flowing_sand: *Creating record...*"),
                user_jid=request.requester_jid, account_id=request.account_id,
            )
        except Exception as e:
            logger.warning(f"Could not show creating state for {approval_id}: {e}")

        logger.info(
            f"Creating {'Nested Share Folder' if is_nsf else 'Classic'} record '{title}' for requester "
            f"{request.requester_id} ({approval_id})" + (" with self-destruct" if self_destruct else "")
        )
        result = keeper_client.create_record(
            title=title, is_nsf=is_nsf, login=login, password=None if generate_password else password,
            url=url or None, notes=notes or None, generate_password=generate_password,
            self_destruct=self_destruct,
        )

        if not result.get("success"):
            error = " ".join(str(result.get("error", "Unknown error")).split())
            logger.error(f"Create record failed for {approval_id}: {error}")
            _show_form_error(request, error, prefill, store, zoom_client)
            return

        record_uid = result.get("record_uid")
        request.creating_record = False
        if not record_uid or record_uid == "Unknown":
            # Created, but we can't select it; let the approver find it by searching
            request.searched = False
            request.search_results = []
            request.selected = None
            request.banner = f"Record '{title}' was created but its UID could not be read. Search for it."
            store.save(request)
            _safe_update_card(zoom_client, request)
            return

        # Back to the results with only the new record, pre-selected
        record = KeeperRecord(uid=record_uid, title=title, record_type="login", notes=notes or None, is_nsf=is_nsf)
        request.searched = True
        request.search_results = [record.to_dict()]
        request.created_record_uid = record_uid
        request.self_destruct = self_destruct
        select_item(request, record)
        store.save(request)
        _safe_update_card(zoom_client, request)
        logger.ok(f"Record created: {record_uid} by {ctx.user_name} for {approval_id}"
                  + (" (self-destruct)" if self_destruct else ""))
