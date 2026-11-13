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

"""Handlers for ``/keeper request-record`` and ``/keeper request-folder``."""

from typing import Any, Callable, Dict

from ..keeper_client import KeeperClient
from ..models import AccessRequest, RequestType
from ..utils import (
    generate_approval_id, is_valid_uid, parse_command_text,
    sanitize_user_input, MAX_JUSTIFICATION_LENGTH, MAX_IDENTIFIER_LENGTH,
    resolve_approval_channel, format_timestamp,
)
from ..views import (
    build_request_submitted_content, build_usage_content, post_approval_request,
    select_item, text_content,
)
from ..logger import logger


def _lookup_record(identifier: str, keeper_client, respond: Callable):
    """Record for a UID request, or None after telling the requester why not."""
    record = keeper_client.get_record_by_uid(identifier)
    if not record:
        respond(text_content(
            f"*Record Not Found*\n\nNo record found with UID: `{identifier}`\n\n"
            f"Please verify the UID and try again."
        ))
        return None
    if record.record_type in KeeperClient._FOLDER_ITEM_TYPES:
        logger.warning(f"UID {identifier} is a folder, not a record")
        respond(text_content(
            f"*Invalid UID Type*\n\nThe UID `{identifier}` is a *folder*, not a record.\n\n"
            f"Use `/keeper request-folder {identifier} <justification>` instead."
        ))
        return None
    return record


def _lookup_folder(identifier: str, keeper_client, respond: Callable):
    """Folder for a UID request (with PAM detection), or None after telling the requester why not."""
    folder = keeper_client.get_folder_by_uid(identifier)
    if not folder:
        respond(text_content(
            f"*Folder Not Found*\n\nNo folder found with UID: `{identifier}`\n\n"
            f"Please verify the UID and try again."
        ))
        return None
    if folder.folder_type == "record":
        logger.warning(f"UID {identifier} is a record, not a folder")
        respond(text_content(
            f"*Invalid UID Type*\n\nThe UID `{identifier}` is a *record*, not a folder.\n\n"
            f"Use `/keeper request-record {identifier} <justification>` instead."
        ))
        return None
    if not folder.is_nsf:
        is_pam, pam_error = keeper_client.is_pam_user_folder(identifier)
        if pam_error:
            respond(text_content(
                f"*Folder request could not be submitted.*\n\n{pam_error.get('error')}\n\n"
                f"*Folder UID:* `{identifier}`"
            ))
            return None
        folder.is_pam = is_pam
    return folder


def handle_access_request(payload: Dict[str, Any], text: str, request_type: RequestType,
                          zoom_client, config, keeper_client, store):
    """
    Validate ``[record|folder] [reason]``, look up a UID, and post the
    approval card. ``payload`` is Zoom's ``bot_notification`` payload; ``text``
    is the command text after the sub-command.
    """
    user_id = payload.get("userId", "")
    user_jid = payload.get("userJid", "")
    user_name = payload.get("userName") or user_id
    account_id = payload.get("accountId", "")
    is_folder = request_type == RequestType.FOLDER
    noun = "folder" if is_folder else "record"
    subcommand = f"request-{noun}"

    def respond(content):
        zoom_client.send_ephemeral(user_jid=user_jid, content=content, account_id=account_id)

    identifier, justification = parse_command_text(text)

    if not identifier:
        respond(build_usage_content(f"Please provide a {noun} UID or description."))
        return

    if not justification:
        respond(text_content(
            f"Justification is required.\n\n"
            f"*Usage:* `/keeper {subcommand} \"{identifier}\" Justification message or ticket number`"
        ))
        return

    identifier, id_valid, id_error = sanitize_user_input(identifier, MAX_IDENTIFIER_LENGTH)
    if not id_valid:
        respond(text_content(f"*Invalid Input*\n\n{id_error}"))
        return

    justification, just_valid, just_error = sanitize_user_input(justification, MAX_JUSTIFICATION_LENGTH)
    if not just_valid:
        respond(text_content(f"*Invalid Input*\n\n{just_error}"))
        return

    if not identifier or not justification:
        respond(build_usage_content(
            f"{noun.capitalize()} and justification can't be empty after removing special characters."
        ))
        return

    is_uid = is_valid_uid(identifier)
    item = None
    if is_uid:
        logger.info(f"Fetching {noun} details for UID: {identifier}")
        item = (_lookup_folder if is_folder else _lookup_record)(identifier, keeper_client, respond)
        if not item:
            return

    approval_id = generate_approval_id()

    # Multi-channel approver: route to the requester's team channel when
    # enabled, else the default approvals channel.
    requester_email = payload.get("userEmail") or payload.get("email")
    if config.multichannel_approver.enabled:
        requester_email = zoom_client.get_user_email(user_id, hint=requester_email)
    approvals_channel = resolve_approval_channel(config, keeper_client, requester_email)

    request = AccessRequest(
        approval_id=approval_id,
        requester_id=user_id,
        requester_jid=user_jid,
        requester_name=user_name,
        requester_email=requester_email,
        identifier=identifier,
        is_uid=is_uid,
        justification=justification,
        created_at=format_timestamp(),
        account_id=account_id,
        request_type=request_type.value,
        channel_jid=approvals_channel,
        duration="5m",
    )
    if item:
        select_item(request, item)

    try:
        request.message_id = post_approval_request(zoom_client, request)
        store.save(request)
        logger.info(
            f"Submitted [approval_id={approval_id}]: {noun} request for "
            f"{'UID' if is_uid else 'description'} '{identifier}' by {user_name} ({user_id}) "
            f"-> {approvals_channel}"
        )
        respond(build_request_submitted_content(request))
    except Exception as e:
        logger.error(f"Error posting approval request: {e}")
        respond(text_content(
            f"*Failed to submit access request*\n\n"
            f"Please try again or contact support.\n\nError: {str(e)}"
        ))
