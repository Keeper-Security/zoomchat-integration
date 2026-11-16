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
``/keeper create-secret``: create a record in one of the requester's shared
folders, using two form cards in the user's 1:1 chat with the bot. The chosen folder travels in the card's button values, so
no state is stored. Submitted field values (which may include a password) are
never logged, stored, or echoed back.
"""

from typing import Any, Dict, List

from ..logger import logger
from ..utils import resolve_approval_channel
from ..views import (
    CS_CANCEL, CS_CREATE, CS_FOLDER, CS_NEXT, CS_SUBFOLDER,
    build_create_secret_folder_card, build_create_secret_form, build_create_secret_notification,
    build_create_secret_result, build_create_secret_status, decode_folder, text_content,
)
from .forms import submitted_values, wants_generated_password

CREATE_SECRET_ACTIONS = (CS_NEXT, CS_CREATE, CS_CANCEL)


def _edit(zoom_client, message_id: str, user_jid: str, account_id: str, content: Dict[str, Any]):
    try:
        zoom_client.edit_message(message_id=message_id, to_jid=user_jid, content=content,
                                 user_jid=user_jid, account_id=account_id)
    except Exception as e:
        logger.error(f"Failed to update create-secret card: {e}")


def _reply(zoom_client, user_jid: str, account_id: str, text: str):
    zoom_client.send_ephemeral(user_jid=user_jid, content=text_content(text), account_id=account_id)


def handle_create_secret_command(payload: Dict[str, Any], zoom_client, config, keeper_client, store):
    """Post the folder picker, listing only shared folders shared with the requester."""
    user_id = payload.get("userId", "")
    user_jid = payload.get("userJid", "")
    account_id = payload.get("accountId", "")

    email = zoom_client.get_user_email(user_id, hint=payload.get("userEmail") or payload.get("email"))
    if not email:
        _reply(zoom_client, user_jid, account_id,
               "*Create Secret*\n\nCould not look up your Zoom email, which is needed to find your shared folders.")
        return

    try:
        message_id = zoom_client.send_message(
            to_jid=user_jid, content=build_create_secret_status(":hourglass_flowing_sand: Loading your shared folders..."),
            user_jid=user_jid, account_id=account_id,
        )
    except Exception as e:
        logger.error(f"Failed to open create-secret card: {e}")
        return

    logger.info(f"User {user_id} ({email}) requesting create-secret")
    folders, error = keeper_client.get_user_shared_folders(email)
    if error:
        content = build_create_secret_status(f":warning: *Could not load shared folders*\n\n{error.get('error')}")
    elif not folders:
        content = build_create_secret_status(
            "No shared folders found for your account.\n\n"
            "Please ensure you have been granted access to at least one shared folder by your administrator."
        )
    else:
        content = build_create_secret_folder_card(folders)
    _edit(zoom_client, message_id, user_jid, account_id, content)


def cancel_create_secret(payload: Dict[str, Any], zoom_client):
    """Cancel button (``interactive_message_actions``) on either create-secret card."""
    _edit(zoom_client, payload.get("messageId", ""), payload.get("userJid", ""), payload.get("accountId", ""),
          build_create_secret_status("Create secret cancelled."))


def handle_create_secret_submit(button_value: str, items: List[Dict[str, Any]], payload: Dict[str, Any],
                                zoom_client, config, keeper_client):
    """``chat_message.submit`` from either create-secret form card."""
    obj = payload.get("object") or {}
    user_jid = obj.get("user_jid", "")
    message_id = obj.get("bot_msg_id", "")
    account_id = payload.get("account_id", "")
    inputs = submitted_values(items, (CS_FOLDER, CS_SUBFOLDER))
    action = button_value.split("|", 1)[0]

    if action == CS_NEXT:
        _folder_chosen(inputs, user_jid, message_id, account_id, zoom_client, keeper_client)
    elif action == CS_CREATE:
        _create_record(button_value, inputs, payload, user_jid, message_id, account_id,
                       zoom_client, config, keeper_client)


def _folder_chosen(inputs, user_jid, message_id, account_id, zoom_client, keeper_client):
    if CS_FOLDER not in inputs:
        _reply(zoom_client, user_jid, account_id, "Select a shared folder in the list first.")
        return
    _, folder_uid, is_nsf, folder_name = decode_folder(inputs[CS_FOLDER])
    logger.info(f"Create-secret: user {user_jid} selected shared folder {folder_uid} (is_nsf={is_nsf})")
    _edit(zoom_client, message_id, user_jid, account_id,
          build_create_secret_status(f":hourglass_flowing_sand: Loading *{folder_name}*..."))
    subfolders = keeper_client.list_subfolders(folder_uid)
    _edit(zoom_client, message_id, user_jid, account_id,
          build_create_secret_form(folder_uid, folder_name, is_nsf, subfolders))


def _create_record(button_value, inputs, payload, user_jid, message_id, account_id,
                   zoom_client, config, keeper_client):
    _, folder_uid, parent_is_nsf, folder_name = decode_folder(button_value)
    title = inputs.get("cs_title", "").strip()
    login = inputs.get("cs_login", "").strip()
    password = inputs.get("cs_password", "").strip()
    url = inputs.get("cs_url", "").strip()
    notes = inputs.get("cs_notes", "").strip()

    if not title:
        # Leave the form as typed; only tell the user what's missing
        _reply(zoom_client, user_jid, account_id, "*Title is required.* Fill in the title and click Create Record again.")
        return

    target_uid, target_is_nsf = folder_uid, parent_is_nsf
    folder_path = folder_name
    if CS_SUBFOLDER in inputs:
        _, sub_uid, sub_is_nsf, sub_path = decode_folder(inputs[CS_SUBFOLDER])
        if sub_uid and sub_uid != folder_uid:
            target_uid, target_is_nsf = sub_uid, sub_is_nsf
            folder_path = f"{folder_name} / {sub_path or sub_uid}"

    generate_password = wants_generated_password(password)
    _edit(zoom_client, message_id, user_jid, account_id, build_create_secret_status(
        f":hourglass_flowing_sand: *Creating your secret...*\n\n*Title:* {title}\n*Folder:* {folder_path}\n\n"
        f"Please wait, this may take a few seconds."
    ))
    logger.info(f"Create-secret: user {user_jid} creating record '{title}' in folder {target_uid} "
                f"(is_nsf={target_is_nsf}, auto-generated password: {generate_password})")

    result = keeper_client.create_record(
        title=title, folder_uid=target_uid, is_nsf=target_is_nsf,
        login=login or None, password=None if generate_password else password,
        url=url or None, notes=notes or None, generate_password=generate_password,
    )

    if not result.get("success"):
        error = " ".join(str(result.get("error", "Unknown error")).split())
        logger.error(f"Create-secret failed for '{title}' in {target_uid}: {error}")
        _edit(zoom_client, message_id, user_jid, account_id, build_create_secret_result(title, "", folder_path, error))
        return

    record_uid = result.get("record_uid", "Unknown")
    _edit(zoom_client, message_id, user_jid, account_id, build_create_secret_result(title, record_uid, folder_path))
    logger.ok(f"Record '{title}' ({record_uid}) created by {user_jid} in {folder_path}")

    obj = payload.get("object") or {}
    email = zoom_client.get_user_email(payload.get("operator_id", ""), hint=None)
    # Approvers know users by their Keeper (email) identity, not the Zoom JID
    requester = email or obj.get("user_name") or user_jid
    channel = resolve_approval_channel(config, keeper_client, email)
    try:
        zoom_client.send_message(
            to_jid=channel, content=build_create_secret_notification(requester, record_uid, title, folder_path),
            user_jid=user_jid, account_id=account_id,
        )
    except Exception as e:
        logger.error(f"Failed to post create-secret notification: {e}")
