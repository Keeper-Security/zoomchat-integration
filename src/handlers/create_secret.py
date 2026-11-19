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
    CREATE_SECRET_TITLE, CS_BACK, CS_CANCEL, CS_CREATE, CS_FIND, CS_FOLDER, CS_FOLDER_FIND, CS_FOLDER_SYNC,
    CS_NEXT, CS_SUB_SYNC, CS_SUBFOLDER,
    NOTE_ERROR, NOTE_WARN,
    build_create_secret_folder_card, build_create_secret_form, build_create_secret_notification,
    build_create_secret_result, build_create_secret_status, decode_folder, notice_content,
)
from .forms import submitted_values, wants_generated_password

CREATE_SECRET_ACTIONS = (CS_FOLDER_FIND, CS_FOLDER_SYNC, CS_NEXT, CS_FIND, CS_SUB_SYNC, CS_CREATE, CS_BACK,
                         CS_CANCEL)


def _edit(zoom_client, message_id: str, user_jid: str, account_id: str, content: Dict[str, Any]):
    try:
        zoom_client.edit_message(message_id=message_id, to_jid=user_jid, content=content,
                                 user_jid=user_jid, account_id=account_id)
    except Exception as e:
        logger.error(f"Failed to update create-secret card: {e}")


def _reply(zoom_client, user_jid: str, account_id: str, text: str, level: str = NOTE_WARN):
    zoom_client.send_ephemeral(user_jid=user_jid, content=notice_content(text, level, CREATE_SECRET_TITLE),
                               account_id=account_id)


def handle_create_secret_command(payload: Dict[str, Any], zoom_client, config, keeper_client, store):
    """Post the folder picker, listing only shared folders shared with the requester."""
    user_id = payload.get("userId", "")
    user_jid = payload.get("userJid", "")
    account_id = payload.get("accountId", "")

    email = zoom_client.get_user_email(user_id, hint=payload.get("userEmail") or payload.get("email"))
    if not email:
        _reply(zoom_client, user_jid, account_id,
               "Could not look up your Zoom email, which is needed to find your shared folders.", NOTE_ERROR)
        return

    # Load first, then post one card: no "Loading..." message to replace a second later
    logger.info(f"User {user_id} ({email}) requesting create-secret")
    folders, error = keeper_client.get_user_shared_folders(email)
    if error:
        content = build_create_secret_status(f"Could not load shared folders: {error.get('error')}", NOTE_ERROR)
    elif not folders:
        content = build_create_secret_status(
            "No shared folders found for your account.\n\n"
            "Please ensure you have been granted access to at least one shared folder by your administrator."
        )
    else:
        content = build_create_secret_folder_card(folders)
    try:
        zoom_client.send_message(to_jid=user_jid, content=content, user_jid=user_jid, account_id=account_id)
    except Exception as e:
        logger.error(f"Failed to open create-secret card: {e}")


def cancel_create_secret(payload: Dict[str, Any], zoom_client):
    """Cancel button (``interactive_message_actions``) on either create-secret card."""
    _edit(zoom_client, payload.get("messageId", ""), payload.get("userJid", ""), payload.get("accountId", ""),
          build_create_secret_status("Create secret cancelled."))


def back_to_folders(payload: Dict[str, Any], zoom_client, keeper_client):
    """Back button (``interactive_message_actions``) on step 2: show the shared folder step again."""
    message_id, user_jid = payload.get("messageId", ""), payload.get("userJid", "")
    account_id = payload.get("accountId", "")
    email = zoom_client.get_user_email(payload.get("userId", ""), hint=payload.get("userEmail"))
    if not email:
        _reply(zoom_client, user_jid, account_id,
               "Could not look up your Zoom email, which is needed to find your shared folders.", NOTE_ERROR)
        return
    folders, error = keeper_client.get_user_shared_folders(email)
    if error:
        content = build_create_secret_status(f"Could not load shared folders: {error.get('error')}", NOTE_ERROR)
    else:
        content = build_create_secret_folder_card(folders)
    _edit(zoom_client, message_id, user_jid, account_id, content)


def handle_create_secret_submit(button_value: str, items: List[Dict[str, Any]], payload: Dict[str, Any],
                                zoom_client, config, keeper_client):
    """``chat_message.submit`` from either create-secret form card."""
    obj = payload.get("object") or {}
    user_jid = obj.get("user_jid", "")
    message_id = obj.get("bot_msg_id", "")
    account_id = payload.get("account_id", "")
    inputs = submitted_values(items, (CS_FOLDER, CS_SUBFOLDER))
    action = button_value.split("|", 1)[0]

    if action in (CS_FOLDER_FIND, CS_FOLDER_SYNC):
        _find_shared_folder(inputs, payload, user_jid, message_id, account_id, zoom_client, keeper_client,
                            resync=action == CS_FOLDER_SYNC)
    elif action == CS_NEXT:
        _folder_chosen(inputs, payload, user_jid, message_id, account_id, zoom_client, keeper_client)
    elif action in (CS_FIND, CS_SUB_SYNC):
        _find_subfolder(button_value, inputs, user_jid, message_id, account_id, zoom_client, keeper_client,
                        resync=action == CS_SUB_SYNC)
    elif action == CS_CREATE:
        _create_record(button_value, inputs, payload, user_jid, message_id, account_id,
                       zoom_client, config, keeper_client)


def _sync_vault(keeper_client, zoom_client, user_jid: str, account_id: str) -> bool:
    """Re-Sync Vault: run ``sync-down``. False when Commander rejected it (the reason is sent to the user)."""
    ok, sync_error = keeper_client.sync_down()
    if sync_error:
        _reply(zoom_client, user_jid, account_id,
               f"Vault sync failed: {sync_error.get('error', 'Commander rejected sync-down')}", NOTE_ERROR)
        return False
    if not ok:
        _reply(zoom_client, user_jid, account_id,
               "Vault sync did not complete; showing folders from the last sync.", NOTE_WARN)
    return True


def _find_shared_folder(inputs, payload, user_jid, message_id, account_id, zoom_client, keeper_client,
                        resync: bool = False):
    """Step 1 "Search" / "Re-Sync Vault": reload the user's shared folders and show the matching ones."""
    find = inputs.get("cs_folder_find", "").strip()
    email = zoom_client.get_user_email(payload.get("operator_id", ""), hint=None)
    if not email:
        _reply(zoom_client, user_jid, account_id,
               "Could not look up your Zoom email, which is needed to find your shared folders.", NOTE_ERROR)
        return
    if resync:  # progress card only for the slow sync (see search.handle_search_records)
        _edit(zoom_client, message_id, user_jid, account_id,
              build_create_secret_status("Syncing the vault and loading your shared folders..."))
        _sync_vault(keeper_client, zoom_client, user_jid, account_id)  # on failure, still show the cached folders
    folders, error = keeper_client.get_user_shared_folders(email)
    if error:
        content = build_create_secret_status(f"Could not load shared folders: {error.get('error')}", NOTE_ERROR)
    else:
        content = build_create_secret_folder_card(folders, find=find)
    _edit(zoom_client, message_id, user_jid, account_id, content)


def _folder_chosen(inputs, payload, user_jid, message_id, account_id, zoom_client, keeper_client):
    if CS_FOLDER not in inputs:
        # Redraw step 1 with the warning on the card (and the user's search kept)
        email = zoom_client.get_user_email(payload.get("operator_id", ""), hint=None)
        folders, error = keeper_client.get_user_shared_folders(email) if email else ([], None)
        if email and not error:
            _edit(zoom_client, message_id, user_jid, account_id, build_create_secret_folder_card(
                folders, find=inputs.get("cs_folder_find", ""), notice="Select a shared folder in the dropdown first."))
        else:
            _reply(zoom_client, user_jid, account_id, "Select a shared folder in the dropdown first.")
        return
    _, folder_uid, is_nsf, folder_name = decode_folder(inputs[CS_FOLDER])
    logger.info(f"Create-secret: user {user_jid} selected shared folder {folder_uid} (is_nsf={is_nsf})")
    subfolders = keeper_client.list_subfolders(folder_uid)
    _edit(zoom_client, message_id, user_jid, account_id,
          build_create_secret_form(folder_uid, folder_name, is_nsf, subfolders))


def _find_subfolder(button_value, inputs, user_jid, message_id, account_id, zoom_client, keeper_client,
                    resync: bool = False):
    """"Find" / "Re-Sync Vault" on step 2: redraw with the matching subfolders, keeping typed fields."""
    _, folder_uid, is_nsf, folder_name = decode_folder(button_value)
    find = inputs.get("cs_find", "").strip()
    prefill = {key: inputs.get(f"cs_{key}", "") for key in ("title", "login", "url", "notes")}
    if resync:
        _edit(zoom_client, message_id, user_jid, account_id,
              build_create_secret_status(f"Syncing the vault and loading *{folder_name}*..."))
        _sync_vault(keeper_client, zoom_client, user_jid, account_id)
    subfolders = keeper_client.list_subfolders(folder_uid)
    logger.debug(f"Create-secret: subfolder search in {folder_uid} ({len(subfolders)} subfolder(s))")
    _edit(zoom_client, message_id, user_jid, account_id,
          build_create_secret_form(folder_uid, folder_name, is_nsf, subfolders, find=find, prefill=prefill))


def _create_record(button_value, inputs, payload, user_jid, message_id, account_id,
                   zoom_client, config, keeper_client):
    _, folder_uid, parent_is_nsf, folder_name = decode_folder(button_value)
    title = inputs.get("cs_title", "").strip()
    login = inputs.get("cs_login", "").strip()
    password = inputs.get("cs_password", "").strip()
    url = inputs.get("cs_url", "").strip()
    notes = inputs.get("cs_notes", "").strip()

    if not title:
        # Redraw the form with the warning, keeping what was typed (never the password) and the subfolder
        selected_uid = decode_folder(inputs[CS_SUBFOLDER])[1] if CS_SUBFOLDER in inputs else None
        _edit(zoom_client, message_id, user_jid, account_id, build_create_secret_form(
            folder_uid, folder_name, parent_is_nsf, keeper_client.list_subfolders(folder_uid),
            find=inputs.get("cs_find", ""), prefill={"login": login, "url": url, "notes": notes},
            notice="Title is required. Fill it in and click Create Record again.", selected_uid=selected_uid))
        return

    target_uid, target_is_nsf = folder_uid, parent_is_nsf
    folder_path = folder_name
    if CS_SUBFOLDER in inputs:
        _, sub_uid, sub_is_nsf, sub_path = decode_folder(inputs[CS_SUBFOLDER])
        if sub_uid and sub_uid != folder_uid:
            # A subfolder has its shared folder's type: Commander keeps Classic folders out of
            # Nested Share Folders and vice versa, so NSF parent => nsf-record-add
            target_uid, target_is_nsf = sub_uid, parent_is_nsf or sub_is_nsf
            folder_path = f"{folder_name} / {sub_path or sub_uid}"

    generate_password = wants_generated_password(password)
    _edit(zoom_client, message_id, user_jid, account_id, build_create_secret_status(
        f"*Creating your secret...*\n\n*Title:* {title}\n*Folder:* {folder_path}\n\n"
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
