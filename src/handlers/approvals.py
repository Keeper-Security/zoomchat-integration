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

"""Handlers for approval card buttons and dropdowns."""

from typing import Any, Dict, Optional

from ..commander_errors import COMMAND_NOT_ALLOWED, COMMANDER_UNAUTHORIZED
from ..models import (
    AccessRequest,
    KeeperFolder,
    NSFPermissionRole,
    PermissionLevel,
    RequestStatus,
)
from ..utils import (
    format_approval_audit_log,
    format_duration,
    format_timestamp,
    is_permission_conflict_error,
    is_record_owner_error,
    parse_duration_to_seconds,
)
from ..views import (
    ACTION_APPROVE, ACTION_CHANGE_RECORD, ACTION_DENY, ACTION_PICK, ACTION_RESYNC, ACTION_SEARCH,
    ACTION_NEW_RECORD, ACTION_NEW_RECORD_BACK, ACTION_NEW_RECORD_SUBMIT, ACTION_PERMISSION_MODEL,
    SELECT_SELF_DESTRUCT,
    CS_BACK, CS_CANCEL, CS_CREATE, CS_FIND, CS_FOLDER_FIND, CS_FOLDER_SYNC, CS_NEXT, CS_SUB_SYNC,
    SELECT_DURATION, SELECT_PERMISSION, SELECT_RECORD, SELECT_ROTATE,
    build_access_denied_content, build_access_granted_content,
    build_invitation_sent_content, build_share_link_content, decode_value, is_pam_target,
    request_duration_options, request_is_permanent_only, request_permission_options,
    default_permission, now_display, select_item, self_destruct_for,
    NOTE_ERROR, NOTE_INFO, NOTE_WARN, notice_content, text_content, update_approval_card,
)
from ..logger import logger
from .forms import submitted_values


SELF_APPROVAL_MESSAGE = (
    "You cannot approve your own request. "
    "Please ask your admin or another team member to review and approve it on your behalf."
)


class InteractionContext:
    """The clicking user and where to reply to them."""

    def __init__(self, payload: Dict[str, Any], config):
        self.user_id = payload.get("userId", "")
        self.user_jid = payload.get("userJid", "")
        self.user_name = payload.get("userName") or self.user_id
        self.user_email = payload.get("userEmail") or payload.get("email")
        self.channel_jid = payload.get("toJid", "")
        self.account_id = payload.get("accountId", "")
        self.allow_self_approval = config.allow_self_approval

    def reply(self, zoom_client, text: str, level: Optional[str] = None):
        """DM the clicking user; with ``level`` the first paragraph is a highlighted note."""
        content = notice_content(text, level) if level else text_content(text)
        zoom_client.send_ephemeral(user_jid=self.user_jid, content=content, account_id=self.account_id)


def _safe_update_card(zoom_client, request: AccessRequest, notice: Optional[str] = None):
    try:
        update_approval_card(zoom_client, request, notice=notice)
    except Exception as e:
        logger.error(f"Failed to update approval card {request.approval_id}: {e}")


def warn_on_card(approval_id: str, payload: Dict[str, Any], text: str, zoom_client, config, store):
    """Show a "fix your input" warning on the approval card itself instead of in a DM."""
    ctx = InteractionContext(payload, config)
    with store.locked(approval_id) as request:
        if _check_pending(request, ctx, zoom_client):
            _safe_update_card(zoom_client, request, notice=text)


def _check_pending(request: Optional[AccessRequest], ctx: InteractionContext, zoom_client) -> bool:
    if request is None:
        ctx.reply(zoom_client, "This approval request is no longer available.", NOTE_WARN)
        return False
    if request.status != RequestStatus.PENDING:
        ctx.reply(
            zoom_client,
            f"Request {request.approval_id} was already processed ({request.status.replace('_', ' ')}).",
            NOTE_INFO,
        )
        return False
    return True


def _is_self_approval(request: AccessRequest, ctx: InteractionContext, zoom_client) -> bool:
    same_id = bool(ctx.user_id) and ctx.user_id == request.requester_id
    same_jid = bool(ctx.user_jid) and ctx.user_jid.lower() == (request.requester_jid or "").lower()
    if same_id or same_jid:
        if ctx.allow_self_approval:
            logger.warning(f"Self-approval allowed for {request.approval_id} by {ctx.user_id} (testing mode)")
            return False
        ctx.reply(zoom_client, SELF_APPROVAL_MESSAGE, NOTE_ERROR)
        logger.info(f"Blocked self-approval for {request.approval_id} by {ctx.user_id}")
        return True
    return False


# ----------------------------------------------------------------------
# Dispatch
# ----------------------------------------------------------------------

def handle_interactive_action(payload: Dict[str, Any], zoom_client, config, keeper_client, store):
    """Route an ``interactive_message_actions`` (button) event."""
    value = (payload.get("actionItem") or {}).get("value", "")
    action, approval_id, arg = decode_value(value)

    if action == ACTION_APPROVE:
        handle_approve_action(payload, approval_id, zoom_client, config, keeper_client, store)
    elif action == ACTION_DENY:
        handle_deny_action(payload, approval_id, zoom_client, config, keeper_client, store)
    elif action in (ACTION_SEARCH, ACTION_RESYNC):
        from .search import handle_search_records
        handle_search_records(payload, approval_id, zoom_client, config, keeper_client, store,
                              resync=action == ACTION_RESYNC)
    elif action == SELECT_RECORD:
        # A radio choice delivered as a plain action instead of a form submit
        _apply_choice(action, approval_id, arg, payload, zoom_client, config, keeper_client, store)
    elif action == ACTION_PICK:
        warn_on_card(approval_id, payload, "Select an item in the dropdown first.", zoom_client, config, store)
    elif action == ACTION_CHANGE_RECORD:
        _clear_record(approval_id, payload, zoom_client, config, store)
    elif action == ACTION_NEW_RECORD:
        from .create_record import open_create_record
        open_create_record(payload, approval_id, zoom_client, config, store)
    elif action == ACTION_NEW_RECORD_BACK:
        from .create_record import close_create_record
        close_create_record(payload, approval_id, zoom_client, config, store)
    elif action == ACTION_PERMISSION_MODEL:
        from .create_record import choose_permission_model
        choose_permission_model(payload, approval_id, arg, zoom_client, config, store)
    elif action == CS_BACK:
        from .create_secret import back_to_folders
        back_to_folders(payload, zoom_client, keeper_client)
    elif action == CS_CANCEL:
        from .create_secret import cancel_create_secret
        cancel_create_secret(payload, zoom_client)
    else:
        logger.warning(f"Unknown button value: {value!r}")


def handle_form_submit(payload: Dict[str, Any], zoom_client, config, keeper_client, store):
    """
    Handle ``chat_message.submit`` from a form card: the search results (dropdown
    or a new search), the approver's Create New Record form, or the create-secret cards.
    All inputs arrive in ``payload.object.submit_items``.
    """
    obj = payload.get("object") or {}
    items = obj.get("submit_items") or []
    # Values can include a typed password (create-secret), so log only the shape
    logger.debug(f"Form submit items: {[sorted(item) for item in items]}")

    button = next((item["actionItem"].get("value", "") for item in items
                   if isinstance(item.get("actionItem"), dict)), "")
    if button.split("|", 1)[0] in (CS_FOLDER_FIND, CS_FOLDER_SYNC, CS_NEXT, CS_FIND, CS_SUB_SYNC, CS_CREATE):
        from .create_secret import handle_create_secret_submit
        handle_create_secret_submit(button, items, payload, zoom_client, config, keeper_client)
        return

    ctx_payload = {
        "userId": payload.get("operator_id", ""),
        "userJid": obj.get("user_jid", ""),
        "userName": obj.get("user_name") or obj.get("user_jid", ""),
        "toJid": obj.get("to_jid", ""),
        "accountId": payload.get("account_id", ""),
    }
    action, approval_id, _ = decode_value(button)
    if action in (ACTION_SEARCH, ACTION_RESYNC):
        from .search import handle_search_records
        query = submitted_values(items).get("search_query", "")
        handle_search_records(ctx_payload, approval_id, zoom_client, config, keeper_client, store,
                              query=query, resync=action == ACTION_RESYNC)
        return
    if action == ACTION_NEW_RECORD_SUBMIT:
        from .create_record import handle_create_record_submit
        handle_create_record_submit(approval_id, items, ctx_payload, zoom_client, config, keeper_client, store)
        return

    choice = submitted_values(items, (SELECT_RECORD,)).get(SELECT_RECORD, "")
    if not choice:
        if button:
            warn_on_card(approval_id, ctx_payload, "Select an item in the dropdown first.", zoom_client, config, store)
        else:
            logger.warning("Form submit without a choice or button")
        return
    kind, approval_id, arg = decode_value(choice)
    _apply_choice(kind, approval_id, arg, ctx_payload, zoom_client, config, keeper_client, store)


def _clear_record(approval_id: str, payload: Dict[str, Any], zoom_client, config, store):
    """Back to the search results list so the approver can pick another record/folder."""
    ctx = InteractionContext(payload, config)
    with store.locked(approval_id) as request:
        if not _check_pending(request, ctx, zoom_client) or _is_self_approval(request, ctx, zoom_client):
            return
        request.selected = None
        request.banner = None
        store.save(request)
        _safe_update_card(zoom_client, request)


def handle_interactive_select(payload: Dict[str, Any], zoom_client, config, keeper_client, store):
    """
    Handle an ``interactive_message_select`` event (record, permission,
    duration or PAM rotation dropdown). Zoom doesn't send dropdown state with
    the Approve click, so each selection is stored as it happens.
    """
    items = payload.get("selectedItems") or []
    if not items:
        return
    kind, approval_id, arg = decode_value(items[0].get("value", ""))
    if kind == SELECT_SELF_DESTRUCT:
        return  # Read from the Create New Record form submit
    _apply_choice(kind, approval_id, arg, payload, zoom_client, config, keeper_client, store)


def _apply_choice(kind: str, approval_id: str, arg: str, payload: Dict[str, Any],
                  zoom_client, config, keeper_client, store):
    """Store an approver's item / permission / duration / rotation choice and re-render the card."""
    ctx = InteractionContext(payload, config)

    with store.locked(approval_id) as request:
        if not _check_pending(request, ctx, zoom_client):
            return
        if _is_self_approval(request, ctx, zoom_client):
            # Re-render to undo the requester's local dropdown change
            _safe_update_card(zoom_client, request)
            return

        record = request.selected_item

        if kind == SELECT_RECORD:
            try:
                chosen = request.search_results[int(arg)]
            except (ValueError, IndexError):
                logger.warning(f"Invalid selection {arg!r} for {approval_id}")
                return
            item = request.item_from_dict(chosen)
            if isinstance(item, KeeperFolder) and not item.is_nsf:
                item.is_pam, pam_error = keeper_client.is_pam_user_folder(item.uid)
                if pam_error:
                    ctx.reply(zoom_client, f"*Could not check the folder*\n\n{pam_error.get('error')}", NOTE_ERROR)
                    return
            select_item(request, item)
            logger.debug(f"{approval_id}: approver {ctx.user_name} selected {request.item_noun} {item.uid}")

        elif kind == SELECT_PERMISSION and record:
            if arg not in {v for v, _ in request_permission_options(request, record)}:
                logger.warning(f"Invalid permission {arg!r} for {approval_id}")
                return
            request.permission = arg

        elif kind == SELECT_DURATION and record:
            allowed = {v for v, _ in request_duration_options(request, record)}
            if arg not in allowed:
                logger.warning(f"Invalid duration {arg!r} for {approval_id}")
                return
            request.duration = arg

        elif kind == SELECT_ROTATE and record:
            request.rotate_on_expire = (arg == "yes")

        else:
            logger.warning(f"Ignoring select {kind!r} for {approval_id}")
            return

        store.save(request)
        _safe_update_card(zoom_client, request)


# ----------------------------------------------------------------------
# Approve
# ----------------------------------------------------------------------

def _resolve_grant(request: AccessRequest, record):
    """
    Turn the stored selections into ``(permission, duration_seconds,
    duration_value, duration_text)``. Ownership / share / manage-users
    permissions are always permanent. A record the approver created with
    self-destruct is shared View Only for the self-destruct duration.
    """
    self_destruct = self_destruct_for(request, record)
    if self_destruct:
        request.permission = PermissionLevel.VIEW_ONLY.value
        return (PermissionLevel.VIEW_ONLY, parse_duration_to_seconds(self_destruct), self_destruct,
                format_duration(self_destruct))
    if request.permission not in {v for v, _ in request_permission_options(request, record)}:
        request.permission = default_permission(record)
    enum = NSFPermissionRole if record.is_nsf and not request.is_one_time_share else PermissionLevel
    permission = enum(request.permission)
    if request.is_one_time_share and request.duration not in {v for v, _ in request_duration_options(request, record)}:
        request.duration = "5m"

    if request_is_permanent_only(request, record, permission.value) or request.duration == "permanent":
        return permission, None, "permanent", "No Expiration"

    duration_value = request.duration or "5m"
    return permission, parse_duration_to_seconds(duration_value), duration_value, format_duration(duration_value)


def _approve_one_time_share(request: AccessRequest, record, permission, duration_seconds, duration_text,
                            requester, approver_email, ctx, zoom_client, keeper_client, store, back_to_pending):
    """Create the one-time share link and DM it to the requester (never stored or posted to the channel)."""
    approval_id = request.approval_id
    try:
        result = keeper_client.create_one_time_share(
            record_uid=record.uid,
            duration_seconds=duration_seconds,
            editable=permission == PermissionLevel.CAN_EDIT,
        )
    except Exception as e:
        logger.error(f"Error creating one-time share: {e}", exc_info=True)
        result = {'success': False, 'error': f"Error creating one-time share: {e}"}

    request.permission = permission.value
    if result.get('success') and result.get('share_url'):
        request.status = RequestStatus.APPROVED
        request.resolved_at = now_display()
        request.expires_at = result.get('expires_at', duration_text)
        store.save(request)
        _safe_update_card(zoom_client, request)
        zoom_client.send_dm(
            request.requester_jid, build_share_link_content(request, result['share_url']), request.account_id,
        )
        logger.info(format_approval_audit_log(
            approval_id=approval_id,
            request_type=request.request_type,
            identifier=record.uid,
            requester_email=requester,
            approver_email=approver_email,
            permission=permission.value,
            duration_text=duration_text,
        ))
        return

    error_message = str(result.get('error', 'Unknown error'))
    error_text = " ".join(error_message.split())
    if result.get('error_code') in (COMMAND_NOT_ALLOWED, COMMANDER_UNAUTHORIZED, "keeper_session_expired"):
        back_to_pending(error_text)
        ctx.reply(
            zoom_client,
            f"*Cannot Create One-Time Share*\n\n{error_message}\n\n*Request ID:* `{approval_id}`\n"
            f"*Record:* {record.title}\n\nThe approval request remains active.",
            NOTE_ERROR,
        )
    else:
        request.status = RequestStatus.FAILED
        request.status_text = f"One-time share failed: {error_text}"
        request.resolved_at = format_timestamp()
        store.save(request)
        _safe_update_card(zoom_client, request)
    logger.info(
        f"Failed [approval_id={approval_id}]: one-time share (UID: {record.uid}), requester {requester}, "
        f"approver {approver_email}, permission {permission.value}, duration {duration_text}, "
        f"error \"{error_text}\""
    )


def handle_approve_action(payload, approval_id, zoom_client, config, keeper_client, store):
    """
    Handle the Approve button: grant access to the selected record/folder and notify
    the requester.
    """
    ctx = InteractionContext(payload, config)

    with store.locked(approval_id) as request:
        if not _check_pending(request, ctx, zoom_client):
            return
        if _is_self_approval(request, ctx, zoom_client):
            return

        record = request.selected_item
        noun = request.item_noun
        Noun = noun.capitalize()
        if not record:
            ctx.reply(
                zoom_client,
                f"*Cannot approve directly*\n\nThis request uses a description, not a UID. "
                f"Please use *Search {Noun}s* and select the correct {noun} first.",
                NOTE_WARN,
            )
            return

        permission, duration_seconds, duration_value, duration_text = _resolve_grant(request, record)
        rotate_on_expire = bool(duration_seconds and is_pam_target(record) and request.rotate_on_expire)
        logger.debug(
            f"Approve {approval_id} - permission: {permission.value}, "
            f"duration: {duration_value} ({duration_seconds} seconds), rotate: {rotate_on_expire}"
        )

        # Lock the card while Commander works so nobody double-approves
        request.status = RequestStatus.PROCESSING
        request.approver_name = ctx.user_name
        request.banner = None
        store.save(request)
        _safe_update_card(zoom_client, request)

        def back_to_pending(banner: str):
            request.status = RequestStatus.PENDING
            request.banner = banner
            store.save(request)
            _safe_update_card(zoom_client, request)

        user_email = zoom_client.get_user_email(request.requester_id, hint=request.requester_email)
        approver_email = zoom_client.get_user_email(ctx.user_id, hint=ctx.user_email) or ctx.user_name

        if request.is_one_time_share:
            _approve_one_time_share(request, record, permission, duration_seconds, duration_text,
                                    user_email or request.requester_name, approver_email,
                                    ctx, zoom_client, keeper_client, store, back_to_pending)
            return

        if not user_email:
            back_to_pending(
                "Could not resolve the requester's Zoom email. Check the app's user-read scope "
                "and that the admin re-added the app, then approve again."
            )
            ctx.reply(zoom_client, f"*Access grant failed*\n\nCould not look up the email of {request.requester_name}.",
                      NOTE_ERROR)
            return

        try:
            if request.is_folder and record.is_nsf:
                result = keeper_client.grant_nsf_folder_access(
                    folder_uid=record.uid,
                    user_email=user_email,
                    role=permission,
                    duration_seconds=duration_seconds,
                )
            elif request.is_folder:
                result = keeper_client.grant_folder_access(
                    folder_uid=record.uid,
                    user_email=user_email,
                    permission=permission,
                    duration_seconds=duration_seconds,
                    rotate_on_expire=rotate_on_expire,
                )
            elif record.is_nsf:
                result = keeper_client.grant_nsf_record_access(
                    record_uid=record.uid,
                    user_email=user_email,
                    role=permission,
                    duration_seconds=duration_seconds,
                )
            else:
                result = keeper_client.grant_record_access(
                    record_uid=record.uid,
                    user_email=user_email,
                    permission=permission,
                    duration_seconds=duration_seconds,
                    rotate_on_expire=rotate_on_expire,
                )
        except Exception as e:
            logger.error(f"Error in approve handler: {e}", exc_info=True)
            result = {'success': False, 'error': f"Error processing approval: {e}"}

        request.permission = permission.value
        request.duration = duration_value

        if result.get('success'):
            request.resolved_at = now_display()

            # Requester has no Keeper account yet
            if result.get('invitation_sent'):
                request.status = RequestStatus.INVITATION_SENT
                store.save(request)
                _safe_update_card(zoom_client, request)
                zoom_client.send_dm(request.requester_jid, build_invitation_sent_content(request), request.account_id)
                logger.info(
                    f"Pending [approval_id={approval_id}]: Invitation sent for {noun} "
                    f"(UID: {record.uid}) to requester {user_email}, approver {approver_email}; "
                    f"waiting for Keeper invitation acceptance"
                )
                return

            request.status = RequestStatus.APPROVED
            request.expires_at = result.get('expires_at', duration_text)
            request.rotate_scheduled = bool(result.get('rotate_on_expire'))
            store.save(request)
            _safe_update_card(zoom_client, request)
            zoom_client.send_dm(
                request.requester_jid,
                build_access_granted_content(request, keeper_client.server_domain),
                request.account_id,
            )
            logger.info(format_approval_audit_log(
                approval_id=approval_id,
                request_type=request.request_type,
                identifier=record.uid,
                requester_email=user_email,
                approver_email=approver_email,
                permission=permission.value,
                duration_text=duration_text,
                rotate_on_expire=request.rotate_scheduled,
                is_pam=is_pam_target(record),
            ))
            return

        error_message = str(result.get('error', 'Unknown error'))
        error_code = result.get('error_code')
        error_text = " ".join(error_message.split())

        if error_code == 'pam_rotation_not_configured':
            # Keep the request open; approver can turn rotation off and retry
            back_to_pending(
                f"Rotation is not configured on this PAM User {noun}. Set *PAM credential rotation* "
                "to No and click Approve again, or configure rotation in the Keeper Vault."
            )
            logger.info(
                f"Pending [approval_id={approval_id}]: Rotation not configured for {noun} "
                f"(UID: {record.uid}), requested by {user_email}, approver {approver_email}; "
                f"approval state unchanged"
            )
            return

        if is_record_owner_error(error_message):
            request.status = RequestStatus.OWNER
            request.status_text = "User Already Has Full Access (Owner)"
            request.resolved_at = format_timestamp()
            store.save(request)
            _safe_update_card(zoom_client, request)
            ctx.reply(
                zoom_client,
                f"*Access grant failed:*\n\nThe selected user is the current owner of this record "
                f"and already has full permissions.\n\n*Request ID:* `{approval_id}`\n*Record:* {record.title}",
                NOTE_ERROR,
            )
            logger.info(
                f"Blocked [approval_id={approval_id}]: requester is record owner (UID: {record.uid}), "
                f"requester {user_email}, approver {approver_email}"
            )
            return

        if is_permission_conflict_error(error_message) or error_code in (
            COMMAND_NOT_ALLOWED, COMMANDER_UNAUTHORIZED, "keeper_session_expired"):
            # Admin-fixable: keep the request open so it can be approved again
            back_to_pending(error_text)
            ctx.reply(
                zoom_client,
                f"*Cannot Grant Access*\n\n{error_message}\n\n*Request ID:* `{approval_id}`\n"
                f"*{Noun}:* {record.title}\n\nThe approval request remains active.",
                NOTE_ERROR,
            )
        else:
            request.status = RequestStatus.FAILED
            request.status_text = f"Approval failed: {error_text}"
            request.resolved_at = format_timestamp()
            store.save(request)
            _safe_update_card(zoom_client, request)

        logger.info(
            f"Failed [approval_id={approval_id}]: {noun} access (UID: {record.uid}), "
            f"requester {user_email}, approver {approver_email}, requested permission "
            f"{permission.value}, duration {duration_text}, error \"{error_text}\""
        )


# ----------------------------------------------------------------------
# Deny
# ----------------------------------------------------------------------

def handle_deny_action(payload, approval_id, zoom_client, config, keeper_client, store):
    """
    Handle the Deny button: close the request and notify the requester.
    """
    ctx = InteractionContext(payload, config)

    with store.locked(approval_id) as request:
        if not _check_pending(request, ctx, zoom_client):
            return

        request.status = RequestStatus.DENIED
        request.approver_name = ctx.user_name
        request.status_text = f"Denied by {ctx.user_name}"
        request.resolved_at = format_timestamp()
        request.banner = None
        store.save(request)

        _safe_update_card(zoom_client, request)
        zoom_client.send_dm(request.requester_jid, build_access_denied_content(request), request.account_id)

        requester_email = zoom_client.get_user_email(request.requester_id, hint=request.requester_email)
        approver_email = zoom_client.get_user_email(ctx.user_id, hint=ctx.user_email) or ctx.user_name
        justification = " ".join(str(request.justification).split())
        logger.info(
            f"Denied [approval_id={approval_id}]: {request.item_noun} request "
            f"(UID: {request.identifier}), requester {requester_email or request.requester_name}, "
            f"denied by {approver_email}, justification \"{justification}\""
        )
