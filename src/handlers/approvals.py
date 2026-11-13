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
    get_duration_options,
    is_permission_conflict_error,
    is_record_owner_error,
    parse_duration_to_seconds,
)
from ..views import (
    ACTION_APPROVE, ACTION_CHANGE_RECORD, ACTION_DENY, ACTION_PICK, ACTION_SEARCH,
    SELECT_DURATION, SELECT_PERMISSION, SELECT_RECORD, SELECT_ROTATE,
    build_access_denied_content, build_access_granted_content,
    build_invitation_sent_content, decode_value, is_pam_target,
    default_permission, is_permanent_only, now_display, permission_options, select_item,
    text_content, update_approval_card,
)
from ..logger import logger


SELF_APPROVAL_MESSAGE = (
    "🚫 You cannot approve your own request. "
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

    def reply(self, zoom_client, text: str):
        zoom_client.send_ephemeral(
            user_jid=self.user_jid, content=text_content(text), account_id=self.account_id,
        )


def _safe_update_card(zoom_client, request: AccessRequest):
    try:
        update_approval_card(zoom_client, request)
    except Exception as e:
        logger.error(f"Failed to update approval card {request.approval_id}: {e}")


def _check_pending(request: Optional[AccessRequest], ctx: InteractionContext, zoom_client) -> bool:
    if request is None:
        ctx.reply(zoom_client, "This approval request is no longer available.")
        return False
    if request.status != RequestStatus.PENDING:
        ctx.reply(
            zoom_client,
            f"Request `{request.approval_id}` was already processed ({request.status.replace('_', ' ')}).",
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
        ctx.reply(zoom_client, SELF_APPROVAL_MESSAGE)
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
    elif action == ACTION_SEARCH:
        from .search import handle_search_records
        handle_search_records(payload, approval_id, zoom_client, config, keeper_client, store)
    elif action == SELECT_RECORD:
        # A radio choice delivered as a plain action instead of a form submit
        _apply_choice(action, approval_id, arg, payload, zoom_client, config, keeper_client, store)
    elif action == ACTION_PICK:
        InteractionContext(payload, config).reply(zoom_client, "Select an item in the list first.")
    elif action == ACTION_CHANGE_RECORD:
        _clear_record(approval_id, payload, zoom_client, config, store)
    else:
        logger.warning(f"Unknown button value: {value!r}")


def handle_form_submit(payload: Dict[str, Any], zoom_client, config, keeper_client, store):
    """
    Handle ``chat_message.submit`` from a form card (the search results radio
    list). All inputs arrive in ``payload.object.submit_items``.
    """
    obj = payload.get("object") or {}
    items = obj.get("submit_items") or []
    logger.debug(f"Form submit items: {items}")

    choice = button = ""
    for item in items:
        for kind, data in item.items():
            if not isinstance(data, dict):
                continue
            if kind == "actionItem":
                button = data.get("value", "")
                continue
            value = (data.get("value")
                     or (data.get("selected_option") or {}).get("value")
                     or (data.get("selected_item") or {}).get("value") or "")
            if isinstance(value, str) and value.startswith(f"{SELECT_RECORD}|"):
                choice = value

    ctx_payload = {
        "userId": payload.get("operator_id", ""),
        "userJid": obj.get("user_jid", ""),
        "userName": obj.get("user_name") or obj.get("user_jid", ""),
        "toJid": obj.get("to_jid", ""),
        "accountId": payload.get("account_id", ""),
    }
    if not choice:
        if button:
            InteractionContext(ctx_payload, config).reply(zoom_client, "Select an item in the list first.")
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
                    ctx.reply(zoom_client, f"*Could not check the folder*\n\n{pam_error.get('error')}")
                    return
            select_item(request, item)
            logger.debug(f"{approval_id}: approver {ctx.user_name} selected {request.item_noun} {item.uid}")

        elif kind == SELECT_PERMISSION and record:
            if arg not in {v for v, _ in permission_options(record)}:
                logger.warning(f"Invalid permission {arg!r} for {approval_id}")
                return
            request.permission = arg

        elif kind == SELECT_DURATION and record:
            allowed = {v for v, _ in get_duration_options(exclude_permanent=is_pam_target(record))}
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
    permissions are always permanent, matching the Slack app.
    """
    if request.permission not in {v for v, _ in permission_options(record)}:
        request.permission = default_permission(record)
    enum = NSFPermissionRole if record.is_nsf else PermissionLevel
    permission = enum(request.permission)

    if is_permanent_only(record, permission.value) or request.duration == "permanent":
        return permission, None, "permanent", "No Expiration"

    duration_value = request.duration or "5m"
    return permission, parse_duration_to_seconds(duration_value), duration_value, format_duration(duration_value)


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

        if not user_email:
            back_to_pending(
                "Could not resolve the requester's Zoom email. Check the app's user-read scope "
                "and that the admin re-added the app, then approve again."
            )
            ctx.reply(zoom_client, f"*Access grant failed*\n\nCould not look up the email of {request.requester_name}.")
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
