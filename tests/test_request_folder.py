"""End-to-end tests for /keeper request-folder and command routing."""

from src.models import NSFPermissionRole, PermissionLevel, RequestStatus

from conftest import (
    APPROVER, CHANNEL, FOLDER_UID, NSF_FOLDER_UID, PAM_FOLDER_UID, UID,
    card_text, card_values, choose, click, slash, submit,
)


def _submit_folder(env, text):
    assert env.post(slash(f"request-folder {text}")).status_code == 200
    channel, card, _ = env.zoom.sent[0]
    assert channel == CHANNEL
    aid = next(v for v in card_values(card) if v.startswith("deny|")).split("|")[1]
    return aid, card


def _reply_text(env, user_jid="req-1@xmpp.zoom.us"):
    return card_text(env.zoom.ephemerals_for(user_jid)[-1])


# ----------------------------------------------------------------------
# Routing
# ----------------------------------------------------------------------

def test_unknown_subcommand_is_not_a_record_request(env):
    env.post(slash("request-something X need it"))
    assert "Unknown command" in _reply_text(env)
    assert all(vis for _, _, vis in env.zoom.sent)  # only private replies, no card


def test_planned_subcommand_not_available_yet(env):
    env.post(slash(f"one-time-share {UID} need it"))
    assert "not available yet" in _reply_text(env)
    assert all(vis for _, _, vis in env.zoom.sent)


def test_help_lists_both_commands(env):
    env.post(slash("help"))
    text = _reply_text(env)
    assert "request-record" in text and "request-folder" in text


def test_folder_justification_required(env):
    env.post(slash(f"request-folder {FOLDER_UID}"))
    assert "Justification is required" in _reply_text(env) and "request-folder" in _reply_text(env)


def test_record_uid_in_folder_request_rejected(env):
    env.post(slash(f"request-folder {UID} need it"))
    assert "is a *record*" in _reply_text(env)
    assert all(vis for _, _, vis in env.zoom.sent)


def test_folder_uid_in_record_request_rejected(env):
    env.post(slash(f"request-record {FOLDER_UID} need it"))
    assert "is a *folder*" in _reply_text(env) and "request-folder" in _reply_text(env)


# ----------------------------------------------------------------------
# Classic shared folder
# ----------------------------------------------------------------------

def test_folder_uid_request_default_grant(env):
    aid, card = _submit_folder(env, f"{FOLDER_UID} deploy release")
    text = card_text(card)
    assert "Folder Access Request" in text and "Folder Details" in text
    values = card_values(card)
    assert f"perm|{aid}|manage_records" in values and f"perm|{aid}|view_only" not in values
    assert f"rot|{aid}|yes" not in values  # not a PAM folder

    env.post(click(f"approve|{aid}|"))
    (grant,) = env.keeper.folder_grants
    assert grant == dict(uid=FOLDER_UID, email="riley@example.com",
                         permission=PermissionLevel.NO_PERMISSIONS, duration=300, rotate=False)
    assert env.store.get(aid).status == RequestStatus.APPROVED
    dm_to, dm = env.zoom.dms[-1]
    assert dm_to == "req-1@xmpp.zoom.us" and f"#shared_folder/{FOLDER_UID}" in card_text(dm)


def test_manage_users_is_permanent(env):
    aid, _ = _submit_folder(env, f"{FOLDER_UID} need it")
    env.post(choose(f"perm|{aid}|manage_users"))
    card = env.zoom.last_card()
    assert "always permanent" in card_text(card)
    assert not any(v.startswith(f"dur|{aid}|") for v in card_values(card))

    env.post(click(f"approve|{aid}|"))
    assert env.keeper.folder_grants[0]["permission"] == PermissionLevel.MANAGE_USERS
    assert env.keeper.folder_grants[0]["duration"] is None


def test_record_permission_rejected_on_folder(env):
    aid, _ = _submit_folder(env, f"{FOLDER_UID} need it")
    env.post(choose(f"perm|{aid}|can_edit"))
    assert env.store.get(aid).permission == PermissionLevel.NO_PERMISSIONS.value


def test_pam_folder_rotation(env):
    aid, card = _submit_folder(env, f"{PAM_FOLDER_UID} rotate test")
    values = card_values(card)
    assert f"rot|{aid}|yes" in values and f"dur|{aid}|permanent" not in values

    env.post(click(f"approve|{aid}|"))
    assert env.keeper.folder_grants[0]["rotate"] is True


def test_folder_invitation_sent(env):
    env.keeper.grant_result = {"success": True, "invitation_sent": True, "expires_at": "Pending Invitation"}
    aid, _ = _submit_folder(env, f"{FOLDER_UID} need it")
    env.post(click(f"approve|{aid}|"))
    assert env.store.get(aid).status == RequestStatus.INVITATION_SENT
    assert "folder" in card_text(env.zoom.dms[-1][1])


# ----------------------------------------------------------------------
# Nested Share Folder
# ----------------------------------------------------------------------

def test_nsf_folder_roles_without_transfer_ownership(env):
    aid, card = _submit_folder(env, f"{NSF_FOLDER_UID} need it")
    values = card_values(card)
    assert f"perm|{aid}|full-manager" in values and f"perm|{aid}|owner" not in values

    env.post(choose(f"perm|{aid}|content-manager"))
    env.post(choose(f"dur|{aid}|24h"))
    env.post(click(f"approve|{aid}|"))
    (grant,) = env.keeper.nsf_folder_grants
    assert grant == dict(uid=NSF_FOLDER_UID, email="riley@example.com",
                         role=NSFPermissionRole.CONTENT_MANAGER, duration=86400)


# ----------------------------------------------------------------------
# Description request: search folders
# ----------------------------------------------------------------------

def test_folder_search_select_pam_folder(env):
    aid, card = _submit_folder(env, '"PAM" need folder')
    assert "Search Folders" in card_text(card)

    env.post(click(f"search|{aid}|"))
    card = env.zoom.last_card()
    assert env.keeper.syncs == 1
    assert "Select a folder" in card_text(card) and "Use Selected Folder" in card_text(card)

    env.post(submit(f"rec|{aid}|0", f"pick|{aid}|"))
    item = env.store.get(aid).selected_item
    assert item.uid == PAM_FOLDER_UID and item.is_pam
    card = env.zoom.last_card()
    assert f"rot|{aid}|yes" in card_values(card) and "Change Folder" in card_text(card)

    env.post(click(f"approve|{aid}|"))
    assert env.keeper.folder_grants[0]["uid"] == PAM_FOLDER_UID


def test_folder_search_no_results(env):
    aid, _ = _submit_folder(env, '"nothing here" need it')
    env.post(click(f"search|{aid}|"))
    assert "No folders found" in card_text(env.zoom.last_card())


def test_folder_deny(env):
    aid, _ = _submit_folder(env, f"{FOLDER_UID} need it")
    env.post(click(f"deny|{aid}|", user=APPROVER))
    assert env.store.get(aid).status == RequestStatus.DENIED
    assert "Folder access request was denied" in card_text(env.zoom.dms[-1][1])


def test_expired_keeper_session_is_shown_and_keeps_request_open(env):
    expired = {"success": False, "error_code": "keeper_session_expired",
               "error": "Commander's Keeper session has expired."}
    env.keeper.sync_down = lambda: (False, expired)
    aid, _ = _submit_folder(env, '"Staging" need it')
    env.post(click(f"search|{aid}|"))
    assert "session has expired" in card_text(env.zoom.last_card())

    env.keeper.grant_result = dict(expired)
    env.post(submit(f"rec|{aid}|0", f"pick|{aid}|"))
    env.post(click(f"approve|{aid}|"))
    assert env.store.get(aid).status == RequestStatus.PENDING
