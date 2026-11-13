"""End-to-end tests for /keeper request-record through the webhook endpoint."""

from src.models import NSFPermissionRole, PermissionLevel, RequestStatus
from src.utils import parse_command_text
from src.zoom_client import url_validation_response

from conftest import (
    APPROVER, CHANNEL, NSF_UID, PAM_UID, REQUESTER, UID,
    card_text, card_values, choose, click, slash, submit,
)


def _submit(env, cmd):
    if not cmd.startswith("request-"):
        cmd = f"request-record {cmd}"
    assert env.post(slash(cmd)).status_code == 200
    channel, card, _ = env.zoom.sent[0]
    assert channel == CHANNEL
    aid = next(v for v in card_values(card) if v.startswith("deny|")).split("|")[1]
    return aid, card


# ----------------------------------------------------------------------
# Webhook security
# ----------------------------------------------------------------------

def test_url_validation(env):
    resp = env.post({"event": "endpoint.url_validation", "payload": {"plainToken": "abc"}})
    assert resp.status_code == 200
    assert resp.get_json() == url_validation_response("test-secret-token", "abc")


def test_rejects_bad_signature(env):
    resp = env.post(slash(f"{UID} need it"), secret="wrong")
    assert resp.status_code == 401
    assert env.zoom.sent == []


def test_rejects_missing_signature(env):
    resp = env.client.post("/zoom/webhook", json=slash(f"{UID} need it"))
    assert resp.status_code == 401


# ----------------------------------------------------------------------
# Command validation
# ----------------------------------------------------------------------

def test_empty_command_shows_usage(env):
    env.post(slash(""))
    (msg,) = env.zoom.ephemerals_for(REQUESTER["userJid"])
    assert "request-record" in card_text(msg) and "request-folder" in card_text(msg)


def test_justification_required(env):
    env.post(slash(f"request-record {UID}"))
    (msg,) = env.zoom.ephemerals_for(REQUESTER["userJid"])
    assert "Justification is required" in card_text(msg)


def test_unknown_uid(env):
    env.post(slash("request-record ZZZZZZZZZZZZZZZZZZZZZZ need it"))
    (msg,) = env.zoom.ephemerals_for(REQUESTER["userJid"])
    assert "Record Not Found" in card_text(msg)


def test_parse_command_text():
    assert parse_command_text('"prod db" fix bug') == ("prod db", "fix bug")
    assert parse_command_text('“prod db” fix bug') == ("prod db", "fix bug")
    assert parse_command_text(f"`{UID}` ticket-1") == (UID, "ticket-1")
    assert parse_command_text("single") == ("single", "")


def test_keeper_subcommand_alias(env):
    aid, _ = _submit(env, f"request-record {UID} JIRA-1")
    assert env.store.get(aid).identifier == UID


# ----------------------------------------------------------------------
# UID flow
# ----------------------------------------------------------------------

def test_uid_request_approve_with_selections(env):
    aid, card = _submit(env, f"{UID} JIRA-123 run migration")
    assert f"approve|{aid}|" in card_values(card)
    assert "Prod DB" in card_text(card)
    # Requester got the "submitted" confirmation
    assert "submitted" in card_text(env.zoom.ephemerals_for(REQUESTER["userJid"])[0])

    env.post(choose(f"perm|{aid}|can_edit"))
    env.post(choose(f"dur|{aid}|1h"))
    env.post(click(f"approve|{aid}|"))

    (grant,) = env.keeper.grants
    assert grant == dict(uid=UID, email="riley@example.com", permission=PermissionLevel.CAN_EDIT,
                         duration=3600, rotate=False)
    req = env.store.get(aid)
    assert req.status == RequestStatus.APPROVED
    assert "Approved" in card_text(env.zoom.last_card())
    (dm_to, dm) = env.zoom.dms[-1]
    assert dm_to == REQUESTER["userJid"]
    assert "Access Granted" in card_text(dm) and f"#detail/{UID}" in card_text(dm)


def test_permanent_only_permission_ignores_duration(env):
    aid, _ = _submit(env, f"{UID} need ownership")
    env.post(choose(f"dur|{aid}|1h"))
    env.post(choose(f"perm|{aid}|change_owner"))
    env.post(click(f"approve|{aid}|"))
    assert env.keeper.grants[0]["permission"] == PermissionLevel.CHANGE_OWNER
    assert env.keeper.grants[0]["duration"] is None


def test_self_approval_blocked(env):
    aid, _ = _submit(env, f"{UID} need it")
    env.post(click(f"approve|{aid}|", user=REQUESTER))
    assert env.keeper.grants == []
    assert env.store.get(aid).status == RequestStatus.PENDING
    assert "cannot approve your own request" in card_text(env.zoom.ephemerals_for(REQUESTER["userJid"])[-1])


def test_requester_cannot_change_selections(env):
    aid, _ = _submit(env, f"{UID} need it")
    env.post(choose(f"perm|{aid}|change_owner", user=REQUESTER))
    assert env.store.get(aid).permission == PermissionLevel.VIEW_ONLY.value


def test_double_approve_only_grants_once(env):
    aid, _ = _submit(env, f"{UID} need it")
    env.post(click(f"approve|{aid}|"))
    env.post(click(f"approve|{aid}|"))
    assert len(env.keeper.grants) == 1
    assert "already processed" in card_text(env.zoom.ephemerals_for(APPROVER["userJid"])[-1])


def test_deny(env):
    aid, _ = _submit(env, f"{UID} need it")
    env.post(click(f"deny|{aid}|"))
    req = env.store.get(aid)
    assert req.status == RequestStatus.DENIED
    assert "Denied by Avery Approver" in card_text(env.zoom.last_card())
    assert "Denied" in card_text(env.zoom.dms[-1][1])
    assert env.keeper.grants == []


def test_invalid_select_value_ignored(env):
    aid, _ = _submit(env, f"{UID} need it")
    env.post(choose(f"perm|{aid}|owner"))  # NSF-only role on a Classic record
    assert env.store.get(aid).permission == PermissionLevel.VIEW_ONLY.value


# ----------------------------------------------------------------------
# Error handling
# ----------------------------------------------------------------------

def test_pam_rotation_not_configured_keeps_request_open(env):
    env.keeper.grant_result = {"success": False, "error_code": "pam_rotation_not_configured", "error": "x"}
    aid, card = _submit(env, f"{PAM_UID} rotate test")
    assert f"rot|{aid}|yes" in card_values(card)
    assert f"dur|{aid}|permanent" not in card_values(card)

    env.post(click(f"approve|{aid}|"))
    assert env.keeper.grants[0]["rotate"] is True
    req = env.store.get(aid)
    assert req.status == RequestStatus.PENDING and "Rotation is not configured" in req.banner

    env.keeper.grant_result = {"success": True, "expires_at": "soon"}
    env.post(choose(f"rot|{aid}|no"))
    env.post(click(f"approve|{aid}|"))
    assert env.keeper.grants[1]["rotate"] is False
    assert env.store.get(aid).status == RequestStatus.APPROVED


def test_owner_error_closes_card(env):
    env.keeper.grant_result = {"success": False, "error": "Cannot grant access to record owner (x)."}
    aid, _ = _submit(env, f"{UID} need it")
    env.post(click(f"approve|{aid}|"))
    assert env.store.get(aid).status == RequestStatus.OWNER
    assert "Owner" in card_text(env.zoom.last_card())


def test_permission_conflict_keeps_request_open(env):
    env.keeper.grant_result = {"success": False,
                               "error": "This user already has existing permissions. First revoke the user's existing access"}
    aid, _ = _submit(env, f"{UID} need it")
    env.post(click(f"approve|{aid}|"))
    assert env.store.get(aid).status == RequestStatus.PENDING


def test_invitation_sent(env):
    env.keeper.grant_result = {"success": True, "invitation_sent": True, "expires_at": "Pending Invitation"}
    aid, _ = _submit(env, f"{UID} need it")
    env.post(click(f"approve|{aid}|"))
    assert env.store.get(aid).status == RequestStatus.INVITATION_SENT
    assert "Share Invitation Sent" in card_text(env.zoom.dms[-1][1])


def test_unresolvable_requester_email(env):
    env.zoom.emails.pop("req-1")
    aid, _ = _submit(env, f"{UID} need it")
    env.post(click(f"approve|{aid}|"))
    assert env.keeper.grants == []
    assert "email" in env.store.get(aid).banner


# ----------------------------------------------------------------------
# Description (search) flow
# ----------------------------------------------------------------------

def test_description_search_select_approve_nsf(env):
    aid, card = _submit(env, '"nsf" need the secret')
    values = card_values(card)
    assert f"search|{aid}|" in values and f"approve|{aid}|" not in values

    # Approve isn't possible before a record is chosen
    env.post(click(f"approve|{aid}|"))
    assert env.keeper.grants == env.keeper.nsf_grants == []

    env.post(click(f"search|{aid}|"))
    card = env.zoom.last_card()
    assert f"rec|{aid}|0" in card_values(card)

    env.post(choose(f"rec|{aid}|0"))
    card = env.zoom.last_card()
    assert f"perm|{aid}|full-manager" in card_values(card)  # NSF roles offered

    env.post(choose(f"perm|{aid}|content-manager"))
    env.post(choose(f"dur|{aid}|24h"))
    env.post(click(f"approve|{aid}|"))

    (grant,) = env.keeper.nsf_grants
    assert grant == dict(uid=NSF_UID, email="riley@example.com",
                         role=NSFPermissionRole.CONTENT_MANAGER, duration=86400)
    assert env.store.get(aid).status == RequestStatus.APPROVED


def test_description_search_form_submit_and_change_record(env):
    aid, _ = _submit(env, '"nsf" need the secret')
    env.post(click(f"search|{aid}|"))
    card = env.zoom.last_card()
    assert card["settings"] == {"form": True}
    assert f"rec|{aid}|0" in card_values(card) and f"approve|{aid}|" not in card_values(card)

    # Submit without choosing: nothing selected, approver is told to pick one
    env.post(submit(None, f"pick|{aid}|"))
    assert env.store.get(aid).selected_item is None
    assert "Select an item" in card_text(env.zoom.ephemerals_for(APPROVER["userJid"])[-1])

    env.post(submit(f"rec|{aid}|0", f"pick|{aid}|"))
    card = env.zoom.last_card()
    assert env.store.get(aid).selected_item.uid == NSF_UID
    assert "settings" not in card
    assert {f"approve|{aid}|", f"change|{aid}|"} <= set(card_values(card))

    env.post(click(f"change|{aid}|"))
    assert env.store.get(aid).selected_item is None
    assert f"rec|{aid}|0" in card_values(env.zoom.last_card())


def test_every_search_runs_sync_down_first(env):
    aid, _ = _submit(env, '"nsf" need the secret')
    env.post(click(f"search|{aid}|"))
    assert env.keeper.syncs == 1
    assert "Syncing the vault" in card_text(env.zoom.edits[-2][1])
    assert f"rec|{aid}|0" in card_values(env.zoom.last_card())

    env.post(click(f"search|{aid}|"))
    assert env.keeper.syncs == 2


def test_form_submit_blocks_self_approval_by_jid(env):
    aid, _ = _submit(env, '"nsf" need the secret')
    env.post(click(f"search|{aid}|"))
    env.post(submit(f"rec|{aid}|0", f"pick|{aid}|", user={**REQUESTER, "userId": ""}))
    assert env.store.get(aid).selected_item is None


def test_description_search_no_results(env):
    aid, _ = _submit(env, '"does not exist" need it')
    env.post(click(f"search|{aid}|"))
    assert "No records found" in card_text(env.zoom.last_card())


def test_requester_cannot_search_own_request(env):
    aid, _ = _submit(env, '"prod" need it')
    env.post(click(f"search|{aid}|", user=REQUESTER))
    assert env.store.get(aid).searched is False


def test_state_survives_restart(env):
    from src.approval_store import ApprovalStore
    aid, _ = _submit(env, f"{UID} need it")
    env.post(choose(f"dur|{aid}|7d"))
    reloaded = ApprovalStore(env.app.config.data_dir)
    assert reloaded.get(aid).duration == "7d"


def test_setup_mode_reports_channel_jid(env):
    env.app.config._data["zoom"]["approvals_channel_jid"] = "xxxxxxxx@conference.xmpp.zoom.us"
    env.post(slash(f"{UID} need it"))
    (msg,) = env.zoom.ephemerals_for(REQUESTER["userJid"])
    assert CHANNEL in card_text(msg) and "not configured" in card_text(msg)
    # Only the private reply was sent: no approval card was posted to a channel
    assert all(vis for _, _, vis in env.zoom.sent)
    assert env.store._items == {}


def test_self_approval_allowed_when_configured(env):
    env.app.config._data["approvals"] = {"allow_self_approval": True}
    aid, _ = _submit(env, f"{UID} need it")
    env.post(click(f"approve|{aid}|", user=REQUESTER))
    assert len(env.keeper.grants) == 1
    assert env.store.get(aid).status == RequestStatus.APPROVED
