"""End-to-end tests for /keeper one-time-share."""

import json

from src.models import RequestStatus

from conftest import (
    APPROVER, CHANNEL, FOLDER_UID, NSF_UID, PAM_UID, UID,
    card_text, card_values, choose, click, slash, submit,
)


def _submit_share(env, text):
    assert env.post(slash(f"one-time-share {text}")).status_code == 200
    channel, card, _ = env.zoom.sent[0]
    assert channel == CHANNEL
    aid = next(v for v in card_values(card) if v.startswith("deny|")).split("|")[1]
    return aid, card


def card_text_items(card):
    items = list(card["body"])
    for item in items:
        if item["type"] == "section":
            items += item["sections"]
    return items


def _reply_text(env):
    return card_text(env.zoom.ephemerals_for("req-1@xmpp.zoom.us")[-1])


def test_card_offers_view_or_edit_and_no_permanent_link(env):
    aid, card = _submit_share(env, f"{UID} share with vendor")
    assert "One-Time Share Request" in card_text(card)
    values = card_values(card)
    assert {f"perm|{aid}|view_only", f"perm|{aid}|can_edit"} <= set(values)
    assert f"perm|{aid}|can_share" not in values
    durations = [v.split("|")[2] for v in values if v.startswith(f"dur|{aid}|")]
    assert durations == ["5m", "10m", "30m", "1h", "4h", "8h", "24h", "7d", "30d"]
    selected = [i for i in card_text_items(card) if i.get("type") == "select" and "selected_item" in i
                and i["selected_item"]["value"].startswith(f"dur|{aid}|")]
    assert selected[0]["selected_item"]["value"] == f"dur|{aid}|5m"
    assert "submitted" in _reply_text(env)


def test_approve_creates_link_and_dms_it_only_to_requester(env):
    aid, _ = _submit_share(env, f"{UID} share with vendor")
    env.post(choose(f"perm|{aid}|can_edit"))
    env.post(choose(f"dur|{aid}|1h"))
    env.post(click(f"approve|{aid}|"))

    assert env.keeper.shares == [dict(uid=UID, duration=3600, editable=True)]
    request = env.store.get(aid)
    assert request.status == RequestStatus.APPROVED

    dm_to, dm = env.zoom.dms[-1]
    assert dm_to == "req-1@xmpp.zoom.us" and "vault/share#SECRET" in card_text(dm)
    # The link is never posted to the channel card or persisted
    assert "SECRET" not in card_text(env.zoom.last_card())
    assert "SECRET" not in json.dumps(request.to_dict())


def test_view_only_by_default(env):
    aid, _ = _submit_share(env, f"{UID} need it")
    env.post(click(f"approve|{aid}|"))
    assert env.keeper.shares[0]["editable"] is False and env.keeper.shares[0]["duration"] == 300


def test_record_only_permissions_rejected(env):
    aid, _ = _submit_share(env, f"{UID} need it")
    env.post(choose(f"perm|{aid}|change_owner"))
    env.post(choose(f"dur|{aid}|permanent"))
    env.post(choose(f"dur|{aid}|90d"))
    request = env.store.get(aid)
    assert request.permission == "view_only" and request.duration == "5m"


def test_pam_record_rejected(env):
    env.post(slash(f"one-time-share {PAM_UID} need it"))
    assert "PAM Record Not Supported" in _reply_text(env)
    assert all(vis for _, _, vis in env.zoom.sent)


def test_nsf_record_rejected(env):
    env.post(slash(f"one-time-share {NSF_UID} need it"))
    assert "Nested Share Folder Record Not Supported" in _reply_text(env)


def test_folder_uid_rejected(env):
    env.post(slash(f"one-time-share {FOLDER_UID} need it"))
    assert "is a *folder*" in _reply_text(env)


def test_search_excludes_pam_and_nsf(env):
    aid, _ = _submit_share(env, '"P" need it')  # matches "Prod DB" and "PAM root"
    env.post(click(f"search|{aid}|"))
    assert [r["uid"] for r in env.store.get(aid).search_results] == [UID]
    env.post(submit(f"rec|{aid}|0", f"pick|{aid}|"))
    env.post(click(f"approve|{aid}|"))
    assert env.keeper.shares[0]["uid"] == UID


def test_share_failure_closes_card(env):
    env.keeper.share_result = {"success": False, "error": "Record not found"}
    aid, _ = _submit_share(env, f"{UID} need it")
    env.post(click(f"approve|{aid}|"))
    assert env.store.get(aid).status == RequestStatus.FAILED
    assert env.zoom.dms == []


def test_commander_rejection_keeps_request_open(env):
    env.keeper.share_result = {"success": False, "error_code": "command_not_allowed", "error": "not allowed"}
    aid, _ = _submit_share(env, f"{UID} need it")
    env.post(click(f"approve|{aid}|"))
    assert env.store.get(aid).status == RequestStatus.PENDING
    assert "Cannot Create One-Time Share" in card_text(env.zoom.ephemerals_for(APPROVER["userJid"])[-1])


def test_deny(env):
    aid, _ = _submit_share(env, f"{UID} need it")
    env.post(click(f"deny|{aid}|", user=APPROVER))
    assert "One-time share request was denied" in card_text(env.zoom.dms[-1][1])
