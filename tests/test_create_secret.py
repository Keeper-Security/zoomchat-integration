"""End-to-end tests for /keeper create-secret (two form cards in the user's 1:1 chat)."""

import json
import logging

from conftest import CHANNEL, FOLDER_UID, NSF_FOLDER_UID, REQUESTER, card_text, click, slash

SECRET = "Sup3r-S3cret!"


def _values(card):
    """All interactive values (buttons, radio options, dropdown items) in a card."""
    values, items = [], list(card["body"])
    for item in items:
        if item["type"] == "section":
            items += item["sections"]
        if item["type"] == "actions":
            values += [b["value"] for b in item["items"]]
        if item["type"] == "radio_buttons":
            values += [o["value"] for o in item["options"]]
        if item["type"] == "select":
            values += [o["value"] for o in item["select_items"]]
    return values


def _submit(button, inputs, user=REQUESTER):
    items = [{"actionItem": {"text": "x", "value": button}}]
    for action_id, value in inputs.items():
        if value.startswith("csf|"):
            items.append({"radio_buttons_item": {"value": value, "action_id": action_id}})
        elif value.startswith("cssub|"):
            # Zoom's shape for form dropdowns: a list of the chosen options
            items.append({"selectedItems": [{"text": "x", "value": value}]})
        else:
            items.append({"plain_text_input": {"text": action_id, "value": value, "action_id": action_id}})
    return {"event": "chat_message.submit",
            "payload": {"account_id": "acct-1", "operator_id": user["userId"],
                        "object": {"bot_msg_id": "msg-1", "to_jid": user["userJid"],
                                   "user_jid": user["userJid"], "submit_items": items}}}


def _start(env):
    env.post(slash("create-secret"))
    to_jid, card, _ = env.zoom.sent[0]
    assert to_jid == REQUESTER["userJid"]  # in the user's 1:1 chat, not a channel
    return env.zoom.last_card()


def _pick_folder(env, uid=FOLDER_UID):
    folder_card = _start(env)
    choice = next(v for v in _values(folder_card) if v.startswith("csf|") and uid in v)
    env.post(_submit("csnext||", {"csf": choice}))
    return env.zoom.last_card()


def test_folder_picker_lists_only_users_shared_folders(env):
    card = _start(env)
    assert card["settings"] == {"form": True}
    text = card_text(card)
    assert "Staging creds" in text and "NSF Team" in text


def test_no_shared_folders(env):
    env.keeper.shared_folders = {}
    assert "No shared folders found" in card_text(_start(env))


def test_commander_error_shown(env):
    env.keeper.shared_folders_error = {"error_code": "keeper_session_expired", "error": "session has expired"}
    assert "session has expired" in card_text(_start(env))


def test_next_without_folder_asks_to_choose(env):
    _start(env)
    env.post(_submit("csnext||", {}))
    assert "Select a shared folder" in card_text(env.zoom.ephemerals_for(REQUESTER["userJid"])[-1])


def test_subfolder_dropdown_first_and_indented(env):
    env.keeper.subfolders["FoLdErUiD0123456789abc"] = [
        {"uid": "B" * 22, "name": "POD 1", "path": "Prod/POD 1", "is_nsf": False},
        {"uid": "C" * 22, "name": "Dev", "path": "Dev", "is_nsf": False},
        {"uid": "A" * 22, "name": "Prod", "path": "Prod", "is_nsf": False},
    ]
    form = _pick_folder(env)
    items = form["body"][0]["sections"]
    assert [i["type"] for i in items[:3]] == ["message", "select", "plain_text_input"]  # right after the folder line
    assert [o["text"] for o in items[1]["select_items"]] == [
        ":file_folder: Staging creds (top level)", "└ Dev", "└ Prod", "\u2003└ POD 1"]


def test_record_form_has_fields_warning_and_subfolders(env):
    form = _pick_folder(env)
    text = card_text(form)
    for action_id in ("cs_title", "cs_login", "cs_password", "cs_url", "cs_notes"):
        assert action_id in text
    assert "pass through Zoom" in text
    assert any(v.startswith("cssub|") and "SuBfOlDeRuId" in v for v in _values(form))


def test_create_with_auto_generated_password_and_notification(env):
    form = _pick_folder(env)
    create = next(v for v in _values(form) if v.startswith("cscreate|"))
    env.post(_submit(create, {"cs_title": "Prod DB", "cs_login": "admin", "cs_password": "",
                              "cs_url": "https://db.example.com", "cs_notes": "line1\nline2"}))

    (created,) = env.keeper.created
    assert created == dict(title="Prod DB", folder_uid=FOLDER_UID, is_nsf=False, login="admin", password=None,
                           url="https://db.example.com", notes="line1\nline2", generate_password=True)
    assert "Record Created Successfully" in card_text(env.zoom.last_card())
    notice = [c for to, c, vis in env.zoom.sent if to == CHANNEL and vis is None]
    assert notice and "New Secret Record Created" in card_text(notice[-1])
    assert "riley@example.com" in card_text(notice[-1]) and "@xmpp.zoom.us" not in card_text(notice[-1])


def test_manual_password_is_used_but_never_logged_or_echoed(env, caplog):
    caplog.set_level(logging.DEBUG)
    form = _pick_folder(env)
    create = next(v for v in _values(form) if v.startswith("cscreate|"))
    env.post(_submit(create, {"cs_title": "API key", "cs_password": SECRET}))

    assert env.keeper.created[0]["password"] == SECRET and not env.keeper.created[0]["generate_password"]
    assert SECRET not in caplog.text
    sent = json.dumps([c for _, c, _ in env.zoom.sent] + [c for _, c in env.zoom.edits])
    assert SECRET not in sent


def test_subfolder_and_nsf_target(env):
    form = _pick_folder(env)
    create = next(v for v in _values(form) if v.startswith("cscreate|"))
    sub = next(v for v in _values(form) if v.startswith("cssub|") and "SuBfOlDeRuId" in v)
    env.post(_submit(create, {"cs_title": "In subfolder", "cssub": sub}))
    assert env.keeper.created[0]["folder_uid"] == "SuBfOlDeRuId0123456789"
    assert "Staging creds / db" in card_text(env.zoom.last_card())

    form = _pick_folder(env, NSF_FOLDER_UID)
    create = next(v for v in _values(form) if v.startswith("cscreate|"))
    env.post(_submit(create, {"cs_title": "NSF secret"}))
    assert env.keeper.created[-1]["folder_uid"] == NSF_FOLDER_UID and env.keeper.created[-1]["is_nsf"] is True


def test_title_required_keeps_form(env):
    form = _pick_folder(env)
    edits_before = len(env.zoom.edits)
    create = next(v for v in _values(form) if v.startswith("cscreate|"))
    env.post(_submit(create, {"cs_title": "  "}))
    assert env.keeper.created == [] and len(env.zoom.edits) == edits_before
    assert "Title is required" in card_text(env.zoom.ephemerals_for(REQUESTER["userJid"])[-1])


def test_create_failure_shown(env):
    env.keeper.create_result = {"success": False, "error": "Folder is read-only"}
    form = _pick_folder(env)
    create = next(v for v in _values(form) if v.startswith("cscreate|"))
    env.post(_submit(create, {"cs_title": "X"}))
    assert "Failed to Create Record" in card_text(env.zoom.last_card())
    assert not [c for to, c, vis in env.zoom.sent if to == CHANNEL]


def test_cancel(env):
    _start(env)
    env.post(click("cscancel||", user=REQUESTER))
    assert "cancelled" in card_text(env.zoom.last_card())
