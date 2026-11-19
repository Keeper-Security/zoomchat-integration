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
        if value.startswith(("csf|", "cssub|")):
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
    to_jid, card, _ = env.zoom.sent[-1]
    assert to_jid == REQUESTER["userJid"]  # in the user's 1:1 chat, not a channel
    return card  # posted once, already loaded (no "Loading..." message replaced a second later)


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
    env.post(_submit("csnext||", {"cs_folder_find": "nsf"}))
    card = env.zoom.last_card()  # warning on the card, not a DM; the search is kept
    warning = next(i for i in card["body"][0]["sections"] if i["type"] == "alert" and "Select a shared" in i["text"])
    assert warning["closeable"] is True  # the user dismisses it
    assert "Select a shared folder in the dropdown first" in card_text(card) and '"value": "nsf"' in card_text(card)
    assert env.zoom.ephemerals_for(REQUESTER["userJid"]) == []


def test_subfolder_dropdown_first_with_one_line_paths(env):
    env.keeper.subfolders["FoLdErUiD0123456789abc"] = [
        {"uid": "B" * 22, "name": "POD 1", "path": "Prod/POD 1", "is_nsf": False},
        {"uid": "C" * 22, "name": "Dev", "path": "Dev", "is_nsf": False},
        {"uid": "A" * 22, "name": "Prod", "path": "Prod", "is_nsf": False},
    ]
    form = _pick_folder(env)
    items = form["body"][0]["sections"]
    assert [i["type"] for i in items[:4]] == ["message", "plain_text_input", "actions", "select"]  # Find, then Save in
    assert items[1]["action_id"] == "cs_find"
    assert [o["text"] for o in items[3]["select_items"]] == [
        "[Classic] \u2503 Staging creds (top level)", "[Classic] \u2503 Staging creds / Dev", "[Classic] \u2503 Staging creds / Prod",
        "[Classic] \u2503 Staging creds / Prod / POD 1"]


def _many_subfolders(env, n=150):
    env.keeper.subfolders[FOLDER_UID] = [
        {"uid": f"S{i:021d}", "name": f"Sub {i:03d}", "path": f"Team {i % 5}/Sub {i:03d}", "is_nsf": False}
        for i in range(n)]


def _find(env, form, text, typed=None):
    find = next(v for v in _values(form) if v.startswith("csfind|"))
    env.post(_submit(find, {"cs_find": text, **(typed or {})}))
    return env.zoom.last_card()


def test_find_folder_narrows_dropdown_and_keeps_typed_fields(env):
    _many_subfolders(env)
    form = _pick_folder(env)
    assert "Find folder" in card_text(form) and "Use Find folder to reach the rest" in card_text(form)

    found = _find(env, form, "sub 149", {"cs_title": "DB", "cs_login": "admin", "cs_password": "secret!"})
    select = next(i for i in found["body"][0]["sections"] if i["type"] == "select")
    labels = [o["text"] for o in select["select_items"]]
    assert labels == ["[Classic] \u2503 Staging creds (top level)", "[Classic] \u2503 Staging creds / Team 4 / Sub 149"]
    assert select["selected_item"]["text"] == "[Classic] \u2503 Staging creds (top level)"  # default stays the parent
    text = card_text(found)
    assert '"value": "DB"' in text and '"value": "admin"' in text and "secret!" not in text

    create = next(v for v in _values(found) if v.startswith("cscreate|"))
    env.post(_submit(create, {"cs_title": "DB", "cssub": select["select_items"][1]["value"]}))
    assert env.keeper.created[-1]["folder_uid"] == "S000000000000000000149"
    assert "Staging creds / Team 4 / Sub 149" in card_text(env.zoom.last_card())


def test_find_folder_no_match(env):
    _many_subfolders(env)
    found = _find(env, _pick_folder(env), "nothing here")
    select = next(i for i in found["body"][0]["sections"] if i["type"] == "select")
    assert len(select["select_items"]) == 1 and 'No subfolders match \\"nothing here\\"' in card_text(found)


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
    sub = next(v for v in _values(form) if v.startswith("cssub|") and "SuBfOlDeRuId" in v)
    env.post(_submit(create, {"cs_title": "  ", "cs_login": "admin", "cs_password": "pw!", "cssub": sub}))
    card = env.zoom.last_card()
    assert env.keeper.created == [] and len(env.zoom.edits) == edits_before + 1
    text = card_text(card)
    assert "Title is required" in text and '"value": "admin"' in text and "pw!" not in text
    select = next(i for i in card["body"][0]["sections"] if i["type"] == "select")
    assert "SuBfOlDeRuId" in select["selected_item"]["value"]  # chosen subfolder kept
    assert env.zoom.ephemerals_for(REQUESTER["userJid"]) == []


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


def test_folder_lists_capped_at_20(env):
    """Both create-secret dropdowns list the first 20 (Zoom itself rejects more than 100)."""
    env.keeper.shared_folders["riley@example.com"] = [
        {"uid": FOLDER_UID, "name": "A staging creds", "type": "Shared Folder", "is_nsf": False}] + [
        {"uid": f"F{i:021d}", "name": f"Folder {i:03d}", "type": "Shared Folder", "is_nsf": False}
        for i in range(149)]
    env.keeper.subfolders[FOLDER_UID] = [
        {"uid": f"S{i:021d}", "name": f"Sub {i:03d}", "path": f"Sub {i:03d}", "is_nsf": False} for i in range(150)]
    picker = _start(env)
    select = next(i for i in picker["body"][0]["sections"] if i["type"] == "select")
    assert len(select["select_items"]) == 20 and "first 20 of 150 shared folders" in card_text(picker)

    env.zoom.sent.clear()
    form = _pick_folder(env)
    select = next(i for i in form["body"][0]["sections"] if i["type"] == "select")
    assert len(select["select_items"]) == 21 and "first 20 of 150 subfolders" in card_text(form)  # + top level


def test_step1_is_search_box_and_dropdown(env):
    picker = _start(env)
    items = picker["body"][0]["sections"]
    assert [i["type"] for i in items[:3]] == ["plain_text_input", "actions", "select"]
    assert items[0]["action_id"] == "cs_folder_find" and not any(i["type"] == "radio_buttons" for i in items)

    search = next(v for v in _values(picker) if v.startswith("csffind|"))
    edits_before = len(env.zoom.edits)
    env.post(_submit(search, {"cs_folder_find": "nsf"}))
    assert len(env.zoom.edits) == edits_before + 1  # straight to the results, no interim "Searching..."
    found = env.zoom.last_card()
    select = next(i for i in found["body"][0]["sections"] if i["type"] == "select")
    assert [o["text"] for o in select["select_items"]] == ["[NSF] \u2503 NSF Team"]
    assert select["selected_item"]["value"].startswith("csf|")  # single match is picked
    assert "1 of 2 shared folder(s) match" in card_text(found)

    # Next with the chosen folder loads the subfolder step
    env.post(_submit("csnext||", {"csf": select["selected_item"]["value"]}))
    assert "Creating record in:* NSF Team" in card_text(env.zoom.last_card())


def test_step1_search_no_match(env):
    picker = _start(env)
    search = next(v for v in _values(picker) if v.startswith("csffind|"))
    env.post(_submit(search, {"cs_folder_find": "zzz"}))
    found = env.zoom.last_card()
    assert not any(i["type"] == "select" for i in found["body"][0]["sections"])
    assert 'No shared folders match \\"zzz\\"' in card_text(found)


def test_back_from_step2_returns_to_folder_step(env):
    form = _pick_folder(env)
    assert "csback||" in _values(form)
    env.post(click("csback||", user=REQUESTER))
    card = env.zoom.last_card()
    assert "Step 1 of 2" in card_text(card)
    assert any(i["type"] == "select" and i["text"] == "Shared folder" for i in card["body"][0]["sections"])


def test_create_secret_syncs_only_on_resync(env):
    picker = _start(env)
    assert env.keeper.syncs == 0
    resync = next(v for v in _values(picker) if v.startswith("csfsync|"))
    env.post(_submit(resync, {"cs_folder_find": ""}))
    assert env.keeper.syncs == 1 and "Step 1 of 2" in card_text(env.zoom.last_card())

    form = _pick_folder(env)
    sub_sync = next(v for v in _values(form) if v.startswith("cssync|"))
    env.post(_submit(sub_sync, {"cs_find": "", "cs_title": "Kept"}))
    assert env.keeper.syncs == 2 and '"value": "Kept"' in card_text(env.zoom.last_card())


def test_subfolder_of_nsf_folder_uses_nsf_record_add(env):
    """Subfolders inherit their shared folder's type, even when Commander's tree doesn't flag them."""
    env.keeper.subfolders[NSF_FOLDER_UID] = [
        {"uid": "N" * 22, "name": "POD2", "path": "POD2", "is_nsf": False}]
    form = _pick_folder(env, NSF_FOLDER_UID)
    sub = next(v for v in _values(form) if v.startswith("cssub|") and "N" * 22 in v)
    create = next(v for v in _values(form) if v.startswith("cscreate|"))
    env.post(_submit(create, {"cs_title": "POD2 Cred's", "cssub": sub}))
    assert env.keeper.created[-1]["folder_uid"] == "N" * 22 and env.keeper.created[-1]["is_nsf"] is True
