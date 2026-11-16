"""Approver "Create New Record" on a description-based record request (search results button)."""

import logging

from src.models import NSFPermissionRole, PermissionLevel, RequestStatus

from conftest import APPROVER, CHANNEL, REQUESTER, card_text, card_values, choose, click, slash

NEW_UID = "NeWrEcOrDuId0123456789"


def _request(env, cmd='request-record "new staging db" need it for the release'):
    env.post(slash(cmd))
    _, card, _ = env.zoom.sent[0]
    return next(v for v in card_values(card) if v.startswith("deny|")).split("|")[1]


def _open_form(env, aid):
    env.post(click(f"search|{aid}|"))
    env.post(click(f"newrec|{aid}|"))
    return env.zoom.last_card()


def _submit_form(env, aid, fields, model="nsf", self_destruct="off", user=APPROVER):
    """The permission model is set with its button first; the submit carries the self-destruct dropdown."""
    if model == "classic":
        env.post(click(f"nrvault|{aid}|classic", user=user))
    # Zoom's shape for form dropdowns: ``selectedItems`` is a list of the chosen options
    items = [{"actionItem": {"text": "Create Record", "value": f"newrecsub|{aid}|"}}]
    if model == "classic":
        items.append({"selectedItems": [{"text": self_destruct, "value": f"nrsd|{aid}|{self_destruct}"}]})
    items += [{"plain_text_input": {"action_id": k, "value": v}} for k, v in fields.items()]
    env.post({"event": "chat_message.submit",
              "payload": {"account_id": "acct-1", "operator_id": user["userId"],
                          "object": {"to_jid": CHANNEL, "user_jid": user["userJid"], "submit_items": items}}})


def test_button_only_for_description_record_requests(env):
    aid = _request(env)
    env.post(click(f"search|{aid}|"))
    assert f"newrec|{aid}|" in card_values(env.zoom.last_card())  # shown on "no results" too

    for cmd in ('request-folder "staging" need it', 'one-time-share "prod" need it'):
        env.zoom.sent.clear()
        other = _request(env, cmd)
        env.post(click(f"search|{other}|"))
        assert f"newrec|{other}|" not in card_values(env.zoom.last_card())


def test_form_fields_and_no_folder_picker(env):
    aid = _request(env)
    card = _open_form(env, aid)
    assert card["settings"] == {"form": True}
    text = card_text(card)
    for label in ("Title (required)", "Login (required)", "Password", "Website Address", "Notes",
                  "1. Permission model", "2. Record details", "*Create New Record* for Riley Requester"):
        assert label in text
    assert "new staging db" in text  # title pre-filled with the search query
    form = [i for s in card["body"] for i in s.get("sections", [])]
    assert not any(i["type"] in ("select", "radio_buttons") for i in form)  # NSF default: no self-destruct

    def model_styles(card):
        return {b["value"]: b["style"] for s in card["body"] for i in s.get("sections", [])
                if i["type"] == "actions" for b in i["items"] if b["value"].startswith("nrvault|")}

    assert model_styles(card) == {f"nrvault|{aid}|nsf": "Primary", f"nrvault|{aid}|classic": "Default"}
    env.post(click(f"nrvault|{aid}|classic"))
    card = env.zoom.last_card()
    form = [i for s in card["body"] for i in s.get("sections", [])]
    assert [i["text"] for i in form if i["type"] == "select"] == ["Self-destruct"]
    assert model_styles(card) == {f"nrvault|{aid}|nsf": "Default", f"nrvault|{aid}|classic": "Primary"}
    env.post(click(f"nrvault|{aid}|nsf"))
    assert "Self-destruct\"" not in card_text(env.zoom.last_card())

    env.post(click(f"newrecback|{aid}|"))
    assert env.store.get(aid).creating_record is False
    assert f"newrec|{aid}|" in card_values(env.zoom.last_card())


def test_create_nsf_record_then_approve(env, caplog):
    aid = _request(env)
    _open_form(env, aid)
    with caplog.at_level(logging.DEBUG):
        _submit_form(env, aid, {"nr_title": "Staging DB", "nr_login": "admin", "nr_password": "S3cret-Pass!",
                                "nr_url": "https://db", "nr_notes": ""})
    assert "S3cret-Pass!" not in caplog.text

    (created,) = env.keeper.created
    assert created == dict(title="Staging DB", folder_uid=None, is_nsf=True, login="admin",
                           password="S3cret-Pass!", url="https://db", notes=None, generate_password=False)
    request = env.store.get(aid)
    assert request.selected_item.uid == NEW_UID and request.selected_item.is_nsf
    card = env.zoom.last_card()
    assert f"approve|{aid}|" in card_values(card) and "S3cret-Pass!" not in card_text(card)

    env.post(choose(f"perm|{aid}|content-manager"))
    env.post(click(f"approve|{aid}|"))
    (grant,) = env.keeper.nsf_grants
    assert grant["uid"] == NEW_UID and grant["role"] == NSFPermissionRole.CONTENT_MANAGER
    assert env.store.get(aid).status == RequestStatus.APPROVED


def test_classic_self_destruct_is_view_only_for_its_duration(env):
    aid = _request(env)
    _open_form(env, aid)
    _submit_form(env, aid, {"nr_title": "Temp", "nr_login": "bob", "nr_password": ""},
                 model="classic", self_destruct="1h")

    (created,) = env.keeper.created
    assert created["is_nsf"] is False and created["self_destruct"] == "1h" and created["generate_password"]
    card = env.zoom.last_card()
    assert "Self-Destruct Record Settings" in card_text(card)
    assert not any(v.startswith(("perm|", "dur|")) for v in card_values(card))

    env.post(click(f"approve|{aid}|"))
    (grant,) = env.keeper.grants
    assert grant["uid"] == NEW_UID and grant["permission"] == PermissionLevel.VIEW_ONLY and grant["duration"] == 3600
    assert "Self-Destruct Record Access Approved" in card_text(env.zoom.last_card())
    (_, dm), = env.zoom.dms
    assert "automatically delete from the vault after 1 hour" in card_text(dm)


def test_validation_keeps_form_with_typed_values(env):
    aid = _request(env)
    _open_form(env, aid)

    _submit_form(env, aid, {"nr_title": "Temp", "nr_login": "", "nr_url": "https://x"})
    assert "Login is required" in card_text(env.zoom.last_card())
    assert "https://x" in card_text(env.zoom.last_card())

    assert env.keeper.created == []


def test_commander_error_shown_on_form(env):
    env.keeper.create_result = {"success": False, "error": "Failed to create record: boom"}
    aid = _request(env)
    _open_form(env, aid)
    _submit_form(env, aid, {"nr_title": "Temp", "nr_login": "bob", "nr_password": "pw"})
    card = env.zoom.last_card()
    assert "Could not create record" in card_text(card) and "boom" in card_text(card)
    assert "pw" not in [i.get("value") for s in card["body"] for i in s.get("sections", [])]
    assert env.store.get(aid).creating_record is True


def test_requester_cannot_create_record(env):
    aid = _request(env)
    env.post(click(f"search|{aid}|"))
    env.post(click(f"newrec|{aid}|", user=REQUESTER))
    assert env.store.get(aid).creating_record is False
    _submit_form(env, aid, {"nr_title": "Temp", "nr_login": "bob"}, user=REQUESTER)
    assert env.keeper.created == []


def test_classic_without_self_destruct(env):
    aid = _request(env)
    _open_form(env, aid)
    _submit_form(env, aid, {"nr_title": "T", "nr_login": "bob"}, model="classic", self_destruct="off")
    (created,) = env.keeper.created
    assert created["is_nsf"] is False and "self_destruct" not in created


def test_create_new_record_button_style_consistent(env):
    aid = _request(env)
    env.post(click(f"search|{aid}|"))   # no results
    styles = [b["style"] for s in env.zoom.last_card()["body"] for i in s.get("sections", [])
              if i["type"] == "actions" for b in i["items"] if b["value"] == f"newrec|{aid}|"]
    env.zoom.sent.clear()
    other = _request(env, 'request-record "prod" need it')
    env.post(click(f"search|{other}|"))  # results
    styles += [b["style"] for s in env.zoom.last_card()["body"] for i in s.get("sections", [])
               if i["type"] == "actions" for b in i["items"] if b["value"] == f"newrec|{other}|"]
    assert styles == ["Primary", "Primary"]
