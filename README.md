# Keeper Zoom Team Chat App

Zoom port of the [Keeper Slack App](https://github.com/Keeper-Security/slack-app).
This version implements **`/keeper request-record`**, **`/keeper request-folder`** and **`/keeper help`**,
as a **user-managed** Zoom app. Other sub-commands reply "not available yet"; unknown ones show help.

Configuration (Zoom credentials, Commander Service Mode URL and API key) comes from a
single **YAML file**. Keeper Secrets Manager is not used.

To create and add the Zoom app itself, see [integrationsetup.md](integrationsetup.md).

---

## What the commands do

```
/keeper request-record <Record UID>           <justification>
/keeper request-record "<record description>" <justification>
/keeper request-folder <Folder UID>           <justification>
/keeper request-folder "<folder description>" <justification>
```

`request-folder` works like `request-record` (below) with these differences, matching the Slack app:

| | Record | Folder |
|---|---|---|
| Search | `search -c r` | `search -c s,d` (Classic shared folders and Nested Share Folders) |
| Classic permissions | View Only … Change Owner (Can Share, Edit & Share, Change Owner are permanent) | No User Permissions, Can Manage Users, Can Manage Records, Can Manage Records and Users (Manage Users and Manage All are permanent) |
| Nested Share Folder | NSF roles incl. Transfer Ownership (`nsf-share-record`) | NSF roles without Transfer Ownership (`nsf-share-folder`) |
| PAM rotate-on-expire | PAM User records | Shared folders with eligible PAM User records (`list-sf <uid> --roe-eligible`) |
| Grant | Revoke, then `share-record` (owner check first) | `share-folder -a grant -o/-p … -f` |
| Vault link in the DM | `#detail/<uid>` | `#shared_folder/<uid>` |

1. **Requester** runs the command in any chat or in the bot's 1:1 chat.
   - Input is validated and sanitized the same way as in the Slack app (length limits, `@all` and
     shell-character stripping, quoted descriptions).
   - **UID:** the record is looked up in Commander (`search <uid>`). Unknown UIDs and folder UIDs are rejected.
   - The requester gets a private confirmation as a DM from the bot.
2. An **approval card** is posted to the approvals channel. With multi-channel approvers enabled, it goes
   to the channel of the requester's Keeper team instead.
   - **UID request:** record details, a *Permission Level* dropdown, *Grant Access For* (duration),
     and **Approve** / **Deny** buttons.
   - **Description request:** **Search Records** / **Deny**. *Search* (and *Search Again*) runs `sync-down`, then `search -c r "<description>"`, so records just created in the vault are found
     and lists up to 10 results as a radio group (`[Classic]` / `[NSF]` badge, title, UID) in a Zoom form card;
     *Use Selected Record* submits the choice (`chat_message.submit`), and *Change Record* goes back to the list. After a record is picked, the permission and
     duration controls appear.
   - **Nested Share Folder records** get the NSF roles (Viewer … Transfer Ownership) and are shared with
     `nsf-share-record`. **Classic records** use `share-record` flags.
   - **PAM User records** don't offer *No Expiration*, and get a *PAM credential rotation* dropdown
     (`--rotate-on-expiration`).
3. **Approver** clicks **Approve**:
   - Self-approval is blocked. The requester also can't change the dropdowns or run Search on their own request.
   - `sync-down` runs, then a record-owner check, then revoke and re-grant with the chosen permission and
     `--expire-in`. Can Share, Edit & Share, Change Owner and NSF Transfer Ownership are always permanent.
   - The card changes to *Approved* and the requester gets a DM with a vault link and the expiry time.
   - **Invitation sent** (requester has no Keeper account): the card and the DM explain the next steps.
   - **Owner / failure:** the card is closed with the reason.
   - **Permission conflict, PAM rotation not configured, Commander 401/403:** the request stays open with
     a warning on the card, so it can be fixed and approved again.
4. **Deny** closes the card and sends the requester a DM.

Every outcome is written to the audit log in the same format as the Slack app.

### Slack → Zoom differences in the implementation

| Slack app | This app |
|---|---|
| Socket Mode | HTTPS webhook `POST /zoom/webhook`, verified with the Secret Token (`x-zm-signature`, 5-minute replay window) and acknowledged immediately; work runs on a thread pool |
| Request data in the button `value`, dropdown choices read from `state` on click | Zoom sends only the clicked value, so requests and approver choices are stored in `data/approvals.json` ([src/approval_store.py](src/approval_store.py)) and survive restarts |
| Search modal with radio buttons | Form card in the channel: radio group of results + submit button (`chat_message.submit` event) |
| Bare command opens a modal | Bare command shows usage (chatbots can't open modals) |
| `users.info` for email | `zoom.user_emails` in the config, then `GET /v2/users/me` with the OAuth token stored at `/zoom/oauth/callback` when the app is added (a user-managed token can only read the user who added the app) |
| `chat.postEphemeral` | DM from the bot (`visible_to_user` needs an admin-managed app) |
| Approve on a UID request always used Classic `share-record` | NSF records found by UID use the NSF roles and `nsf-share-record` |

---

## Project layout

```
run_zoom.py                     entry point
zoom_config.example.yaml        configuration template (copy to zoom_config.yaml)
src/
  app.py                        Flask webhook server, signature check, event routing
  config.py                     YAML config loader and validation
  zoom_client.py                Zoom API: chatbot token, send/edit message, user email, OAuth
  keeper_client.py              Commander Service Mode: search, get, share-record, nsf-share-record, ...
  approval_store.py             persisted approval requests
  views.py                      Zoom message cards (approval card, DMs)
  commands/router.py            /keeper sub-command routing and help
  commands/request_access.py    request-record / request-folder validation and card posting
  handlers/approvals.py         Approve / Deny buttons and dropdown selections
  handlers/search.py            Search Records / Search Folders button
  models.py, utils.py, logger.py, commander_errors.py
tests/                          end-to-end tests through the webhook with fake Zoom and Commander
```

---

## Setup

### 1. Zoom app

Follow [integrationsetup.md](integrationsetup.md), with these values:

| Setting | Value |
|---|---|
| Features → Surface → Team Chat → **Slash Command** | `keeper` in production (one app per tenant). A dev app can use another name, e.g. `keeperdemo`; the server ignores the command name. |
| **Bot Endpoint URL** and Event Subscription | `https://<public-host>/zoom/webhook` |
| **OAuth Redirect URL** | `https://<public-host>/zoom/oauth/callback` |
| App management | **User-managed** |
| Scopes | `imchat:userapp`, `team_chat:read:user_message` |

After the app is running behind the public URL, add (or re-add) the app (**Local test → Add app**). Zoom
redirects to `/zoom/oauth/callback`, which stores your token in `data/zoom_oauth_token.json`, and the token
is refreshed automatically. That token resolves the email of the user who added the app. Every other
requester must be mapped in `zoom.user_emails` (their Zoom user ID is logged as
`... by <name> (<user id>) -> ...`), otherwise Approve fails with *"Could not resolve the requester's Zoom
email"*.

Add the app to the approvals channel and use the channel's JID for `zoom.approvals_channel_jid`. A channel
link `https://<host>/launch/chat/v2/<base64>` decodes to `{"sid":"<channel JID>"}`.

After creating a new app, update all of `client_id`, `client_secret`, `bot_jid` and
`secret_token` in `zoom_config.yaml`, restart, and add the new app so its token replaces the old one.

**A user's Zoom email must match their Keeper email.**

### 2. Commander Service Mode

Run Service Mode as the Keeper service account, the same way as for the Slack app. The command allowlist
must include:

```
search, get, share-record, nsf-share-record, share-folder, nsf-share-folder, list-sf, sync-down, server, list-team
```

### 3. Configuration

```bash
cp zoom_config.example.yaml zoom_config.yaml
chmod 600 zoom_config.yaml
# fill in zoom.* and keeper.*
```

The config file is found in this order: `$ZOOM_CONFIG_PATH`, `./zoom_config.yaml`, `./config/zoom_config.yaml`,
`~/.keeper/zoom_config.yaml`.

### 4. Run

**Local (development):**

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python run_zoom.py                 # listens on :3000
ngrok http 3000 --domain=<your-static-domain>.ngrok.app
```

**Docker:**

```bash
# edit the commander-zoom placeholders in docker-compose.yml first
export CLOUDFLARE_TUNNEL_TOKEN=...           # or remove the cloudflared service
docker compose up -d --build
docker logs -f keeper-zoom-app
```

`keeper.service_url` inside Docker: `http://commander-zoom:8900/api/v2` (`localhost` is rewritten to this
automatically).

### 5. Test

```bash
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest -q
```

Then in Zoom: `/keeper request-record "prod db" Need to run migration` → the card appears in the approvals
channel → Search Records → select a record → Approve → the requester gets a DM.

---

## Not confirmed against a live Zoom account

The request and response shapes follow Zoom's chatbot documentation but have not been run against a live
account yet. Check these during the first setup:

- The `chat_message.submit` payload for the radio group (`submit_items[]`). The handler logs the raw items at DEBUG and
  accepts the value under `value`, `selected_option.value` or `selected_item.value`.
- `divider` and `alert` blocks, and `radio_buttons` inside a form card, in the chatbot (not App Card Builder) message API.
- The `interactive_message_select` payload (`selectedItems[].value`) and how dropdown `selected_item`
  renders after a card edit.
- Whether `bot_notification` includes the user's email. If it does, it's used directly and the OAuth token
  isn't needed for that request.
