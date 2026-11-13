# Keeper Zoom Team Chat App – Integration Setup Guide

Step-by-step guide to create, configure, and add (install) the Keeper Security chatbot in **Zoom Team Chat** as a **private, self-hosted app**, the Zoom equivalent of the [Keeper Slack App](https://docs.keeper.io/keeperpam/secrets-manager/integrations/slack-app).

> **Status:** Draft for internal development and testing. Steps marked **🔎 Verify** are not yet confirmed on a live Zoom account and should be validated during first setup.

---

## Contents

1. [How it works](#1-how-it-works)
2. [Prerequisites](#2-prerequisites)
3. [Step 1 – Get Zoom developer access](#step-1--get-zoom-developer-access)
4. [Step 2 – Enable required Zoom account settings](#step-2--enable-required-zoom-account-settings)
5. [Step 3 – Prepare a public HTTPS endpoint](#step-3--prepare-a-public-https-endpoint)
6. [Step 4 – Create the Zoom app](#step-4--create-the-zoom-app)
7. [Step 5 – Basic Information](#step-5--basic-information)
8. [Step 6 – Features → Access (Secret Token)](#step-6--features--access-secret-token)
9. [Step 7 – Features → Surface (Team Chat / Chatbot)](#step-7--features--surface-team-chat--chatbot)
10. [Step 8 – Scopes](#step-8--scopes)
11. [Step 9 – Add (install) the app to your account](#step-9--add-install-the-app-to-your-account)
12. [Step 10 – Create the approvals channel and add the app](#step-10--create-the-approvals-channel-and-add-the-app)
13. [Step 11 – Collect credentials](#step-11--collect-credentials)
14. [Step 12 – Verify the setup (smoke tests)](#step-12--verify-the-setup-smoke-tests)
15. [Step 13 – Deploy with Commander (planned)](#step-13--deploy-with-commander-planned)
16. [Optional – Create the app from a manifest](#optional--create-the-app-from-a-manifest)
17. [Slack → Zoom terminology mapping](#slack--zoom-terminology-mapping)
18. [Troubleshooting](#troubleshooting)
19. [References](#references)

---

## 1. How it works

```
 Zoom Team Chat (cloud)
        │  HTTPS POST (slash commands, button clicks)   ▲  Chatbot API (send / edit messages)
        ▼                                               │
 ┌──────────────── Customer-hosted Linux VM (Docker) ───────────────────┐
 │  cloudflared tunnel  ──►  keeper-zoom-app  ──►  keeper-service       │
 │  (public HTTPS URL)       (webhook server)      (Commander Service   │
 │                                                  Mode, /api/v2)      │
 └──────────────────────────────────────────────────────────────────────┘
                                  │
                         Keeper Secrets Manager (stores all config/credentials)
```

Key differences from Slack:

| | Slack App | Zoom App |
|---|---|---|
| Event delivery | Socket Mode (outbound only, no public URL) | **HTTPS webhook** to a "Bot Endpoint URL" (public URL required, e.g. via a Cloudflare Tunnel) |
| Commands | 4 slash commands | **1 slash command** with sub-commands: `/keeper request-record …` |
| Bot token | Static `xoxb-` token | Short-lived (1 hour) token requested with Client ID + Secret (`client_credentials`) |
| Request verification | Signing secret | **Secret Token**: HMAC-SHA256 `x-zm-signature` header |
| Distribution | Created in the customer's workspace | **Private app** created in the customer's Zoom account; never published to the Marketplace |

---

## 2. Prerequisites

| Requirement | Details |
|---|---|
| Zoom account | Paid Zoom Workplace account with **Team Chat** enabled |
| Zoom role | Account **Owner**, **Admin**, or a role with **Zoom for developers** (View + Edit). See Step 1. |
| Zoom admin | Someone who can change account Chat settings (Step 2). The app itself is **user-managed**, so any developer-enabled user can add it. |
| Linux VM + Docker | Outbound HTTPS/443 to Zoom and Keeper |
| Public HTTPS URL | Cloudflare Tunnel (recommended) or ngrok, pointing to the Zoom app container. TLS 1.2+. |
| Keeper Commander | Logged in as the Keeper service account (same as the Slack app) |
| Keeper Secrets Manager | KSM or KeeperPAM license (stores the configuration) |
| Matching emails | Users' Zoom email must match their Keeper email (used for permissions and folder visibility) |

---

## Step 1 – Get Zoom developer access

The user who creates the app needs developer permissions on the Zoom account.

**Done by a Zoom account admin:**

1. Sign in to the Zoom web portal (<https://zoom.us>) as an admin.
2. Go to **User Management → Roles**.
3. Either:
   - assign the user the **Admin** role, **or**
   - edit an existing role (or create a new one, e.g. `Keeper App Developer`):
     **Role Settings → Advanced features →** check **View** and **Edit** for **Zoom for developers**, then assign that role to the user.
4. Save.

> The legacy permissions **OAuth**, **Chatbot**, and **Meeting SDK** are deprecated. Only **Zoom for developers** is needed now.

**Check:** sign in to <https://marketplace.zoom.us>. A **Developer** link should appear in the lower-left navigation. If it doesn't, the role has not taken effect.

---

## Step 2 – Enable required Zoom account settings

**Done by a Zoom account admin** in the Zoom web portal:

1. **Account Management → Account Settings → Chat**
   - Enable **Allow users to add apps to channels** (needed so the bot can be added to the approvals channel).
2. **🔎 Verify:** If the account restricts Marketplace apps (**Account Management → Account Settings → Zoom App Marketplace**, e.g. *pre-approval required*), make sure the Keeper app is allowed or pre-approved after it's created.

---

## Step 3 – Prepare a public HTTPS endpoint

Zoom must be able to POST events to the app. The URL must be up **before** you save the Bot Endpoint URL and Event Subscription in Step 7, because Zoom validates it.

**Option A – Cloudflare Tunnel (recommended for production)**

1. In Cloudflare Zero Trust → **Networks → Tunnels**, create a tunnel and copy its **tunnel token**.
2. Add a public hostname, e.g. `keeper-zoom.company.com` → `http://keeper-zoom-app:3000`.
3. Run `cloudflared` as a container next to the app (the planned `zoom-app-setup` command will generate this, see Step 13).

**Option B – ngrok (development / testing)**

```bash
ngrok http 3000 --domain=<your-static-domain>.ngrok.app
```

Endpoint paths used by the app:

| Purpose | URL |
|---|---|
| Bot Endpoint URL (slash commands, button clicks) | `https://<public-host>/zoom/webhook` |
| Event subscription endpoint | `https://<public-host>/zoom/webhook` (same handler) |
| OAuth redirect URL | `https://<public-host>/zoom/oauth/callback` |

> The webhook server must answer Zoom's `endpoint.url_validation` challenge (HMAC-SHA256 of `plainToken` using the Secret Token) or Zoom will not save the URL. For early manual testing before the app code exists, see Step 12.

---

## Step 4 – Create the Zoom app

1. Sign in to <https://marketplace.zoom.us> with the developer-enabled account.
2. Click **Developer** (lower-left) → **Created Apps** page.
3. Click **Develop → Build App** (or the **+** next to *Developer* → **Build an app**).
4. Select **General App** → **Create**.

> Alternative: **Develop → Build from an app manifest**. See [Optional – Create the app from a manifest](#optional--create-the-app-from-a-manifest).

---

## Step 5 – Basic Information

1. **App name:** click the pencil icon and rename it to `Keeper Security`.
2. **Select how the app is managed:** choose **User-managed**.
   - The user who adds the app authorizes it; it shows up under *Apps* in their Zoom client.
   - Private replies to the requester are sent as DMs from the bot (`visible_to_user` in channels is admin-managed only).
   - The stored OAuth token can only read the email of the user who added the app. Map every other
     requester's Zoom user ID to their Keeper email in `zoom.user_emails`.
3. **App Credentials:** note the **Client ID** and **Client Secret**. Keep them secret; they are equivalent to a password.
4. **OAuth Information:**
   - **OAuth Redirect URL:** `https://<public-host>/zoom/oauth/callback`
     (for testing, any HTTPS page you control works; the chatbot token flow doesn't use the returned code).
   - **OAuth Allow List:** add `https://<public-host>`.
5. Save.

> Leave the app **private**. Do **not** click *Enable Publishing / Change Now* under **Activation**, and do not submit for review. Private apps can only be used inside your own Zoom account, which is what we want.

---

## Step 6 – Features → Access (Secret Token)

1. Open **Features → Access**.
2. Copy the **Secret Token** (used to verify every request from Zoom and to answer URL validation).
   Do not use the deprecated *Verification Token*.
3. **Event Subscription:** toggle on → **Add New Event Subscription**:
   - Name: `keeper-events`
   - Method: **Webhook**
   - Endpoint URL: `https://<public-host>/zoom/webhook`
   - Events:
     - Team Chat → `team_chat_channel_chatbot_add` / `team_chat_channel_chatbot_removed` (app added to or removed from a channel)
     - **🔎 Verify:** `app_deauthorized` (app removed from the account)
     - **Required:** `chat_message.submit` (form card submitted). The search-results card is a Zoom form card (radio list + *Use Selected Record*); without this event, picking a record does nothing.
   - Click **Validate**, then **Save**. Validation only passes if the endpoint from Step 3 is running.

---

## Step 7 – Features → Surface (Team Chat / Chatbot)

1. Open **Features → Surface**.
2. **Select where to use your app:** check **Team Chat**.
3. Under **Team Chat Subscription** (Chat Subscription), toggle it **on** and fill in:

   | Field | Value |
   |---|---|
   | **Slash Command** | `keeper` (a dev app can use another name, e.g. `keeperdemo`; the server ignores it) |
   | **Command hints** (description / usage) | `request-record` → *Request access to a Keeper record*: `request-record "Record UID or description" justification`<br>`request-folder` → *Request access to a Keeper folder*: `request-folder "Folder UID or description" justification`<br>`one-time-share` → *Request a one-time share link*: `one-time-share "Record UID or description" justification`<br>`create-secret` → *Create a new secret in a shared folder*<br>`help` → *Show available commands* |
   | **Bot Endpoint URL** | `https://<public-host>/zoom/webhook` |
   | **Welcome message** | Sender: **Zoom**, with a title (e.g. *Welcome to Keeper Security*). With Sender *Your app* and no title, the client showed the bot as "Unknown app – DELETED" with disabled card buttons. The app also DMs a usage card on `bot_installed`. |
   | **Add this app to Chat channels** | **Enabled** |
   | **App supports @mention** | Optional (enable if we support `@Keeper Security help`) |
   | **Trusted domain list** | Your Keeper domain(s), e.g. `keepersecurity.com`, so one-time share links render as trusted |

4. Click **Save**.
5. Copy the **Bot JID** shown on this page (format `xxxxxxxx@xmpp.zoom.us`). It's needed to send, edit, and delete messages.
6. Leave **App Shortcuts** and **Home URL / Zoom Apps SDK** **off** for Phase 1 (no web-view modals).

---

## Step 8 – Scopes

1. Open **Scopes → Add Scopes**.
2. Make sure these are present:

   | Scope | Why | Notes |
   |---|---|---|
   | `imchat:userapp` | Send, edit, and delete chatbot messages | Added automatically when the slash command / chat subscription is enabled on a user-managed app |
   | `team_chat:read:user_message` | Read Team Chat messages for the user who added the app | |

3. Fill in **Scope Description** for each (e.g. *"Reads the requesting user's email to match their Keeper account for access approval workflows."*).
4. Save. Every time scopes change, **re-authorize (re-add)** the app (Step 9).

---

## Step 9 – Add (install) the app to your account

In Zoom terminology, apps are **added**, not installed.

1. Go to **Local Test** (or **Add your app**) in the app's build flow.
2. Click **Add App Now** → review the permissions → **Allow**.
3. Zoom redirects to the OAuth Redirect URL (`?code=…`). The app exchanges the code and stores the token in
   `data/zoom_oauth_token.json` (used to look up your email). The log shows `Stored Zoom OAuth token`.
4. Open the Zoom desktop client → **Team Chat → Apps**. **Keeper Security** should appear, and the app receives a `bot_installed` event (welcome message).
   - Direct link to the bot chat: `https://zoom.us/launch/chat?jid=robot_<BOT_JID>`
5. **🔎 Verify:** whether the other users in the account see the app right away or need the **Authorization URL** (Local Test → *Authorization URL → Generate → Copy*) shared with them. Private apps may only be shared with members of your own account.

---

## Step 10 – Create the approvals channel and add the app

1. In the Zoom client: **Team Chat → + → Create a channel**
   - Name: `keeper-vault-approvers`
   - Type: **Private**
   - Add the approvers as members.
2. Add the bot: open the channel → **members icon** (top right) → **Integrations → Add apps** → select **Keeper Security** → choose the access level → **Add**.
3. Get the **Channel ID**:
   - Copy the channel link (`https://<host>/launch/chat/v2/<base64>`); the base64 part decodes to `{"sid":"<channel JID>"}`, **or**
   - Zoom web portal → **Account Management → Team Chat Management → Channels** (or `https://zoom.us/account/imchannel`) → open the channel and copy its ID, **or**
   - From any event payload the bot receives in that channel (`toJid`).
4. Build the **Channel JID**: `<CHANNEL_ID>@conference.xmpp.zoom.us`

> Like Slack, this is the **default / fallback** approvals channel. EPM (PEDM) and SSO device approvals always go here. Multi-channel approver channels (one per Keeper team) are created the same way.

---

## Step 11 – Collect credentials

Store these in a password manager until you run the setup command (Step 13). Never commit them to source control.

| Value | Where to find it | Slack equivalent |
|---|---|---|
| **Account ID** | Not needed in the config: the app uses the `accountId` Zoom sends with every event. Only needed for the manual curl test in 12.2 (take it from any event payload). | Workspace / team ID |
| **Client ID** | Basic Information → App Credentials | – |
| **Client Secret** | Basic Information → App Credentials | Bot token (`xoxb-`), used to mint one |
| **Bot JID** | Features → Surface → Team Chat Subscription | Bot user ID |
| **Secret Token** | Features → Access | Signing secret |
| **Approvals Channel JID** | Step 10 | Approvals channel ID (`C0…`) |
| **Public endpoint URL** | Step 3 | – (Socket Mode needed none) |
| **Cloudflare tunnel token** (if used) | Cloudflare Zero Trust | App-level token (`xapp-`), the "connection" credential |

---

## Step 12 – Verify the setup (smoke tests)

### 12.1 Request a chatbot token

```bash
curl -s -X POST "https://zoom.us/oauth/token?grant_type=client_credentials" \
  -H "Authorization: Basic $(printf '%s:%s' "$ZOOM_CLIENT_ID" "$ZOOM_CLIENT_SECRET" | base64)"
```

Expected: `{"access_token":"…","token_type":"bearer","expires_in":3600,"scope":"imchat:bot", …}`
Tokens expire after 1 hour. Request a new one; there's no refresh flow.

### 12.2 Send a test message to the approvals channel

```bash
curl -s -X POST "https://api.zoom.us/v2/im/chat/messages" \
  -H "Authorization: Bearer $ZOOM_BOT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
        "robot_jid":  "'"$ZOOM_BOT_JID"'",
        "to_jid":     "'"$APPROVALS_CHANNEL_JID"'",
        "account_id": "'"$ZOOM_ACCOUNT_ID"'",
        "content": {
          "head": { "text": "Keeper Security" },
          "body": [ { "type": "message", "text": "Test message from the Keeper Zoom app setup." } ]
        }
      }'
```

Expected: the response includes `message_id`, and the message appears in the channel.

### 12.3 Slash command and webhook

1. With the webhook server running behind the public URL, type `/keeper help` in any chat.
2. The server should receive a `bot_notification` event with `cmd: "help"` and a valid `x-zm-signature` header.

Signature check (what the server does):

```
message   = "v0:" + <x-zm-request-timestamp header> + ":" + <raw request body>
signature = "v0=" + HMAC_SHA256_hex(SECRET_TOKEN, message)
valid if signature == <x-zm-signature header>
```

---

## Step 13 – Deploy with Commander (planned)

This mirrors Steps 3–5 of the Slack app documentation. It depends on a new **`zoom-app-setup`** command in Keeper Commander (not built yet).

1. Log in to Commander as the Keeper service account:
   ```
   keeper shell
   My Vault> login serviceuser@company.com
   ```
2. Run:
   ```
   My Vault> zoom-app-setup
   ```
   - **Phase 1 – Docker Service Mode setup** (same as `slack-app-setup`): shared folder, config record, KSM app, client device, base64 KSM config.
   - **Phase 2 – Zoom app configuration** prompts: Account ID, Client ID, Client Secret, Bot JID, Secret Token, Approvals Channel JID, public endpoint / Cloudflare tunnel token, enable PEDM? (+ interval), enable Device Approval? (+ interval), enable multi-channel approvers? (team → channel JID, optional folder/record UIDs).
   - Values are saved to a **"Commander Service Mode Zoom App Config"** vault record, never to plaintext files.
3. Quit Commander and remove the local config to avoid device-token conflicts:
   ```
   My Vault> quit
   $ rm ~/.keeper/config.json
   ```
4. Copy the generated `docker-compose.yml` to the Linux VM and start it:
   ```bash
   docker compose up -d
   docker compose ps          # keeper-service (healthy), keeper-zoom-app, cloudflared
   docker logs keeper-zoom-app
   ```
   Planned compose layout:
   ```yaml
   services:
     commander:
       container_name: keeper-service
       image: keeper/commander:latest
       # service-create ... (same as Slack setup)
     zoom-app:
       container_name: keeper-zoom-app
       image: keeper/zoom-app:latest
       environment:
         KSM_CONFIG: <KSM_CONFIG_BASE64_VALUE>
         COMMANDER_RECORD: <CONFIG_RECORD_UID>
         ZOOM_RECORD: <ZOOM_CONFIG_RECORD_UID>
       depends_on:
         commander:
           condition: service_healthy
       restart: unless-stopped
     cloudflared:
       container_name: keeper-zoom-tunnel
       image: cloudflare/cloudflared:latest
       command: tunnel --no-autoupdate run --token <CLOUDFLARE_TUNNEL_TOKEN>
       depends_on: [zoom-app]
       restart: unless-stopped
   ```
5. Go back to the Zoom app (Steps 6–7) and confirm the **Bot Endpoint URL** and **Event Subscription** validate against the live URL.
6. Test in Zoom: `/keeper request-record "prod db" Need to run migration` → the card appears in the approvals channel → approve → the requester gets a DM.

---

## Optional – Create the app from a manifest

Zoom supports creating and updating a General App from a JSON manifest (similar to the Slack app manifest). Use it to skip most of Steps 5–8.

1. Marketplace → **Developer → Develop → Build from an app manifest**.
2. Download the **manifest template** from that screen (always use the latest template; old ones fail validation).
3. Fill in the Keeper values (draft of the chat section below), upload → **Create**.
4. Then complete the parts that differ per customer: endpoint URLs, the Secret Token copy, scopes review, and **Add App** (Step 9).

Draft `team_chat_subscription` section (**🔎 Verify** against the latest template):

```json
{
  "features": {
    "products": ["ZOOM_CHAT"],
    "team_chat_subscription": {
      "enable": true,
      "slash_command": {
        "command": "keeper",
        "command_hints": [
          { "description": "Request access to a Keeper record",  "usage_hint": "request-record \"Record UID or description\" justification" },
          { "description": "Request access to a Keeper folder",  "usage_hint": "request-folder \"Folder UID or description\" justification" },
          { "description": "Request a one-time share link",      "usage_hint": "one-time-share \"Record UID or description\" justification" },
          { "description": "Create a secret in a shared folder", "usage_hint": "create-secret" },
          { "description": "Show available commands",            "usage_hint": "help" }
        ],
        "enable_add_to_channel": true,
        "development_message_url": "https://<public-host>/zoom/webhook",
        "production_message_url":  "https://<public-host>/zoom/webhook",
        "sender_type": "zoom",
        "welcome_msg": { "title": "Welcome to Keeper Security", "body": "" },
        "trust_domain_list": [ { "domain": "keepersecurity.com", "unfurling": false } ]
      }
    }
  }
}
```

To update an existing app later (e.g. a new sub-command): app → **Basic Information → Manage manifest** → download → edit → **Upload new manifest** → re-add the app if scopes changed.

---

## Slack → Zoom terminology mapping

| Slack | Zoom |
|---|---|
| api.slack.com/apps | marketplace.zoom.us → Developer |
| Create app from manifest | Build from an app manifest (General App) |
| Install to Workspace | **Add App** (user-managed: Local test → Add app) |
| Bot User OAuth Token (`xoxb-`) | Chatbot token from Client ID + Secret (1-hour) |
| App-level token (`xapp-`) / Socket Mode | Public Bot Endpoint URL (Cloudflare Tunnel) |
| Signing Secret | Secret Token |
| Bot user ID | Bot JID |
| Channel ID `C0…` | Channel JID `<id>@conference.xmpp.zoom.us` |
| User ID `U0…` | User ID / User JID `<id>@xmpp.zoom.us` |
| `/invite @Keeper Security` | Channel → Members → Integrations → **Add apps** |
| Block Kit | Chatbot message cards (Zoom App Card Builder) |
| Ephemeral message | DM from the bot (`visible_to_user` is admin-managed only) |
| Modals | Not available for chatbots. Interactive cards (Phase 1) or App Shortcut web view (Phase 2) |
| App Home tab | Welcome / help card in the bot's DM + `/keeper settings` |

---

## Troubleshooting

| Problem | Likely cause | Fix |
|---|---|---|
| No **Developer** link in Marketplace | Missing role permission | Step 1: role needs **Zoom for developers** View + Edit (or Admin) |
| Event subscription / Bot endpoint won't validate | Server not reachable or wrong Secret Token | Make sure the tunnel and app are up, and the `endpoint.url_validation` response uses the current Secret Token |
| `401 / invalid signature` in app logs | Secret Token regenerated or wrong | Copy the current Secret Token from Features → Access into the KSM config record and restart |
| Token request returns `invalid_client` | Wrong Client ID/Secret | Re-copy from Basic Information. Secrets stay valid for 30 days after regeneration. |
| Can't add the app to a channel | Account setting off, or channel scope missing | Step 2 (*Allow users to add apps to channels*) and Step 8 (*Chatbot within Chat Channel*), then re-add the app |
| Bot can't post to the channel | App not added to the channel, or wrong JID | Step 10. JID must end in `@conference.xmpp.zoom.us`. |
| Slash command does nothing, no log line | Typing an old/deleted app's command, or the app isn't added to that chat | Use `/keeper …`; remove the old app from the channel |
| App shows **DELETED** in Team Chat, card buttons disabled | Welcome message Sender set to *Your app* with no title, or the app it was installed from was deleted | Step 7: set the Welcome message Sender to **Zoom** with a title, then re-add the app. Otherwise re-add the current app (Step 9) and update every value in `zoom_config.yaml` from it. |
| `Event is for bot … but zoom.bot_jid is …` warning | `bot_jid` is from another app or environment | Set `zoom.bot_jid` to the JID in the warning |
| Requester email lookup fails | User-managed token can only read the user who added the app | Add the requester's Zoom user ID (from the log) to `zoom.user_emails` |
| Changes not taking effect | Scopes/events changed without re-authorizing | Re-add the app (Step 9) |

---

## References

- Zoom – Before you start (roles, app types): <https://developers.zoom.us/docs/build-flow/before-you-build/>
- Zoom – Quick start guide (General App): <https://developers.zoom.us/docs/build-flow/quick-start-guide/>
- Zoom – App manifests: <https://developers.zoom.us/docs/build-flow/manifests/>
- Zoom – Team Chat get credentials: <https://developers.zoom.us/docs/chat/get-credentials/>
- Zoom – Authorize / chatbot token: <https://developers.zoom.us/docs/chat/installation-and-authentication/>
- Zoom – Send, edit, delete messages: <https://developers.zoom.us/docs/chat/send-edit-and-delete-messages/>
- Zoom – Add app to channel: <https://developers.zoom.us/docs/chat/tutorial/add-app-to-channel/>
- Zoom – Migrating from Slack: <https://developers.zoom.us/docs/chat/chatbot/extend/>
- Zoom – Private and beta apps: <https://developers.zoom.us/docs/distribute/sharing-private-and-beta-apps/>
- Keeper – Slack App docs: <https://docs.keeper.io/keeperpam/secrets-manager/integrations/slack-app>
- Keeper – Slack App source: <https://github.com/Keeper-Security/slack-app>
