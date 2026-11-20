# n8n Security Checklist Scorecard

An n8n workflow that checks your self-hosted n8n against the 7 checks in
Diego Rodriguez's [n8n Security Checklist for IT Teams](https://symplytics.com/blog/n8n-security-checklist)
and emails you a scorecard every week.

It reads your instance through n8n's own public API, so there is nothing to
install. Each check comes back as **PASS**, **FAIL** or **CHECK**. CHECK means
the API can't see that part (backups, where the encryption key is kept), so the
row turns it into a short question for a person to answer.

![Sample scorecard](screenshots/scorecard.png)

*Sample from a test instance seeded with an open webhook, an open form, an open
MCP Server Trigger, a second admin without 2FA, a shared-looking login and an
unused community node.*

![The workflow in n8n](screenshots/workflow.png)

## What it checks

| # | Check | Pass when | What the workflow does |
|---|---|---|---|
| 1 | Version | Within a few weeks of the current release; security releases applied | Reads the running version and compares it with n8n's release list. FAIL if a newer release has a security fix, or if you've been behind for more than 28 days. |
| 2 | Exposure | Only the endpoints that need to be public are public, and each authenticates | Lists every Webhook, Form, MCP Server Trigger and public Chat trigger in active workflows. FAIL for each one with Authentication set to None. Asks whether the editor sits behind a VPN or IP allow-list. |
| 3 | Credentials | Encryption key set by you and stored off the server; tokens scoped | Lists credentials no workflow uses, or that haven't run in 90 days (from n8n's built-in security audit). Asks where `N8N_ENCRYPTION_KEY` is stored and whether tokens are scoped. |
| 4 | Access | Few owners/admins, named accounts, no shared logins, 2FA | Counts owners and admins, lists who has no 2FA, flags logins that look shared (`admin@`, `ops@`, `team@` …) and old pending invites. FAIL if there are more than 3 owners/admins, an admin without 2FA, or a shared admin login. |
| 5 | Code | Task runners in external mode; `N8N_BLOCK_ENV_ACCESS_IN_NODE=true` | A Code node in the run tries to read an environment variable. FAIL if it can. Asks whether task runners run in external mode, which the API can't see. |
| 6 | Community nodes | Each one reviewed, with a reason to keep it | Lists installed community packages with version and author. FAIL for any package no active workflow uses. Asks about `N8N_UNVERIFIED_PACKAGES_ENABLED=false`. |
| 7 | Recovery and logs | A backup restored at least once; logs kept somewhere watched | Shows log streaming destinations when your plan has them. Asks about backups, test restores and who reads the logs. |

The two limits (3 owners/admins, 28 days behind) are in the **Settings** node.
Change them there.

## Setup (about 5 minutes)

1. **Import the workflow.** In n8n, create a new workflow, open the **…** menu,
   choose **Import from URL** and paste:

   ```
   https://raw.githubusercontent.com/Pankaj3112/n8n-security-scorecard/main/workflow.json
   ```

   Or copy the contents of [`workflow.json`](workflow.json) and paste them onto
   the canvas.

2. **Connect it.**
   - Create an API key in **Settings > n8n API**. It needs to be an owner or
     admin's key. On plans with key scopes, give it `securityAudit:generate`,
     `user:list`, `workflow:list`, `communityPackage:list` and (optional)
     `eventBusDestination:list`.
   - Open any **Get …** node and create an **n8n API** credential with that key
     and your base URL (`https://your-n8n.example.com/api/v1`). All the API
     nodes use the same credential.
   - In the **Settings** node, set `n8nUrl` (how this instance reaches itself;
     `http://localhost:5678` works for a standard Docker install), a name for
     the instance, and the email to/from addresses.
   - Add an SMTP credential to **Send scorecard email**. If you'd rather use
     Slack, enable **Post to Slack (optional)** and pick a channel.

3. **Run it.** Click **Execute workflow** and check your inbox. Publish the
   workflow to get the scorecard every Monday at 08:00 (change the time in the
   schedule node).

## What it sends where

- Everything runs inside your n8n. The workflow reads your own API and your
  editor page (to get the version number).
- The only outside call is `GET https://api.n8n.io/api/versions/<your version>`,
  the same release list n8n's own security audit and update notices use.
- The scorecard contains workflow names, webhook paths and user emails. Send it
  to a channel that's fine to hold those.

## Limits

- The API can't see how n8n is deployed. Anything about environment variables
  (except the env-access test), the reverse proxy, backups or where the
  encryption key lives is asked as a question rather than scored.
- A webhook with Authentication set to None that checks a signature in the next
  node is listed separately as "payload checked in the next node", not as a
  FAIL. Make sure that check is real.
- The shared-login check only looks at the email address, so it can miss
  shared accounts and flag ones that aren't shared.
- Tested on n8n 2.48.7 (self-hosted, Docker, community edition).

## Credit

The checklist is Diego Rodriguez's
[n8n Security Checklist for IT Teams](https://symplytics.com/blog/n8n-security-checklist).
Read it for the reasons behind each check. This workflow is an independent
build that automates those checks. It is not made by, for, or with Symplytics.

## Development

`workflow.json` is generated. Edit the Code node sources in `src/` and run
`python3 src/build.py`.

## License

[MIT](LICENSE)
