#!/usr/bin/env python3
"""Assembles workflow.json from the Code node sources in src/.

Run from the repo root:  python3 src/build.py
"""
import json
import pathlib
import uuid

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "src"

# Stable node IDs so rebuilds produce small diffs.
def nid(name):
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "n8n-security-scorecard/" + name))


def node(name, type_, version, params, pos, **extra):
    n = {"parameters": params, "id": nid(name), "name": name, "type": type_,
         "typeVersion": version, "position": pos}
    n.update(extra)
    return n


API = "={{ $('Settings').first().json.n8nUrl.replace(/\\/+$/, '') }}/api/v1"
TOLERANT = {"onError": "continueRegularOutput", "alwaysOutputData": True}
N8N_CRED = {"n8nApi": {"name": "n8n API (this instance)"}}


def api_get(name, path, pos, query=None, paginate=False, execute_once=True):
    params = {
        "url": API + path,
        "authentication": "predefinedCredentialType",
        "nodeCredentialType": "n8nApi",
        "options": {},
    }
    if query:
        params["sendQuery"] = True
        params["queryParameters"] = {"parameters": [{"name": k, "value": v} for k, v in query]}
    if paginate:
        params["options"]["pagination"] = {"pagination": {
            "parameters": {"parameters": [
                {"name": "cursor", "value": "={{ $response.body.nextCursor }}"}]},
            "paginationCompleteWhen": "other",
            "completeExpression": "={{ !$response.body.nextCursor }}",
            "limitPagesFetched": True,
            "maxRequests": 40,
        }}
    extra = dict(TOLERANT, credentials=N8N_CRED)
    if execute_once:
        extra["executeOnce"] = True
    return node(name, "n8n-nodes-base.httpRequest", 4.2, params, pos, **extra)


settings = node("Settings", "n8n-nodes-base.set", 3.4, {
    "assignments": {"assignments": [
        {"id": nid("a-url"), "name": "n8nUrl", "type": "string", "value": "http://localhost:5678"},
        {"id": nid("a-inst"), "name": "instanceName", "type": "string", "value": "My n8n"},
        {"id": nid("a-to"), "name": "emailTo", "type": "string", "value": "you@example.com"},
        {"id": nid("a-from"), "name": "emailFrom", "type": "string", "value": "n8n@example.com"},
        {"id": nid("a-adm"), "name": "maxOwnersAndAdmins", "type": "number", "value": 3},
        {"id": nid("a-days"), "name": "maxDaysBehindLatest", "type": "number", "value": 28},
    ]},
    "options": {},
}, [220, 300])

TABLE = "n8n_security_answers"
FORM_PATH = "n8n-security-answers"
TABLE_RL = {"__rl": True, "mode": "name", "value": TABLE}
COLUMNS = ["answered_by", "answered_at", "editor_restricted", "key_off_server", "creds_scoped",
           "unverified_off", "backup_restored", "logs_reviewed", "logs_reviewer"]


def yes_no(name, label):
    return {"fieldLabel": label, "fieldName": name, "fieldType": "radio",
            "fieldOptions": {"values": [{"option": "Yes"}, {"option": "No"}]}, "requiredField": True}


form_fields = [
    {"fieldLabel": "Your name", "fieldName": "answered_by", "requiredField": True},
    yes_no("editor_restricted", "Is the n8n editor behind a VPN or an IP allow-list?"),
    yes_no("key_off_server", "Did you set N8N_ENCRYPTION_KEY yourself, and is a copy kept off this server (password manager or secrets store)?"),
    yes_no("creds_scoped", "Is each credential limited to what its workflow needs (for example a read-only database user)?"),
    yes_no("unverified_off", "Is N8N_UNVERIFIED_PACKAGES_ENABLED=false set (or are community packages turned off)?"),
    yes_no("backup_restored", "Is the database backed up on a schedule, kept off this server, and has a backup been restored on another machine at least once?"),
    yes_no("logs_reviewed", "Does someone review the n8n logs on a schedule?"),
    {"fieldLabel": "Who reviews the logs? (optional)", "fieldName": "logs_reviewer"},
]

nodes = [
    node("Every Monday 08:00", "n8n-nodes-base.scheduleTrigger", 1.2, {
        "rule": {"interval": [{"field": "weeks", "triggerAtDay": [1], "triggerAtHour": 8}]}}, [0, 220]),
    node("Run now", "n8n-nodes-base.manualTrigger", 1, {}, [0, 400]),
    settings,
    node("Run security audit", "n8n-nodes-base.httpRequest", 4.2, {
        "method": "POST",
        "url": API + "/audit",
        "authentication": "predefinedCredentialType",
        "nodeCredentialType": "n8nApi",
        "sendBody": True,
        "specifyBody": "json",
        "jsonBody": "{\n  \"additionalOptions\": { \"daysAbandonedWorkflow\": 90 }\n}",
        "options": {},
    }, [480, 300], executeOnce=True, credentials=N8N_CRED, **TOLERANT),
    api_get("Get users", "/users", [680, 300], query=[("includeRole", "true"), ("limit", "250")], paginate=True),
    api_get("Get active workflows", "/workflows", [880, 300], query=[("active", "true"), ("limit", "250")], paginate=True),
    api_get("Get community packages", "/community-packages", [1080, 300]),
    api_get("Get log streaming destinations", "/settings/log-streaming/destinations", [1280, 300]),
    node("Get editor page", "n8n-nodes-base.httpRequest", 4.2, {
        "url": "={{ $('Settings').first().json.n8nUrl.replace(/\\/+$/, '') }}/",
        "options": {"response": {"response": {"responseFormat": "text", "outputPropertyName": "data"}}},
    }, [480, 720], executeOnce=True, **TOLERANT),
    node("Read version", "n8n-nodes-base.code", 2, {
        "jsCode": (SRC / "read-version.js").read_text()}, [680, 720]),
    node("Check n8n releases", "n8n-nodes-base.httpRequest", 4.2, {
        "url": "=https://api.n8n.io/api/versions/{{ $json.version }}",
        "options": {"timeout": 15000},
    }, [880, 720], executeOnce=True, **TOLERANT),
    node("Get public settings", "n8n-nodes-base.httpRequest", 4.2, {
        "url": "={{ $('Settings').first().json.n8nUrl.replace(/\\/+$/, '') }}/rest/settings",
        "options": {},
    }, [1080, 720], executeOnce=True, **TOLERANT),
    node("Get saved answers", "n8n-nodes-base.dataTable", 1.1, {
        "resource": "row",
        "operation": "get",
        "dataTableId": TABLE_RL,
        "returnAll": True,
    }, [1340, 720], executeOnce=True, **TOLERANT),
    node("Build scorecard", "n8n-nodes-base.code", 2, {
        "jsCode": (SRC / "scorecard.js").read_text()}, [1600, 720], executeOnce=True),
    node("Send scorecard email", "n8n-nodes-base.emailSend", 2.1, {
        "fromEmail": "={{ $('Settings').first().json.emailFrom }}",
        "toEmail": "={{ $('Settings').first().json.emailTo }}",
        "subject": "={{ $json.subject }}",
        "html": "={{ $json.html }}",
        "options": {"appendAttribution": False},
    }, [1820, 640], credentials={"smtp": {"name": "SMTP account"}}),
    node("Post to Slack (optional)", "n8n-nodes-base.slack", 2.3, {
        "select": "channel",
        "channelId": {"__rl": True, "mode": "name", "value": "#n8n-security"},
        "text": "={{ $json.text }}",
        "otherOptions": {},
    }, [1820, 800], disabled=True),

    # One-time questions: a form only logged-in n8n users can open.
    node("One-time questions", "n8n-nodes-base.formTrigger", 2.6, {
        "authentication": "n8nUserAuth",
        "requireExecuteAccess": True,
        "formTitle": "n8n security: one-time questions",
        "formDescription": "The weekly scorecard checks most things itself. These 6 it can't see. Answer once; it asks again after 90 days.",
        "formFields": {"values": form_fields},
        "options": {
            "path": FORM_PATH,
            "appendAttribution": False,
            "respondWithOptions": {"values": {"respondWith": "text",
                                              "formSubmittedText": "Saved. The next scorecard will use these answers."}},
        },
    }, [0, 1160], webhookId=nid("form-webhook")),
    node("Create answers table", "n8n-nodes-base.dataTable", 1.1, {
        "resource": "table",
        "operation": "create",
        "tableName": TABLE,
        "columns": {"column": [{"name": c, "type": "string"} for c in COLUMNS]},
        "options": {"createIfNotExists": True},
    }, [260, 1160]),
    node("Prepare answers", "n8n-nodes-base.code", 2, {
        "jsCode": (SRC / "prepare-answers.js").read_text()}, [480, 1160]),
    node("Save answers", "n8n-nodes-base.dataTable", 1.1, {
        "resource": "row",
        "operation": "insert",
        "dataTableId": TABLE_RL,
        "columns": {"mappingMode": "autoMapInputData", "value": {}, "matchingColumns": [], "schema": []},
        "options": {},
    }, [700, 1160]),

    node("Read me", "n8n-nodes-base.stickyNote", 1, {
        "content": (
            "## n8n Security Checklist Scorecard\n"
            "Runs the 7 checks from the *n8n Security Checklist* (Symplytics, Diego Rodriguez) against this instance "
            "and emails a scorecard every week.\n\n"
            "**Setup**\n"
            "1. Settings > n8n API: create an API key. Open any *Get …* node and create an **n8n API** credential "
            "(key + Base URL `<your n8n URL>/api/v1`). All API nodes share it.\n"
            "2. **Settings** node: your n8n URL, instance name, email to/from. Add an SMTP credential to "
            "**Send scorecard email** (or enable Slack).\n"
            "3. Publish the workflow, then open `<your n8n URL>/form/n8n-security-answers` and answer the "
            "6 one-time questions.\n"
            "4. Click *Execute workflow* to get the first scorecard."),
        "height": 460, "width": 380, "color": 4,
    }, [-440, 140]),
    node("Group: collect", "n8n-nodes-base.stickyNote", 1, {
        "content": "### 1. Collect\nSecurity audit, users, published workflows, community packages and log streaming, all from this instance's public API.",
        "height": 300, "width": 1020, "color": 7}, [420, 140]),
    node("Group: version", "n8n-nodes-base.stickyNote", 1, {
        "content": "### 2. Version and settings\nRunning version vs. n8n's release list; public login settings.",
        "height": 300, "width": 760, "color": 7}, [462, 560]),
    node("Group: score", "n8n-nodes-base.stickyNote", 1, {
        "content": "### 3. Score and send\nAdd your saved answers, map everything onto the 7 checks, send the scorecard.",
        "height": 420, "width": 740, "color": 7}, [1260, 500]),
    node("Group: form", "n8n-nodes-base.stickyNote", 1, {
        "content": "### One-time questions\nA form only logged-in n8n users can open. Saves answers to the `n8n_security_answers` data table. The scorecard re-asks after 90 days.",
        "height": 320, "width": 940, "color": 7}, [-60, 980]),
]

chain = ["Settings", "Run security audit", "Get users", "Get active workflows", "Get community packages",
         "Get log streaming destinations", "Get editor page", "Read version", "Check n8n releases",
         "Get public settings", "Get saved answers", "Build scorecard"]
connections = {
    "Every Monday 08:00": {"main": [[{"node": "Settings", "type": "main", "index": 0}]]},
    "Run now": {"main": [[{"node": "Settings", "type": "main", "index": 0}]]},
}
for a, b in zip(chain, chain[1:]):
    connections[a] = {"main": [[{"node": b, "type": "main", "index": 0}]]}
connections["Build scorecard"] = {"main": [[
    {"node": "Send scorecard email", "type": "main", "index": 0},
    {"node": "Post to Slack (optional)", "type": "main", "index": 0},
]]}
for a, b in [("One-time questions", "Create answers table"), ("Create answers table", "Prepare answers"),
             ("Prepare answers", "Save answers")]:
    connections[a] = {"main": [[{"node": b, "type": "main", "index": 0}]]}

workflow = {
    "name": "n8n Security Checklist Scorecard",
    "nodes": nodes,
    "connections": connections,
    "settings": {"executionOrder": "v1"},
    "pinData": {},
    "meta": {"templateCredsSetupCompleted": False},
}

(ROOT / "workflow.json").write_text(json.dumps(workflow, indent=2, ensure_ascii=False) + "\n")
print("wrote workflow.json with", len(nodes), "nodes")
