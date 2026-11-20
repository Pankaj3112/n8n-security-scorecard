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
        "jsCode": (SRC / "read-version.js").read_text()}, [660, 720]),
    node("Check n8n releases", "n8n-nodes-base.httpRequest", 4.2, {
        "url": "=https://api.n8n.io/api/versions/{{ $json.version }}",
        "options": {"timeout": 15000},
    }, [840, 720], executeOnce=True, **TOLERANT),
    node("Build scorecard", "n8n-nodes-base.code", 2, {
        "jsCode": (SRC / "scorecard.js").read_text()}, [1080, 720], executeOnce=True),
    node("Send scorecard email", "n8n-nodes-base.emailSend", 2.1, {
        "fromEmail": "={{ $('Settings').first().json.emailFrom }}",
        "toEmail": "={{ $('Settings').first().json.emailTo }}",
        "subject": "={{ $json.subject }}",
        "html": "={{ $json.html }}",
        "options": {"appendAttribution": False},
    }, [1300, 640], credentials={"smtp": {"name": "SMTP account"}}),
    node("Post to Slack (optional)", "n8n-nodes-base.slack", 2.3, {
        "select": "channel",
        "channelId": {"__rl": True, "mode": "name", "value": "#n8n-security"},
        "text": "={{ $json.text }}",
        "otherOptions": {},
    }, [1300, 800], disabled=True),
    node("Read me", "n8n-nodes-base.stickyNote", 1, {
        "content": (
            "## n8n Security Checklist Scorecard\n"
            "Runs the 7 checks from Diego Rodriguez's *n8n Security Checklist for IT Teams* against this instance "
            "and emails a scorecard.\n\n"
            "**Setup**\n"
            "1. Settings > n8n API: create an API key.\n"
            "2. Open any HTTP node named *Get …* and create an **n8n API** credential "
            "(API key + Base URL `<your n8n URL>/api/v1`). All API nodes share it.\n"
            "3. Edit **Settings**: your n8n URL, instance name, email to/from.\n"
            "4. Set an SMTP credential on **Send scorecard email** (or enable the Slack node).\n"
            "5. Click *Execute workflow*, then publish to get the weekly run."),
        "height": 440, "width": 380, "color": 4,
    }, [-440, 140]),
    node("Group: collect", "n8n-nodes-base.stickyNote", 1, {
        "content": "### 1. Collect\nSecurity audit, users, published workflows, community packages and log streaming, all from this instance's public API.",
        "height": 300, "width": 1020, "color": 7}, [420, 140]),
    node("Group: version", "n8n-nodes-base.stickyNote", 1, {
        "content": "### 2. Version\nRead the running version and compare it with n8n's release list.",
        "height": 300, "width": 520, "color": 7}, [462, 560]),
    node("Group: score", "n8n-nodes-base.stickyNote", 1, {
        "content": "### 3. Score and send\nMap everything onto the 7 checks and send the scorecard.",
        "height": 420, "width": 420, "color": 7}, [1020, 500]),
]

chain = ["Settings", "Run security audit", "Get users", "Get active workflows", "Get community packages",
         "Get log streaming destinations", "Get editor page", "Read version", "Check n8n releases", "Build scorecard"]
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
