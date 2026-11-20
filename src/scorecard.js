// Builds the scorecard: maps the n8n API data onto the 7 checks of the
// "n8n Security Checklist for IT Teams" and renders an HTML email + plain text.

const cfg = $('Settings').first().json;
const maxAdmins = Number(cfg.maxOwnersAndAdmins) || 3;
const maxBehindDays = Number(cfg.maxDaysBehindLatest) || 28;

// ---------- helpers ----------
const items = (name) => {
  try { return $(name).all().map((i) => i.json); } catch (e) { return []; }
};
const errorOf = (list) => {
  const bad = list.find((j) => j && j.error);
  if (!bad) return null;
  const e = bad.error;
  return typeof e === 'string' ? e : (e.message || e.description || JSON.stringify(e)).slice(0, 200);
};
const esc = (s) => String(s ?? '')
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const plural = (n, one, many) => `${n} ${n === 1 ? one : (many || one + 's')}`;
const daysBetween = (a, b) => Math.round((new Date(b) - new Date(a)) / 86400000);

// ---------- data ----------
const auditItems = items('Run security audit');
const auditError = errorOf(auditItems);
const reports = auditError ? [] : auditItems.flatMap((j) => Object.values(j)).filter((r) => r && Array.isArray(r.sections));
const section = (risk, title) => {
  for (const r of reports) if (r.risk === risk) for (const s of r.sections) if (s.title === title) return s;
  return null;
};

const userPages = items('Get users');
const usersError = errorOf(userPages);
const users = usersError ? [] : userPages.flatMap((p) => p.data || []);

const wfPages = items('Get active workflows');
const workflowsError = errorOf(wfPages);
const workflows = workflowsError ? [] : wfPages.flatMap((p) => p.data || []).filter((w) => w.active && !w.isArchived);

const pkgItems = items('Get community packages');
const pkgError = errorOf(pkgItems);
const packages = pkgError ? [] : pkgItems.filter((p) => p && p.packageName);

const logItems = items('Get log streaming destinations');
const logError = errorOf(logItems);
const logDestinations = logError ? [] : logItems.flatMap((p) => p.data || []);

const version = (items('Read version')[0] || {}).version || null;
const releaseItems = items('Check n8n releases');
const releasesError = errorOf(releaseItems);
const releases = releasesError ? [] : releaseItems.filter((r) => r && r.name);

const checks = [];
const add = (c) => checks.push({ n: checks.length + 1, ...c });

// ---------- 1. Version ----------
{
  const outdated = section('instance', 'Outdated instance');
  const found = [];
  const todo = [];
  let status;
  if (version && releases.length) {
    const current = releases.find((r) => r.name === version);
    const newer = releases.filter((r) => r.name !== version)
      .sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));
    const security = newer.filter((r) => r.hasSecurityFix || r.hasSecurityIssue);
    const insecureNow = current && current.hasSecurityIssue;
    const latest = newer[newer.length - 1];
    const behindDays = newer.length ? daysBetween(newer[0].createdAt, new Date().toISOString()) : 0;
    found.push(`Running n8n ${version}.`);
    if (!newer.length) {
      found.push('This is the latest release.');
    } else {
      found.push(`${plural(newer.length, 'newer release')} available (latest ${latest.name}). The first one came out ${plural(behindDays, 'day')} ago.`);
    }
    if (security.length) found.push(`Security fixes in: ${security.map((r) => r.name).join(', ')}.`);
    if (insecureNow) found.push('n8n flags the running version as having a known security issue.');
    status = (security.length || insecureNow || behindDays > maxBehindDays) ? 'FAIL' : 'PASS';
    if (status === 'FAIL') todo.push(`Upgrade to ${latest ? latest.name : 'the latest release'}. Back up the database and keep the encryption key at hand first.`);
    todo.push('Have someone read the release notes weekly so security releases land within days.');
  } else if (outdated) {
    status = 'FAIL';
    found.push(outdated.description);
    todo.push('Upgrade to the latest release. Back up the database and keep the encryption key at hand first.');
  } else {
    status = 'MANUAL';
    found.push(version ? `Running n8n ${version}. Could not reach api.n8n.io to compare releases.` : 'Could not read the running version.');
    todo.push('Is this instance within a few weeks of the latest n8n release, with every security release applied?');
  }
  add({ name: 'Version', goal: 'Within a few weeks of the current release; every security release applied.', status, found, todo });
}

// ---------- 2. Exposure ----------
{
  const PUBLIC_TRIGGERS = {
    'n8n-nodes-base.webhook': 'Webhook',
    'n8n-nodes-base.formTrigger': 'Form',
    '@n8n/n8n-nodes-langchain.mcpTrigger': 'MCP Server',
    '@n8n/n8n-nodes-langchain.chatTrigger': 'Chat',
  };
  // Webhooks the audit considers protected because the next node validates the payload.
  const auditOpen = new Set(((section('instance', 'Unprotected webhooks in instance') || {}).location || [])
    .map((l) => `${l.workflowId}/${l.nodeId}`));
  const open = [];
  const validated = [];
  const secured = [];
  for (const w of workflows) {
    const nodes = (w.activeVersion && w.activeVersion.nodes) || w.nodes || [];
    for (const node of nodes) {
      const kind = PUBLIC_TRIGGERS[node.type];
      if (!kind || node.disabled) continue;
      const p = node.parameters || {};
      if (kind === 'Chat' && p.public !== true) continue; // hosted chat is only public when "Make Chat Publicly Available" is on
      const auth = p.authentication || 'none';
      const label = `${w.name} → ${node.name} (${kind}${p.path ? `, /${p.path}` : ''})`;
      if (auth !== 'none') secured.push(label);
      else if (kind === 'Webhook' && !auditOpen.has(`${w.id}/${node.id}`)) validated.push(label);
      else open.push(label);
    }
  }
  const found = [];
  const todo = [];
  let status;
  if (workflowsError) {
    status = 'MANUAL';
    found.push(`Could not list workflows: ${workflowsError}`);
    todo.push('List every active webhook, form, chat and MCP Server Trigger by hand and confirm each one authenticates.');
  } else {
    const total = open.length + validated.length + secured.length;
    found.push(`${plural(total, 'public trigger')} in ${plural(workflows.length, 'active workflow')}; ${secured.length} with authentication.`);
    for (const o of open) found.push(`No authentication: ${o}`);
    for (const v of validated) found.push(`No authentication, payload checked in the next node: ${v}`);
    status = open.length ? 'FAIL' : 'PASS';
    if (open.length) todo.push('Set Authentication on each of these (header auth with a shared secret is the cheap option), or deactivate the ones that should not be public. MCP Server Triggers need auth and a narrow set of tools.');
    if (validated.length) todo.push('Confirm the next-node check really verifies a signature or secret.');
    todo.push('Is the editor behind a VPN or an IP allow-list at the reverse proxy?');
  }
  add({ name: 'Exposure', goal: 'Only the webhooks, forms and MCP endpoints that need to be public are public, and each authenticates.', status, found, todo });
}

// ---------- 3. Credentials ----------
{
  const found = [];
  const notUsed = section('credentials', 'Credentials not used in any workflow');
  const notActive = section('credentials', 'Credentials not used in any active workflow');
  const notRecent = section('credentials', 'Credentials not used in recently executed workflows');
  const names = (s) => ((s && s.location) || []).map((l) => l.name);
  if (auditError) found.push(`Security audit failed: ${auditError}`);
  else {
    const unused = names(notUsed);
    const inactive = names(notActive).filter((n) => !unused.includes(n));
    const stale = names(notRecent).filter((n) => !unused.includes(n) && !inactive.includes(n));
    if (unused.length) found.push(`Not used in any workflow: ${unused.join(', ')}.`);
    if (inactive.length) found.push(`Only used in inactive workflows: ${inactive.join(', ')}.`);
    if (stale.length) found.push(`Not used in a run in the last 90 days: ${stale.join(', ')}.`);
    if (!unused.length && !inactive.length && !stale.length) found.push('Every credential is in active, recent use.');
  }
  const todo = [
    'Was N8N_ENCRYPTION_KEY set by you (not auto-generated), and is a copy stored off the server, in a password manager or secrets store?',
    'Is each credential scoped to what its workflow needs (for example a read-only database user)?',
  ];
  if (found.some((f) => f.startsWith('Not used') || f.startsWith('Only used'))) todo.unshift('Delete the credentials you no longer need.');
  add({ name: 'Credentials', goal: 'Encryption key set by you and stored off the server; tokens scoped to what each workflow needs.', status: 'MANUAL', found, todo });
}

// ---------- 4. Access ----------
{
  const found = [];
  const todo = [];
  let status;
  if (usersError) {
    status = 'MANUAL';
    found.push(`Could not list users: ${usersError}`);
    todo.push('Count owners and admins by hand and confirm each is a named person with 2FA.');
  } else {
    const active = users.filter((u) => !u.isPending && !u.disabled);
    const admins = active.filter((u) => u.role === 'global:owner' || u.role === 'global:admin');
    const adminsNo2fa = admins.filter((u) => !u.mfaEnabled);
    const othersNo2fa = active.filter((u) => !admins.includes(u) && !u.mfaEnabled);
    const SHARED = /^(admin|administrator|ops|devops|it|team|shared|info|automation|automations|n8n|service|svc|bot|integrations?|support|dev|test|office|hello)([._+-].*)?$/i;
    const shared = active.filter((u) => u.email && SHARED.test(u.email.split('@')[0]));
    const pending = users.filter((u) => u.isPending);
    const who = (u) => u.email || `${u.firstName || ''} ${u.lastName || ''}`.trim();
    found.push(`${plural(active.length, 'user')}; ${plural(admins.length, 'owner/admin', 'owners/admins')}: ${admins.map(who).join(', ')}.`);
    if (adminsNo2fa.length) found.push(`Owners/admins without 2FA: ${adminsNo2fa.map(who).join(', ')}.`);
    if (othersNo2fa.length) found.push(`Other users without 2FA: ${othersNo2fa.length}.`);
    if (shared.length) found.push(`Looks like a shared login: ${shared.map(who).join(', ')}.`);
    if (pending.length) found.push(`Pending invites: ${pending.map(who).join(', ')}.`);
    const fail = admins.length > maxAdmins || adminsNo2fa.length || shared.some((u) => admins.includes(u));
    status = fail ? 'FAIL' : (shared.length ? 'MANUAL' : 'PASS');
    if (admins.length > maxAdmins) todo.push(`Cut owners/admins to ${maxAdmins} or fewer.`);
    if (adminsNo2fa.length) todo.push('Turn on 2FA for every owner and admin (Settings > Personal > Enable 2FA).');
    if (shared.length) todo.push('Replace shared logins with one named account per person.');
    if (pending.length) todo.push('Cancel invites nobody is going to accept.');
    if (!todo.length) todo.push('Nothing to do. Re-check when people join or leave.');
  }
  add({ name: 'Access', goal: 'Few owners and admins, each a named account with 2FA; no shared logins.', status, found, todo });
}

// ---------- 5. Code ----------
{
  // Probe: can a Code node read the server's environment? Blocked by default since n8n 2.0.
  let envReadable;
  try {
    const v = $env.PATH ?? $env.HOME;
    envReadable = v !== undefined && v !== null && !/denied/i.test(String(v));
  } catch (e) {
    envReadable = false;
  }
  const risky = (section('nodes', 'Official risky nodes') || {}).location || [];
  const codeTypes = new Set(['n8n-nodes-base.code', 'n8n-nodes-base.function', 'n8n-nodes-base.functionItem', 'n8n-nodes-base.executeCommand', 'n8n-nodes-base.ssh']);
  const codeWfs = [...new Set(risky.filter((l) => codeTypes.has(l.nodeType) && l.workflowId !== $workflow.id).map((l) => l.workflowName))];
  const found = [
    envReadable
      ? 'A Code node in this run could read server environment variables.'
      : 'A Code node in this run could not read server environment variables (blocked).',
  ];
  if (!auditError) found.push(`${plural(codeWfs.length, 'workflow')} ${codeWfs.length === 1 ? 'uses' : 'use'} Code, Execute Command or SSH nodes${codeWfs.length ? `: ${codeWfs.slice(0, 8).join(', ')}${codeWfs.length > 8 ? ', …' : ''}` : ''}.`);
  const todo = [];
  if (envReadable) todo.push('Set N8N_BLOCK_ENV_ACCESS_IN_NODE=true (the default since 2.0) so workflow code cannot read server secrets.');
  todo.push('Do task runners run in external mode (N8N_RUNNERS_MODE=external, a separate runner container, matching N8N_RUNNERS_AUTH_TOKEN)? n8n logs a deprecation warning at startup while it runs in internal mode.');
  add({ name: 'Code', goal: 'Task runners in external mode; N8N_BLOCK_ENV_ACCESS_IN_NODE left at true.', status: envReadable ? 'FAIL' : 'MANUAL', found, todo });
}

// ---------- 6. Community nodes ----------
{
  const found = [];
  const todo = [];
  let status;
  const settings = (section('instance', 'Security settings') || {}).settings || {};
  const enabled = settings.features ? settings.features.communityPackagesEnabled : undefined;
  const auditCommunity = ((section('nodes', 'Community nodes') || {}).location || []).map((l) => l.nodeType);
  if (pkgError && !auditCommunity.length) {
    if (enabled === false) {
      status = 'PASS';
      found.push('Community packages are turned off on this instance.');
    } else {
      status = 'MANUAL';
      found.push(`Could not list community packages: ${pkgError}`);
      todo.push('Check Settings > Community nodes by hand.');
    }
  } else if (!packages.length && !auditCommunity.length) {
    status = 'PASS';
    found.push('No community packages installed.');
  } else {
    // Which installed packages are used by any workflow?
    const usedTypes = new Set();
    for (const w of wfPages.flatMap((p) => p.data || [])) {
      for (const n of ((w.activeVersion && w.activeVersion.nodes) || w.nodes || [])) usedTypes.add(n.type);
    }
    const pkgs = packages.length ? packages : [...new Set(auditCommunity.map((t) => t.split('.')[0]))].map((name) => ({ packageName: name }));
    const unused = [];
    for (const p of pkgs) {
      const types = (p.installedNodes || []).map((n) => n.type);
      const inUse = types.length ? types.some((t) => usedTypes.has(t)) : auditCommunity.some((t) => t.startsWith(p.packageName + '.'));
      const update = p.updateAvailable ? `, update to ${p.updateAvailable} available` : '';
      found.push(`${p.packageName}${p.installedVersion ? ` ${p.installedVersion}` : ''}${p.authorName ? ` by ${p.authorName}` : ''}${inUse ? '' : ', not used in any active workflow'}${update}.`);
      if (!inUse) unused.push(p.packageName);
    }
    status = unused.length ? 'FAIL' : 'MANUAL';
    if (unused.length) todo.push(`Uninstall what nothing uses: ${unused.join(', ')}.`);
    todo.push('For each package: who maintains it, when was it last updated, and does a built-in node now do the same job? Remove any you cannot justify.');
  }
  if (enabled !== false) todo.push('Is N8N_UNVERIFIED_PACKAGES_ENABLED=false set, so only verified packages can be installed?');
  add({ name: 'Community nodes', goal: 'Each one reviewed, with a reason to keep it.', status, found, todo });
}

// ---------- 7. Recovery and logs ----------
{
  const found = [];
  if (logError) {
    found.push(/40[34]|licen|forbidden/i.test(logError)
      ? 'Log streaming is not available on this plan (it is a paid feature), so the API cannot see where logs go.'
      : `Could not read log streaming settings: ${logError}`);
  } else {
    const on = logDestinations.filter((d) => d.enabled !== false);
    found.push(on.length
      ? `Log streaming to: ${on.map((d) => d.label || d.__type || 'destination').join(', ')}.`
      : 'No log streaming destination is set up.');
  }
  found.push('Backups and restores are outside what the n8n API can see.');
  const todo = [
    'Is the database backed up on a schedule and copied off the server?',
    'Has a backup been restored on another machine at least once, with the encryption key at hand?',
    'Who reviews the n8n logs, and how often?',
  ];
  add({ name: 'Recovery and logs', goal: 'A backup restored at least once; logs kept somewhere someone looks.', status: 'MANUAL', found, todo });
}

// ---------- render ----------
const count = (s) => checks.filter((c) => c.status === s).length;
const totals = { PASS: count('PASS'), FAIL: count('FAIL'), MANUAL: count('MANUAL') };
const instance = cfg.instanceName || cfg.n8nUrl;
const today = new Date().toISOString().slice(0, 10);
const subject = `n8n security scorecard for ${instance}: ${totals.FAIL} fail, ${totals.PASS} pass, ${totals.MANUAL} to check by hand`;

const STATUS = {
  PASS: { bg: '#e7f6ec', fg: '#1a7f37', label: 'PASS' },
  FAIL: { bg: '#fdecea', fg: '#c62828', label: 'FAIL' },
  MANUAL: { bg: '#fff4e0', fg: '#9a6700', label: 'CHECK' },
};
const pill = (s) => `<span style="display:inline-block;padding:3px 10px;border-radius:999px;background:${STATUS[s].bg};color:${STATUS[s].fg};font-weight:700;font-size:12px;letter-spacing:.04em">${STATUS[s].label}</span>`;
const list = (arr) => arr.length === 1
  ? `<div>${esc(arr[0])}</div>`
  : `<ul style="margin:0;padding-left:18px">${arr.map((x) => `<li style="margin:0 0 4px">${esc(x)}</li>`).join('')}</ul>`;
const td = 'padding:14px 12px;border-top:1px solid #e5e7eb;vertical-align:top;font-size:14px;line-height:1.45;color:#1f2328';
const rows = checks.map((c) => `
  <tr>
    <td style="${td};color:#6b7280;width:24px">${c.n}</td>
    <td style="${td};width:150px"><div style="font-weight:600">${esc(c.name)}</div><div style="color:#6b7280;font-size:12px;margin-top:4px">${esc(c.goal)}</div></td>
    <td style="${td};width:70px">${pill(c.status)}</td>
    <td style="${td}">${list(c.found)}</td>
    <td style="${td}">${list(c.todo)}</td>
  </tr>`).join('');
const tile = (s, label) => `<td style="padding:10px 16px;background:${STATUS[s].bg};border-radius:8px;text-align:center"><div style="font-size:22px;font-weight:700;color:${STATUS[s].fg}">${totals[s]}</div><div style="font-size:12px;color:${STATUS[s].fg}">${label}</div></td>`;

const html = `<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>${esc(subject)}</title></head>
<body style="margin:0;padding:24px;background:#f6f8fa;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif">
<table role="presentation" cellpadding="0" cellspacing="0" style="max-width:960px;width:100%;margin:0 auto;background:#ffffff;border:1px solid #e5e7eb;border-radius:12px">
  <tr><td style="padding:24px 24px 8px">
    <div style="font-size:12px;color:#6b7280;text-transform:uppercase;letter-spacing:.08em">n8n security checklist scorecard</div>
    <div style="font-size:22px;font-weight:700;color:#1f2328;margin-top:4px">${esc(instance)}</div>
    <div style="font-size:13px;color:#6b7280;margin-top:4px">${today}${version ? ` · n8n ${esc(version)}` : ''}</div>
  </td></tr>
  <tr><td style="padding:12px 24px">
    <table role="presentation" cellpadding="0" cellspacing="8" style="margin-left:-8px"><tr>
      ${tile('FAIL', 'fail')}${tile('PASS', 'pass')}${tile('MANUAL', 'check by hand')}
    </tr></table>
  </td></tr>
  <tr><td style="padding:0 12px 8px">
    <table role="presentation" cellpadding="0" cellspacing="0" style="width:100%;border-collapse:collapse">
      <tr>
        <th style="text-align:left;padding:8px 12px;font-size:12px;color:#6b7280;font-weight:600">#</th>
        <th style="text-align:left;padding:8px 12px;font-size:12px;color:#6b7280;font-weight:600">Check</th>
        <th style="text-align:left;padding:8px 12px;font-size:12px;color:#6b7280;font-weight:600">Status</th>
        <th style="text-align:left;padding:8px 12px;font-size:12px;color:#6b7280;font-weight:600">What we found</th>
        <th style="text-align:left;padding:8px 12px;font-size:12px;color:#6b7280;font-weight:600">What to do</th>
      </tr>
      ${rows}
    </table>
  </td></tr>
  <tr><td style="padding:16px 24px 24px;font-size:12px;color:#6b7280;border-top:1px solid #e5e7eb;line-height:1.5">
    CHECK means the n8n API cannot see it; answer the questions in that row yourself.
    The checks follow Diego Rodriguez's <a href="https://symplytics.com/blog/n8n-security-checklist" style="color:#0969da">n8n Security Checklist for IT Teams</a>.
    This workflow is an independent build and is not made by or affiliated with the checklist's authors.
  </td></tr>
</table>
</body></html>`;

const icon = { PASS: '✅', FAIL: '❌', MANUAL: '❓' };
const text = [
  `*n8n security scorecard: ${instance}* (${today}${version ? `, n8n ${version}` : ''})`,
  `${totals.FAIL} fail · ${totals.PASS} pass · ${totals.MANUAL} to check by hand`,
  '',
  ...checks.map((c) => `${icon[c.status]} *${c.n}. ${c.name}*: ${c.found.join(' ')}`),
].join('\n');

return [{ json: { subject, html, text, totals, checks } }];
