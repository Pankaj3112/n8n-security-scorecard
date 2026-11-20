// Builds the scorecard: maps what n8n can see (public API, built-in security
// audit, a sandbox probe) plus the admin's saved one-time answers onto the 7
// checks of the n8n Security Checklist, and renders an HTML email + plain text.
// Text wrapped in `backticks` is shown as code in the email.

const cfg = $('Settings').first().json;
const baseUrl = String(cfg.n8nUrl || '').replace(/\/+$/, '');
const formUrl = `${baseUrl}/form/n8n-security-answers`;
const maxAdmins = Number(cfg.maxOwnersAndAdmins) || 3;
const maxBehindDays = Number(cfg.maxDaysBehindLatest) || 28;
const staleAfterDays = 90;

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
const daysBetween = (a, b) => Math.floor((new Date(b) - new Date(a)) / 86400000);
const fmtDate = (d) => new Date(d).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' });
const cap = (s) => s.charAt(0).toUpperCase() + s.slice(1);

// ---------- what n8n can see ----------
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
const liveNodes = (w) => (w.activeVersion && w.activeVersion.nodes) || w.nodes || [];

const pkgItems = items('Get community packages');
const pkgError = errorOf(pkgItems);
const packages = pkgError ? [] : pkgItems.filter((p) => p && p.packageName);

const logItems = items('Get log streaming destinations');
const logError = errorOf(logItems);
const logDestinations = logError ? [] : logItems.flatMap((p) => p.data || []).filter((d) => d && d.enabled !== false);

const version = (items('Read version')[0] || {}).version || null;
const releaseItems = items('Check n8n releases');
const releases = errorOf(releaseItems) ? [] : releaseItems.filter((r) => r && r.name);

const publicSettings = (items('Get public settings')[0] || {}).data || null;
const secureCookie = publicSettings && publicSettings.authCookie ? publicSettings.authCookie.secure : null;

// Runner mode: a Code node's own stack trace shows where the task runner code lives.
// Internal mode runs the runner from inside the n8n install; external mode runs it from the runners image.
let runnerMode = 'unknown';
try { null.probe; } catch (e) {
  const stack = String(e && e.stack || '');
  if (/node_modules\/n8n\/node_modules\/.*task-runner/.test(stack)) runnerMode = 'internal';
  else if (/task-runner/.test(stack)) runnerMode = 'external';
}

// Can workflow code read the server's environment? Blocked by default since n8n 2.0.
let envReadable;
try {
  const v = $env.PATH ?? $env.HOME;
  envReadable = v !== undefined && v !== null && !/denied/i.test(String(v));
} catch (e) {
  envReadable = false;
}

// ---------- the admin's saved answers ----------
const answerRows = items('Get saved answers').filter((r) => r && r.answered_at && !r.error);
const answers = answerRows.sort((a, b) => new Date(b.answered_at) - new Date(a.answered_at))[0] || null;
const answerAge = answers ? daysBetween(answers.answered_at, new Date().toISOString()) : null;
const stale = answers && answerAge > staleAfterDays;
const said = (key) => (answers ? String(answers[key] || '').trim().toLowerCase() === 'yes' : null);

// Each check: status, headline (one line), found (facts), fix (actions, FAIL only), needsAnswers.
const checks = [];
const add = (c) => checks.push({ n: checks.length + 1, found: [], fix: [], needsAnswers: false, ...c });
// Combine automated failures with the saved answers into one status.
const decide = (autoFail, answerFail, usesAnswers = true) => {
  if (autoFail || answerFail) return 'FAIL';
  if (usesAnswers && !answers) return 'MANUAL';
  return 'PASS';
};

// ---------- 1. Version ----------
{
  const outdated = section('instance', 'Outdated instance');
  const found = [];
  const fix = [];
  let status;
  let headline;
  if (version && releases.length) {
    const current = releases.find((r) => r.name === version);
    const newer = releases.filter((r) => r.name !== version)
      .sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));
    const security = newer.filter((r) => r.hasSecurityFix || r.hasSecurityIssue);
    const insecureNow = !!(current && current.hasSecurityIssue);
    const latest = newer[newer.length - 1];
    const behindDays = newer.length ? daysBetween(newer[0].createdAt, new Date().toISOString()) : 0;
    status = (security.length || insecureNow || behindDays > maxBehindDays) ? 'FAIL' : 'PASS';
    headline = newer.length
      ? `Running ${version}, ${plural(newer.length, 'release')} behind ${latest.name}`
      : `Running ${version}, the latest release`;
    if (newer.length) found.push(`First newer release came out ${plural(behindDays, 'day')} ago`);
    if (security.length) found.push(`Security fixes in ${security.map((r) => r.name).join(', ')}`);
    if (insecureNow) found.push('n8n flags this version as having a known security issue');
    if (status === 'FAIL') fix.push(`Upgrade to ${latest ? latest.name : 'the latest release'} (back up the database and keep the encryption key at hand)`);
  } else if (outdated) {
    status = 'FAIL';
    headline = 'This instance is out of date';
    found.push(outdated.description);
    fix.push('Upgrade to the latest release (back up the database and keep the encryption key at hand)');
  } else {
    status = 'MANUAL';
    headline = version ? `Running ${version}; api.n8n.io was not reachable this week` : 'Could not read the running version';
  }
  add({ name: 'Version', status, headline, found, fix });
}

// ---------- 2. Exposure ----------
{
  const PUBLIC_TRIGGERS = {
    'n8n-nodes-base.webhook': 'webhook',
    'n8n-nodes-base.formTrigger': 'form',
    '@n8n/n8n-nodes-langchain.mcpTrigger': 'MCP server',
    '@n8n/n8n-nodes-langchain.chatTrigger': 'chat',
  };
  // Webhooks the audit considers protected because the next node validates the payload.
  const auditOpen = new Set(((section('instance', 'Unprotected webhooks in instance') || {}).location || [])
    .map((l) => `${l.workflowId}/${l.nodeId}`));
  const open = [];
  const validated = [];
  let secured = 0;
  for (const w of workflows) {
    for (const node of liveNodes(w)) {
      const kind = PUBLIC_TRIGGERS[node.type];
      if (!kind || node.disabled) continue;
      const p = node.parameters || {};
      if (kind === 'chat' && p.public !== true) continue; // hosted chat is only public when made publicly available
      const auth = p.authentication || 'none';
      const path = p.path || (p.options && p.options.path);
      const label = `${w.name} (${kind}${path ? ` \`/${path}\`` : ''})`;
      if (auth !== 'none') secured++;
      else if (kind === 'webhook' && !auditOpen.has(`${w.id}/${node.id}`)) validated.push(label);
      else open.push(label);
    }
  }
  const editorOpen = said('editor_restricted') === false;
  const cookieInsecure = secureCookie === false;
  const status = decide(open.length || cookieInsecure || !!workflowsError, editorOpen);
  const found = [];
  const fix = [];
  const problems = [];
  if (open.length) problems.push(`${plural(open.length, 'public endpoint')} without authentication`);
  if (editorOpen) problems.push('editor reachable from anywhere');
  if (cookieInsecure) problems.push('login cookie not marked secure');
  const total = open.length + validated.length + secured;
  let headline = problems.length ? cap(problems.join(', ')) : `${plural(total, 'public endpoint')}, all authenticated`;
  if (workflowsError) { headline = 'Could not list workflows'; found.push(workflowsError); }
  for (const o of open) found.push(`No auth: ${o}`);
  for (const v of validated) found.push(`No auth, checked in the next node: ${v}`);
  if (total && !workflowsError) found.push(`${secured} of ${total} public endpoints authenticate`);
  if (answers) found.push(editorOpen ? 'Editor is not behind a VPN or IP allow-list (your answer)' : 'Editor is behind a VPN or IP allow-list (your answer)');
  if (cookieInsecure) found.push('`N8N_SECURE_COOKIE` is off, so logins work over plain HTTP');
  if (status === 'FAIL') {
    if (open.length) fix.push('Turn on Authentication for each endpoint (header auth with a shared secret is the quick option), or unpublish it');
    if (editorOpen) fix.push('Put the editor behind a VPN or an IP allow-list at the reverse proxy');
    if (cookieInsecure) fix.push('Serve n8n over HTTPS and remove `N8N_SECURE_COOKIE=false`');
  }
  add({ name: 'Exposure', status, headline, found, fix, needsAnswers: status === 'MANUAL' });
}

// ---------- 3. Credentials ----------
{
  const keyBad = said('key_off_server') === false;
  const scopeBad = said('creds_scoped') === false;
  const status = decide(false, keyBad || scopeBad);
  const found = [];
  const fix = [];
  const names = (title) => (((section('credentials', title)) || {}).location || []).map((l) => l.name);
  const unused = names('Credentials not used in any workflow');
  const inactive = names('Credentials not used in any active workflow').filter((n) => !unused.includes(n));
  if (answers) {
    found.push(keyBad ? '`N8N_ENCRYPTION_KEY` has no copy off the server (your answer)' : '`N8N_ENCRYPTION_KEY` set by you, copy kept off the server (your answer)');
    found.push(scopeBad ? 'Some credentials have more access than their workflow needs (your answer)' : 'Credentials are scoped to what each workflow needs (your answer)');
  }
  if (unused.length) found.push(`Not used in any workflow: ${unused.join(', ')}`);
  if (inactive.length) found.push(`Only used in unpublished workflows: ${inactive.join(', ')}`);
  if (keyBad) fix.push('Store a copy of `N8N_ENCRYPTION_KEY` in a password manager or secrets store; without it, backups cannot decrypt credentials');
  if (scopeBad) fix.push('Swap broad credentials for scoped ones (for example a read-only database user)');
  if (status === 'FAIL' && unused.length) fix.push('Delete credentials nothing uses');
  const headline = status === 'FAIL'
    ? cap([keyBad && 'encryption key has no off-server copy', scopeBad && 'some credentials are over-scoped'].filter(Boolean).join(', '))
    : status === 'PASS' ? 'Encryption key kept off the server; credentials scoped' : 'Encryption key storage and credential scopes';
  add({ name: 'Credentials', status, headline, found, fix, needsAnswers: status === 'MANUAL' });
}

// ---------- 4. Access ----------
{
  const found = [];
  const fix = [];
  let status;
  let headline;
  if (usersError) {
    status = 'MANUAL';
    headline = 'Could not list users';
    found.push(usersError);
  } else {
    const active = users.filter((u) => !u.isPending && !u.disabled);
    const admins = active.filter((u) => u.role === 'global:owner' || u.role === 'global:admin');
    const adminsNo2fa = admins.filter((u) => !u.mfaEnabled);
    const othersNo2fa = active.filter((u) => !admins.includes(u) && !u.mfaEnabled);
    const SHARED = /^(admin|administrator|ops|devops|it|team|shared|info|automation|automations|n8n|service|svc|bot|integrations?|support|dev|test|office|hello)([._+-].*)?$/i;
    const shared = active.filter((u) => u.email && SHARED.test(u.email.split('@')[0]));
    const pending = users.filter((u) => u.isPending);
    const who = (u) => u.email || `${u.firstName || ''} ${u.lastName || ''}`.trim();
    status = (admins.length > maxAdmins || adminsNo2fa.length || shared.length) ? 'FAIL' : 'PASS';
    const problems = [];
    if (admins.length > maxAdmins) problems.push(`${admins.length} owners/admins`);
    if (adminsNo2fa.length) problems.push(`${plural(adminsNo2fa.length, 'admin')} without 2FA`);
    if (shared.length) problems.push(plural(shared.length, 'shared-looking login'));
    headline = problems.length ? cap(problems.join(', ')) : `${plural(admins.length, 'owner/admin', 'owners/admins')}, all with 2FA`;
    found.push(`${plural(admins.length, 'owner/admin', 'owners/admins')} of ${plural(active.length, 'user')}: ${admins.map(who).join(', ')}`);
    if (adminsNo2fa.length) found.push(`No 2FA: ${adminsNo2fa.map(who).join(', ')}`);
    if (shared.length) found.push(`Looks shared: ${shared.map(who).join(', ')}`);
    if (othersNo2fa.length) found.push(`${plural(othersNo2fa.length, 'other user')} without 2FA`);
    if (pending.length) found.push(`Pending invites: ${pending.map(who).join(', ')}`);
    if (status === 'FAIL') {
      if (admins.length > maxAdmins) fix.push(`Cut owners/admins to ${maxAdmins} or fewer`);
      if (adminsNo2fa.length) fix.push('Turn on 2FA for every owner and admin');
      if (shared.length) fix.push('Give each person their own named account');
      if (pending.length) fix.push('Cancel invites nobody will accept');
    }
  }
  add({ name: 'Access', status, headline, found, fix });
}

// ---------- 5. Code ----------
{
  const found = [];
  const fix = [];
  const internal = runnerMode === 'internal';
  let status = (envReadable || internal) ? 'FAIL' : (runnerMode === 'external' ? 'PASS' : 'MANUAL');
  const problems = [];
  if (internal) problems.push('task runners run in internal mode');
  if (envReadable) problems.push('workflow code can read server environment variables');
  const headline = problems.length ? cap(problems.join('; '))
    : status === 'PASS' ? 'External task runners; environment variables blocked'
      : 'Could not detect the task runner mode';
  found.push(runnerMode === 'unknown'
    ? 'Task runner mode: not detectable on this install'
    : `Task runners: ${runnerMode} mode (detected from a Code node in this run)`);
  found.push(envReadable
    ? 'A Code node in this run could read server environment variables'
    : 'A Code node in this run could not read server environment variables');
  if (internal) fix.push('Run the runners as a separate container: `N8N_RUNNERS_MODE=external` plus the `n8nio/runners` image, with the same `N8N_RUNNERS_AUTH_TOKEN` on both sides');
  if (envReadable) fix.push('Set `N8N_BLOCK_ENV_ACCESS_IN_NODE=true` (the default since 2.0)');
  add({ name: 'Code', status, headline, found, fix });
}

// ---------- 6. Community nodes ----------
{
  const found = [];
  const fix = [];
  const settings = (section('instance', 'Security settings') || {}).settings || {};
  const enabled = settings.features ? settings.features.communityPackagesEnabled : undefined;
  const auditCommunity = ((section('nodes', 'Community nodes') || {}).location || []).map((l) => l.nodeType);
  const usedTypes = new Set(workflows.flatMap((w) => liveNodes(w).map((n) => n.type)));
  const pkgs = packages.length ? packages
    : [...new Set(auditCommunity.map((t) => t.split('.')[0]))].map((name) => ({ packageName: name }));
  const unused = [];
  for (const p of pkgs) {
    const types = (p.installedNodes || []).map((n) => n.type);
    const inUse = types.length ? types.some((t) => usedTypes.has(t)) : auditCommunity.some((t) => t.startsWith(p.packageName + '.'));
    const bits = [p.installedVersion, p.authorName && `by ${p.authorName}`, inUse ? 'used by a published workflow' : 'not used by any published workflow', p.updateAvailable && `update ${p.updateAvailable} available`].filter(Boolean);
    found.push(`\`${p.packageName}\` ${bits.join(', ')}`);
    if (!inUse) unused.push(p.packageName);
  }
  const off = enabled === false;
  const unverifiedOn = !off && said('unverified_off') === false;
  const status = off ? (pkgs.length ? (unused.length ? 'FAIL' : 'PASS') : 'PASS') : decide(unused.length > 0, unverifiedOn);
  if (!off && !pkgs.length && pkgError && !/404/.test(pkgError)) found.unshift(`Could not list packages: ${pkgError}`);
  if (answers && !off) found.push(unverifiedOn ? 'Unverified packages can still be installed (your answer)' : '`N8N_UNVERIFIED_PACKAGES_ENABLED=false` is set (your answer)');
  if (unused.length) fix.push(`Uninstall ${unused.map((u) => `\`${u}\``).join(', ')}`);
  if (unverifiedOn) fix.push('Set `N8N_UNVERIFIED_PACKAGES_ENABLED=false` so only n8n-verified packages can be installed');
  const problems = [];
  if (unused.length) problems.push(`${plural(unused.length, 'package')} installed but unused`);
  if (unverifiedOn) problems.push('unverified packages allowed');
  const headline = problems.length ? cap(problems.join(', '))
    : off ? 'Community packages are turned off'
      : pkgs.length ? `${plural(pkgs.length, 'package')}, each used by a published workflow` : 'No community packages installed';
  add({ name: 'Community nodes', status, headline, found, fix, needsAnswers: status === 'MANUAL' });
}

// ---------- 7. Recovery and logs ----------
{
  const found = [];
  const fix = [];
  const backupBad = said('backup_restored') === false;
  const streaming = logDestinations.length > 0;
  const logsBad = !streaming && said('logs_reviewed') === false;
  const status = decide(false, backupBad || logsBad);
  if (answers) {
    found.push(backupBad ? 'No tested restore of a backup yet (your answer)' : 'Backups run on a schedule, are kept off the server and a restore was tested (your answer)');
  }
  if (streaming) found.push(`Logs stream to ${logDestinations.map((d) => d.label || d.__type || 'a destination').join(', ')}`);
  else if (answers) {
    const reviewer = String(answers.logs_reviewer || '').trim();
    found.push(logsBad ? 'Nobody reviews the n8n logs on a schedule (your answer)' : `Logs are reviewed on a schedule${reviewer ? ` by ${reviewer}` : ''} (your answer)`);
  }
  if (backupBad) fix.push('Back up the database on a schedule, copy it off the server, and restore it on another machine once with the encryption key');
  if (logsBad) fix.push('Pick someone to read the n8n logs every week, or stream them to a tool your team already watches');
  const headline = status === 'FAIL'
    ? cap([backupBad && 'backup restore never tested', logsBad && 'nobody watches the logs'].filter(Boolean).join(', '))
    : status === 'PASS' ? 'Restore tested; logs watched' : 'Backups, restores and log review';
  add({ name: 'Recovery and logs', status, headline, found, fix, needsAnswers: status === 'MANUAL' });
}

// ---------- render ----------
const count = (s) => checks.filter((c) => c.status === s).length;
const totals = { PASS: count('PASS'), FAIL: count('FAIL'), MANUAL: count('MANUAL') };
const instance = cfg.instanceName || baseUrl;
const today = fmtDate(new Date());
const subject = totals.FAIL
  ? `n8n security: ${plural(totals.FAIL, 'check')} failed on ${instance}`
  : totals.MANUAL ? `n8n security: ${totals.PASS} of 7 passed on ${instance}; answer the one-time questions to score the rest`
    : `n8n security: all 7 checks passed on ${instance}`;

const FONT = "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif";
const MONO = 'ui-monospace,SFMono-Regular,Menlo,Consolas,monospace';
const STATUS = {
  FAIL: { fg: '#b42318', bg: '#fef3f2', line: '#f04438', label: 'Fail' },
  PASS: { fg: '#067647', bg: '#ecfdf3', line: '#17b26a', label: 'Pass' },
  MANUAL: { fg: '#93370d', bg: '#fffaeb', line: '#f79009', label: 'Needs answers' },
};
const rich = (s) => esc(s).replace(/`([^`]+)`/g,
  `<code style="font-family:${MONO};font-size:12px;background:#f2f4f7;border-radius:4px;padding:1px 5px;color:#344054">$1</code>`);
const link = (href, text) => `<a href="${esc(href)}" style="color:#175cd3;font-weight:600;text-decoration:none">${esc(text)}</a>`;
const block = (label, lines, mark) => !lines.length ? '' : `
  <tr><td colspan="2" style="padding:12px 0 0">
    <div style="font-size:11px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:#98a2b3;padding-bottom:4px">${label}</div>
    ${lines.map((l) => `<table role="presentation" cellpadding="0" cellspacing="0" width="100%"><tr>
      <td width="18" valign="top" style="font-size:14px;line-height:22px;color:#98a2b3">${mark}</td>
      <td style="font-size:14px;line-height:22px;color:#344054">${rich(l)}</td></tr></table>`).join('')}
  </td></tr>`;

const card = (c) => {
  const s = STATUS[c.status];
  const ask = c.needsAnswers
    ? `<tr><td colspan="2" style="padding:12px 0 0;font-size:14px;line-height:22px;color:#344054">n8n can't see this part. ${link(formUrl, 'Answer the one-time questions →')}</td></tr>`
    : '';
  return `
<tr><td style="padding:0 0 12px">
  <table role="presentation" cellpadding="0" cellspacing="0" width="100%" style="background:#ffffff;border:1px solid #eaecf0;border-left:4px solid ${s.line};border-radius:10px">
    <tr><td style="padding:18px 20px">
      <table role="presentation" cellpadding="0" cellspacing="0" width="100%">
        <tr>
          <td valign="top">
            <div style="font-size:12px;color:#98a2b3;font-weight:600">${c.n} of 7</div>
            <div style="font-size:17px;font-weight:700;color:#101828;padding-top:2px">${esc(c.name)}</div>
          </td>
          <td valign="top" align="right">
            <span style="display:inline-block;padding:4px 12px;border-radius:999px;background:${s.bg};color:${s.fg};font-size:12px;font-weight:700;white-space:nowrap">${s.label}</span>
          </td>
        </tr>
        <tr><td colspan="2" style="padding-top:8px;font-size:15px;line-height:22px;color:#101828">${rich(c.headline)}</td></tr>
        ${block('Found', c.found, '•')}
        ${c.status === 'FAIL' ? block('Fix', c.fix, '→') : ''}
        ${ask}
      </table>
    </td></tr>
  </table>
</td></tr>`;
};

const stat = (s, label) => `
  <td width="33%" style="padding:0 4px">
    <table role="presentation" cellpadding="0" cellspacing="0" width="100%" style="background:${STATUS[s].bg};border-radius:10px">
      <tr><td align="center" style="padding:14px 8px">
        <div style="font-size:28px;font-weight:800;line-height:32px;color:${STATUS[s].fg}">${totals[s]}</div>
        <div style="font-size:12px;font-weight:600;color:${STATUS[s].fg};padding-top:2px">${label}</div>
      </td></tr>
    </table>
  </td>`;
const stats = totals.MANUAL
  ? stat('FAIL', 'Failed') + stat('PASS', 'Passed') + stat('MANUAL', 'Need answers')
  : `${stat('FAIL', 'Failed')}${stat('PASS', 'Passed')}`;

let banner = '';
if (!answers) {
  banner = `n8n can't see a few things, like where the encryption key is kept or whether a backup was ever restored. ${link(formUrl, 'Answer 6 yes/no questions once')} (about 2 minutes) and every scorecard after that is fully scored.`;
} else if (stale) {
  banner = `Your answers are from ${fmtDate(answers.answered_at)} (${answerAge} days ago). ${link(formUrl, 'Confirm they are still true')}.`;
}
const bannerHtml = banner ? `
  <tr><td style="padding:0 0 12px">
    <table role="presentation" cellpadding="0" cellspacing="0" width="100%" style="background:#eff8ff;border:1px solid #b2ddff;border-radius:10px">
      <tr><td style="padding:14px 18px;font-size:14px;line-height:21px;color:#194185">${banner}</td></tr>
    </table>
  </td></tr>` : '';
const answeredLine = answers
  ? `Answers by ${esc(answers.answered_by || 'an admin')} on ${esc(fmtDate(answers.answered_at))}. ${link(formUrl, 'Update them')} any time.<br>`
  : '';

const html = `<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(subject)}</title></head>
<body style="margin:0;padding:0;background:#f2f4f7;font-family:${FONT}">
<table role="presentation" cellpadding="0" cellspacing="0" width="100%" style="background:#f2f4f7">
<tr><td align="center" style="padding:28px 12px">
<table role="presentation" cellpadding="0" cellspacing="0" width="100%" style="max-width:640px;font-family:${FONT}">
  <tr><td style="padding:0 0 16px">
    <table role="presentation" cellpadding="0" cellspacing="0" width="100%" style="background:#101828;border-radius:12px">
      <tr><td style="padding:24px 24px 20px">
        <div style="font-size:12px;font-weight:600;letter-spacing:.08em;text-transform:uppercase;color:#98a2b3">n8n security scorecard</div>
        <div style="font-size:24px;font-weight:700;color:#ffffff;padding-top:6px">${esc(instance)}</div>
        <div style="font-size:13px;color:#98a2b3;padding-top:4px">${esc(today)}${version ? ` &nbsp;·&nbsp; n8n ${esc(version)}` : ''} &nbsp;·&nbsp; 7 checks</div>
      </td></tr>
      <tr><td style="padding:0 20px 20px">
        <table role="presentation" cellpadding="0" cellspacing="0" width="100%"><tr>${stats}</tr></table>
      </td></tr>
    </table>
  </td></tr>
  ${bannerHtml}
  ${checks.map(card).join('')}
  <tr><td style="padding:8px 8px 0;font-size:12px;line-height:18px;color:#667085">
    ${answeredLine}Based on the <a href="https://symplytics.com/blog/n8n-security-checklist" style="color:#175cd3">n8n Security Checklist</a> by Symplytics (Diego Rodriguez).
    Independent build, not made by or affiliated with Symplytics.
  </td></tr>
</table>
</td></tr>
</table>
</body></html>`;

const icon = { PASS: '✅', FAIL: '❌', MANUAL: '📝' };
const text = [
  `*n8n security scorecard: ${instance}* (${today}${version ? `, n8n ${version}` : ''})`,
  `${totals.FAIL} failed · ${totals.PASS} passed${totals.MANUAL ? ` · ${totals.MANUAL} need answers` : ''}`,
  '',
  ...checks.map((c) => `${icon[c.status]} *${c.n}. ${c.name}*: ${c.headline.replace(/`/g, '')}`),
  ...(!answers || stale ? ['', `${!answers ? 'Answer the one-time questions' : 'Confirm your answers'}: ${formUrl}`] : []),
].join('\n');

return [{ json: { subject, html, text, totals, checks, runnerMode, answeredAt: answers ? answers.answered_at : null } }];
