// Builds the scorecard: maps the n8n API data onto the 7 checks of the
// "n8n Security Checklist for IT Teams" and renders an HTML email + plain text.
// Text wrapped in `backticks` is shown as code in the email.

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
const liveNodes = (w) => (w.activeVersion && w.activeVersion.nodes) || w.nodes || [];

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

// Each check: status, headline (one line), found (facts), fix (actions), ask (questions for a person).
const checks = [];
const add = (c) => checks.push({ n: checks.length + 1, found: [], fix: [], ask: [], ...c });

// ---------- 1. Version ----------
{
  const outdated = section('instance', 'Outdated instance');
  const found = [];
  const fix = [];
  const ask = [];
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
    if (!newer.length) {
      headline = `Running ${version}, the latest release`;
    } else {
      headline = `Running ${version}, ${plural(newer.length, 'release')} behind ${latest.name}`;
      found.push(`First newer release came out ${plural(behindDays, 'day')} ago`);
    }
    if (security.length) found.push(`Security fixes in ${security.map((r) => r.name).join(', ')}`);
    if (insecureNow) found.push('n8n flags this version as having a known security issue');
    if (status === 'FAIL') fix.push(`Upgrade to ${latest ? latest.name : 'the latest release'} (back up the database and keep the encryption key at hand)`);
    ask.push('Does someone read the release notes every week?');
  } else if (outdated) {
    status = 'FAIL';
    headline = 'Instance is out of date';
    found.push(outdated.description);
    fix.push('Upgrade to the latest release (back up the database and keep the encryption key at hand)');
  } else {
    status = 'MANUAL';
    headline = version ? `Running ${version}; could not reach api.n8n.io to compare` : 'Could not read the running version';
    ask.push('Is this instance within a few weeks of the latest release, with every security release applied?');
  }
  add({ name: 'Version', status, headline, found, fix, ask });
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
      const label = `${w.name} (${kind}${p.path ? ` \`/${p.path}\`` : ''})`;
      if (auth !== 'none') secured++;
      else if (kind === 'webhook' && !auditOpen.has(`${w.id}/${node.id}`)) validated.push(label);
      else open.push(label);
    }
  }
  const found = [];
  const fix = [];
  const ask = [];
  let status;
  let headline;
  if (workflowsError) {
    status = 'MANUAL';
    headline = 'Could not list workflows';
    found.push(workflowsError);
    ask.push('Does every active webhook, form, chat and MCP Server Trigger authenticate?');
  } else {
    const total = open.length + validated.length + secured;
    status = open.length ? 'FAIL' : 'PASS';
    headline = open.length
      ? `${plural(open.length, 'public endpoint')} with no authentication`
      : `${plural(total, 'public endpoint')}, all authenticated`;
    for (const o of open) found.push(`No auth: ${o}`);
    for (const v of validated) found.push(`No auth, checked in next node: ${v}`);
    if (total) found.push(`${secured} of ${total} public endpoints authenticate`);
    if (open.length) fix.push('Turn on Authentication for each one (header auth with a shared secret is the quick option), or unpublish it');
    if (validated.length) ask.push('Does the next-node check really verify a signature or secret?');
    ask.push('Is the editor behind a VPN or an IP allow-list?');
  }
  add({ name: 'Exposure', status, headline, found, fix, ask });
}

// ---------- 3. Credentials ----------
{
  const found = [];
  const fix = [];
  const names = (title) => (((section('credentials', title)) || {}).location || []).map((l) => l.name);
  let headline = 'Key storage and scopes need a person to confirm';
  if (auditError) {
    found.push(`Security audit failed: ${auditError}`);
  } else {
    const unused = names('Credentials not used in any workflow');
    const inactive = names('Credentials not used in any active workflow').filter((n) => !unused.includes(n));
    const stale = names('Credentials not used in recently executed workflows').filter((n) => !unused.includes(n) && !inactive.includes(n));
    if (unused.length) found.push(`Not used anywhere: ${unused.join(', ')}`);
    if (inactive.length) found.push(`Only in unpublished workflows: ${inactive.join(', ')}`);
    if (stale.length) found.push(`Not run in 90 days: ${stale.join(', ')}`);
    const idle = unused.length + inactive.length + stale.length;
    if (idle) {
      headline = `${plural(idle, 'credential')} idle; key storage needs a person to confirm`;
      fix.push('Delete the credentials you no longer need');
    } else {
      found.push('Every credential is in active, recent use');
    }
  }
  const ask = [
    'Did you set `N8N_ENCRYPTION_KEY` yourself, and is a copy kept off the server?',
    'Is each credential scoped to what its workflow needs?',
  ];
  add({ name: 'Credentials', status: 'MANUAL', headline, found, fix, ask });
}

// ---------- 4. Access ----------
{
  const found = [];
  const fix = [];
  const ask = [];
  let status;
  let headline;
  if (usersError) {
    status = 'MANUAL';
    headline = 'Could not list users';
    found.push(usersError);
    ask.push('How many owners and admins are there, and does each have 2FA?');
  } else {
    const active = users.filter((u) => !u.isPending && !u.disabled);
    const admins = active.filter((u) => u.role === 'global:owner' || u.role === 'global:admin');
    const adminsNo2fa = admins.filter((u) => !u.mfaEnabled);
    const othersNo2fa = active.filter((u) => !admins.includes(u) && !u.mfaEnabled);
    const SHARED = /^(admin|administrator|ops|devops|it|team|shared|info|automation|automations|n8n|service|svc|bot|integrations?|support|dev|test|office|hello)([._+-].*)?$/i;
    const shared = active.filter((u) => u.email && SHARED.test(u.email.split('@')[0]));
    const pending = users.filter((u) => u.isPending);
    const who = (u) => u.email || `${u.firstName || ''} ${u.lastName || ''}`.trim();
    const fail = admins.length > maxAdmins || adminsNo2fa.length || shared.some((u) => admins.includes(u));
    status = fail ? 'FAIL' : (shared.length ? 'MANUAL' : 'PASS');
    const problems = [];
    if (admins.length > maxAdmins) problems.push(`${admins.length} owners/admins`);
    if (adminsNo2fa.length) problems.push(`${plural(adminsNo2fa.length, 'admin')} without 2FA`);
    if (shared.length) problems.push(`${plural(shared.length, 'shared-looking login')}`);
    headline = problems.length
      ? problems.join(', ').replace(/^./, (c) => c.toUpperCase())
      : `${plural(admins.length, 'owner/admin', 'owners/admins')}, all with 2FA`;
    found.push(`${plural(admins.length, 'owner/admin', 'owners/admins')} of ${plural(active.length, 'user')}: ${admins.map(who).join(', ')}`);
    if (adminsNo2fa.length) found.push(`No 2FA: ${adminsNo2fa.map(who).join(', ')}`);
    if (shared.length) found.push(`Looks shared: ${shared.map(who).join(', ')}`);
    if (othersNo2fa.length) found.push(`${plural(othersNo2fa.length, 'other user')} without 2FA`);
    if (pending.length) found.push(`Pending invites: ${pending.map(who).join(', ')}`);
    if (admins.length > maxAdmins) fix.push(`Cut owners/admins to ${maxAdmins} or fewer`);
    if (adminsNo2fa.length) fix.push('Turn on 2FA for every owner and admin');
    if (shared.length) fix.push('Give each person their own named account');
    if (pending.length) fix.push('Cancel invites nobody will accept');
  }
  add({ name: 'Access', status, headline, found, fix, ask });
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
  const found = [envReadable
    ? 'Test: a Code node could read server environment variables'
    : 'Test: a Code node could not read server environment variables'];
  if (!auditError && codeWfs.length) {
    found.push(`Code, Execute Command or SSH in ${plural(codeWfs.length, 'workflow')}: ${codeWfs.slice(0, 6).join(', ')}${codeWfs.length > 6 ? ', …' : ''}`);
  }
  const fix = envReadable ? ['Set `N8N_BLOCK_ENV_ACCESS_IN_NODE=true` (the default since 2.0)'] : [];
  const ask = ['Do task runners run in external mode (`N8N_RUNNERS_MODE=external`, separate container)? n8n warns at startup while they are internal.'];
  add({
    name: 'Code',
    status: envReadable ? 'FAIL' : 'MANUAL',
    headline: envReadable ? 'Workflow code can read server secrets' : 'Env access blocked; runner mode needs a person to confirm',
    found, fix, ask,
  });
}

// ---------- 6. Community nodes ----------
{
  const found = [];
  const fix = [];
  const ask = [];
  let status;
  let headline;
  const settings = (section('instance', 'Security settings') || {}).settings || {};
  const enabled = settings.features ? settings.features.communityPackagesEnabled : undefined;
  const auditCommunity = ((section('nodes', 'Community nodes') || {}).location || []).map((l) => l.nodeType);
  if (pkgError && !auditCommunity.length) {
    if (enabled === false) {
      status = 'PASS';
      headline = 'Community packages are turned off';
    } else {
      status = 'MANUAL';
      headline = 'Could not list community packages';
      found.push(pkgError);
      ask.push('Which community packages are installed, and does each have a reason to stay?');
    }
  } else if (!packages.length && !auditCommunity.length) {
    status = 'PASS';
    headline = 'No community packages installed';
  } else {
    const usedTypes = new Set(workflows.flatMap((w) => liveNodes(w).map((n) => n.type)));
    const pkgs = packages.length ? packages : [...new Set(auditCommunity.map((t) => t.split('.')[0]))].map((name) => ({ packageName: name }));
    const unused = [];
    for (const p of pkgs) {
      const types = (p.installedNodes || []).map((n) => n.type);
      const inUse = types.length ? types.some((t) => usedTypes.has(t)) : auditCommunity.some((t) => t.startsWith(p.packageName + '.'));
      const bits = [p.installedVersion, p.authorName && `by ${p.authorName}`, inUse ? 'in use' : 'not used by any published workflow', p.updateAvailable && `update ${p.updateAvailable} available`].filter(Boolean);
      found.push(`\`${p.packageName}\` ${bits.join(', ')}`);
      if (!inUse) unused.push(p.packageName);
    }
    status = unused.length ? 'FAIL' : 'MANUAL';
    headline = unused.length
      ? `${plural(unused.length, 'package')} installed but unused`
      : `${plural(pkgs.length, 'package')} installed; each needs a reason to stay`;
    if (unused.length) fix.push(`Uninstall ${unused.map((u) => `\`${u}\``).join(', ')}`);
    ask.push('For each package: who maintains it, and does a built-in node now do the same job?');
  }
  if (enabled !== false) ask.push('Is `N8N_UNVERIFIED_PACKAGES_ENABLED=false` set?');
  add({ name: 'Community nodes', status, headline, found, fix, ask });
}

// ---------- 7. Recovery and logs ----------
{
  const found = [];
  if (logError) {
    found.push(/40[34]|licen|forbidden/i.test(logError)
      ? 'Log streaming is a paid feature, so the API cannot see where logs go'
      : `Could not read log streaming settings: ${logError}`);
  } else {
    const on = logDestinations.filter((d) => d.enabled !== false);
    found.push(on.length
      ? `Logs stream to ${on.map((d) => d.label || d.__type || 'a destination').join(', ')}`
      : 'No log streaming destination set up');
  }
  const ask = [
    'Is the database backed up on a schedule and copied off the server?',
    'Has a backup been restored on another machine at least once?',
    'Who reads the n8n logs, and how often?',
  ];
  add({ name: 'Recovery and logs', status: 'MANUAL', headline: 'Backups and logs need a person to confirm', found, fix: [], ask });
}

// ---------- render ----------
const count = (s) => checks.filter((c) => c.status === s).length;
const totals = { PASS: count('PASS'), FAIL: count('FAIL'), MANUAL: count('MANUAL') };
const instance = cfg.instanceName || cfg.n8nUrl;
const today = new Date().toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric', timeZone: 'UTC' });
const subject = totals.FAIL
  ? `n8n security: ${plural(totals.FAIL, 'check')} failed on ${instance}`
  : `n8n security: no failed checks on ${instance}`;

const FONT = "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif";
const MONO = "ui-monospace,SFMono-Regular,Menlo,Consolas,monospace";
const STATUS = {
  FAIL: { fg: '#b42318', bg: '#fef3f2', line: '#f04438', label: 'Fail' },
  PASS: { fg: '#067647', bg: '#ecfdf3', line: '#17b26a', label: 'Pass' },
  MANUAL: { fg: '#93370d', bg: '#fffaeb', line: '#f79009', label: 'Check' },
};
const rich = (s) => esc(s).replace(/`([^`]+)`/g,
  `<code style="font-family:${MONO};font-size:12px;background:#f2f4f7;border-radius:4px;padding:1px 5px;color:#344054">$1</code>`);
const block = (label, lines, mark) => !lines.length ? '' : `
  <tr><td style="padding:12px 0 0">
    <div style="font-size:11px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:#98a2b3;padding-bottom:4px">${label}</div>
    ${lines.map((l) => `<table role="presentation" cellpadding="0" cellspacing="0" width="100%"><tr>
      <td width="18" valign="top" style="font-size:14px;line-height:22px;color:#98a2b3">${mark}</td>
      <td style="font-size:14px;line-height:22px;color:#344054">${rich(l)}</td></tr></table>`).join('')}
  </td></tr>`;

const card = (c) => {
  const s = STATUS[c.status];
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
            <span style="display:inline-block;padding:4px 12px;border-radius:999px;background:${s.bg};color:${s.fg};font-size:12px;font-weight:700">${s.label}</span>
          </td>
        </tr>
        <tr><td colspan="2" style="padding-top:8px;font-size:15px;line-height:22px;color:#101828">${rich(c.headline)}</td></tr>
        ${block('Found', c.found, '•')}
        ${block('Fix', c.fix, '→')}
        ${block('Answer yourself', c.ask, '☐')}
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
        <table role="presentation" cellpadding="0" cellspacing="0" width="100%"><tr>
          ${stat('FAIL', 'Failed')}${stat('PASS', 'Passed')}${stat('MANUAL', 'Check yourself')}
        </tr></table>
      </td></tr>
    </table>
  </td></tr>
  ${checks.map(card).join('')}
  <tr><td style="padding:8px 8px 0;font-size:12px;line-height:18px;color:#667085">
    <b>Check</b> means the n8n API can't see it, so a person has to answer the questions in that card.
    The checks follow Diego Rodriguez's <a href="https://symplytics.com/blog/n8n-security-checklist" style="color:#175cd3">n8n Security Checklist for IT Teams</a>.
    This workflow is an independent build, not made by or affiliated with the checklist's authors.
  </td></tr>
</table>
</td></tr>
</table>
</body></html>`;

const icon = { PASS: '✅', FAIL: '❌', MANUAL: '❔' };
const text = [
  `*n8n security scorecard: ${instance}* (${today}${version ? `, n8n ${version}` : ''})`,
  `${totals.FAIL} failed · ${totals.PASS} passed · ${totals.MANUAL} to check yourself`,
  '',
  ...checks.map((c) => `${icon[c.status]} *${c.n}. ${c.name}*: ${c.headline.replace(/`/g, '')}`),
].join('\n');

return [{ json: { subject, html, text, totals, checks } }];
