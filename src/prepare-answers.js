// Shapes the form submission into one row for the answers data table.
const form = $('One-time questions').first().json;
const yn = (v) => (String(v || '').trim().toLowerCase() === 'yes' ? 'yes' : 'no');
return [{
  json: {
    answered_by: String(form.answered_by || '').trim(),
    answered_at: new Date().toISOString(),
    editor_restricted: yn(form.editor_restricted),
    key_off_server: yn(form.key_off_server),
    creds_scoped: yn(form.creds_scoped),
    unverified_off: yn(form.unverified_off),
    backup_restored: yn(form.backup_restored),
    logs_reviewed: yn(form.logs_reviewed),
    logs_reviewer: String(form.logs_reviewer || '').trim(),
  },
}];
