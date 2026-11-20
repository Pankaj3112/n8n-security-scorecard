// Reads the running n8n version from the editor page.
// The editor HTML carries a base64 JSON meta tag whose "release" is "n8n@<version>".
const page = $input.first().json;
const html = typeof page.data === 'string' ? page.data : '';
let version = null;
const m = html.match(/name="n8n:config:sentry"\s+content="([^"]+)"/);
if (m) {
  try {
    const raw = typeof Buffer !== 'undefined'
      ? Buffer.from(m[1], 'base64').toString('utf8')
      : atob(m[1]);
    const release = JSON.parse(raw).release || '';
    const v = release.replace(/^n8n@/, '');
    if (/^\d+\.\d+\.\d+/.test(v)) version = v;
  } catch (e) {
    version = null;
  }
}
return [{ json: { version } }];
