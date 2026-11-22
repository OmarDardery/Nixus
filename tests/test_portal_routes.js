'use strict';
// Every route the console calls must be allowed by the portal (cmd/nixus/server.go).
// Built route names are listed explicitly so a cleanup cannot drop a live route (#94).
const assert = require('node:assert/strict'), fs = require('node:fs'), path = require('node:path');
const root = path.join(__dirname, '..');
const server = fs.readFileSync(path.join(root, 'cmd/nixus/server.go'), 'utf8');
const allowed = new Set(server.match(/\/api\/[a-z0-9/-]+/g));
const dir = path.join(root, 'admin/static');
const js = fs.readdirSync(dir).filter(f => f.endsWith('.js')).map(f => fs.readFileSync(path.join(dir, f), 'utf8')).join('\n');
const routes = new Set();
for (const m of js.matchAll(/\b(?:api|appRequest|repoAction)\("([a-z0-9/-]+)["?]/g)) if (!m[1].endsWith('-')) routes.add(m[1]);
// Names built at runtime.
for (const action of ['verify', 'restore']) routes.add('project-secrets/recovery-' + action);
for (const name of ['apply', 'confirm', 'rollback', 'cancel']) routes.add(name);
assert.ok(routes.size > 20, 'route scan found too few calls: ' + routes.size);
const missing = [...routes].filter(r => !allowed.has('/api/' + r)).sort();
assert.deepEqual(missing, [], 'console routes the portal refuses: ' + missing.join(', '));
console.log('Portal route checks passed: ' + routes.size + ' console routes are allowed.');
