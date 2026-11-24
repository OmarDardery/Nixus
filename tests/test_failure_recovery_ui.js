'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const read = name => fs.readFileSync(path.join(__dirname, '../admin/static', name), 'utf8');
const esc = value => String(value ?? '').replaceAll('<', '&lt;');

async function checkFailedView(file, refresh, render, page, view, retry) {
  let requests = 0, renders = 0, failed = true;
  const context = vm.createContext({
    state: {page, status: {release: {}}}, document: {activeElement: null},
    administrator: () => true, esc, title: () => '', badge: esc,
    card: (heading, body) => body, setTimeout: () => {},
    api: async () => { requests++; if (failed) throw Error('Backend unavailable'); return {}; },
    shell: () => { assert.ok(++renders < 5, 'render triggered a retry loop'); vm.runInContext(render, context); },
  });
  vm.runInContext(read(file), context);
  await vm.runInContext(refresh + '()', context);
  await new Promise(resolve => setImmediate(resolve));
  const afterFailure = requests;
  const html = vm.runInContext(render, context);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(requests, afterFailure, file + ' automatically retried a failed initial request');
  assert.match(html, /Backend unavailable/);
  assert.ok(html.includes(retry), file + ' has no retry control');
  failed = false;
  await vm.runInContext(refresh + '()', context);
  assert.equal(vm.runInContext(view + '.loadError', context), '', 'load errors clear after recovery');
}

(async () => {
  await checkFailedView('apps.js', 'refreshApps', 'appsPage()', 'projects', 'appView', 'Retry loading apps');
  await checkFailedView('backups.js', 'refreshBackups', 'backupsCards()', 'operations', 'backupView', 'Refresh backup status');
  await checkFailedView('quick.js', 'refreshQuick', 'quickActions()', 'overview', 'quick', 'Retry status');

  // Errors returned by a reverse proxy can be HTML, or JSON null.
  let status = 502, payload = null, malformed = true, logins = 0;
  const apiContext = vm.createContext({state: {csrf: 'csrf'}, login: () => logins++,
    fetch: async () => ({status, ok: false, json: async () => {if (malformed) throw Error('HTML'); return payload;}})});
  vm.runInContext(read('api.js'), apiContext);
  await assert.rejects(vm.runInContext("api('status')", apiContext), /unreadable response/);
  status = 401;
  await assert.rejects(vm.runInContext("api('status')", apiContext));
  assert.equal(logins, 1, '401 must show login even when its body is not JSON');
  status = 503; malformed = false;
  await assert.rejects(vm.runInContext("api('status')", apiContext), /HTTP 503/);

  // A slow status request must not overlap the next timer tick. A render
  // deferred while typing must still happen after the job stops changing.
  let resolveStatus, calls = 0, redraws = 0, editing = true;
  const context = vm.createContext({document: {querySelector: () => null}, setInterval: () => 0,
    setupIncomplete: () => false, typing: () => editing,
    api: () => {calls++; return new Promise(resolve => resolveStatus = resolve);}});
  const source = read('app.js');
  vm.runInContext(source.slice(0, source.lastIndexOf('\n(async () =>')), context);
  context.redraw = () => redraws++;
  vm.runInContext("state.page='review'; state.status={job:null}; shell=redraw", context);
  const first = vm.runInContext('poll()', context);
  await vm.runInContext('poll()', context);
  assert.equal(calls, 1);
  resolveStatus({job: {status: 'ready'}}); await first;
  assert.equal(redraws, 0);
  editing = false;
  const next = vm.runInContext('poll()', context);
  resolveStatus({job: {status: 'ready'}}); await next;
  assert.equal(redraws, 1, 'deferred render was lost');
  console.log('Failure recovery verified: bounded retries, explicit recovery, malformed responses and non-overlapping polling.');
})().catch(error => {console.error(error); process.exit(1);});
