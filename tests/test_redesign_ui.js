'use strict';
// Regression checks for the redesigned shell without requiring a browser or live host.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const root = path.join(__dirname, '../admin/static');
const source = fs.readFileSync(path.join(root, 'app.js'), 'utf8');
const bootstrap = source.lastIndexOf('\n(async () =>');
assert.ok(bootstrap > 0);
const context = vm.createContext({document:{querySelector:()=>({})},setInterval:()=>0,URL});
for (const name of ['projects.js', 'foundation.js', 'operations.js', 'apps.js', 'commands.js', 'setup.js'])
  vm.runInContext(fs.readFileSync(path.join(root, name), 'utf8'), context);
vm.runInContext(source.slice(0, bootstrap), context);
const fixture = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures/defaults.json'), 'utf8'));
context.fixture = fixture;
vm.runInContext(`
state.status = {settings: copy(fixture),setupComplete:true,codeOverrides:[],job:null};
state.host = {kvm:true,interfaces:[],disks:[],serialDevices:[],helpers:{sources:{},applications:[]}};
state.draft = copy(fixture);
state.principal = {username:'admin',role:'admin'};
state.page = 'overview';
`, context);
const ids = JSON.parse(vm.runInContext('JSON.stringify(pages.map(([id])=>id))', context));
for (const id of ['overview','projects','guests','network','storage','hardware','integrations','security','ingress','operations','review','system','files','commands'])
  assert.ok(ids.includes(id), 'Missing redesigned route: ' + id);
const nav = vm.runInContext('navigationHtml()', context);
for (const id of ['overview', 'projects', 'operations', 'network', 'review', 'commands']) assert.ok(nav.includes('data-go="' + id + '"'));
assert.equal((nav.match(/data-go=/g) || []).length, 6, 'six top-level destinations');
assert.ok(nav.includes('aria-current="page"'), 'Current page should be announced.');
const tabs = vm.runInContext("state.page='storage';settingsTabs()", context);
for (const id of ['network','guests','storage','hardware','integrations','security','ingress','system','files'])
  assert.ok(tabs.includes('data-go="' + id + '"'), 'settings tab missing: ' + id);
assert.ok(vm.runInContext("state.page='storage';navigationHtml()", context).includes('class="active"'), 'Settings stays highlighted');
assert.equal(vm.runInContext("state.page='overview';settingsTabs()", context), '');
vm.runInContext("state.page='overview'", context);
assert.equal(vm.runInContext('stagedCount()', context), 0);
vm.runInContext("state.draft.management.address='192.0.2.110';state.draft.hostName='sample-host';",context);
assert.equal(vm.runInContext('stagedCount()',context), 2);
assert.ok(vm.runInContext('stagedBanner()',context).includes('2 staged changes'));
const guest = vm.runInContext("state.page='guests';renderPage()",context);
assert.ok(guest.includes('Guests & addresses'));
assert.ok(!guest.includes('data-guest-action'), 'Guest mutations belong in Incus, not the Nixus portal.');
const storage = vm.runInContext("state.page='storage';renderPage()",context);
assert.ok(storage.includes('Detected drives') && storage.includes('Declared mounts'));
const access = vm.runInContext("state.page='security';security()",context);
assert.ok(access.includes('Create an Incus browser identity'));
assert.ok(!access.includes('Cloudflare Tunnel'), 'Ingress configuration must live on its dedicated page.');
const ingress = vm.runInContext("state.page='ingress';ingressPage()",context);
assert.ok(ingress.includes('data-path="tunnel.enable"'));
assert.ok(ingress.includes('data-ingress'));
assert.ok(!ingress.includes('certificate-passphrase'));
const ready = vm.runInContext("state.page='review';state.status.job={id:'a'.repeat(32),status:'ready',guestPlan:{targets:[]}};deploymentTimeline()",context);
assert.ok(ready.includes('aria-current="step"') && ready.includes('Activate host'));
const confirmed = vm.runInContext("state.status.job.status='confirmed';deploymentTimeline()",context);
assert.ok(confirmed.includes('Deploy guests') && confirmed.includes('complete'));
const ops = vm.runInContext("state.page='operations';operationView.users=[];operationsPage()",context);
assert.ok(!ops.includes('Portal accounts'), 'Accounts are not part of backup recovery.');
assert.ok(!vm.runInContext("state.page='operations';title('','Backups','')",context).includes('href="/docs/install.md"'));
assert.ok(source.includes('passwd') && !source.includes('reset-password') && !source.includes('setup password printed by the installer'), 'Single-user console: forgotten passwords are reset with passwd');
console.log('Redesigned console checks passed: routing, drafts, safe delegation, permissions and deployment stages.');

vm.runInContext("state.status.release={revision:'a'.repeat(40)};state.draft=copy(fixture);state.platformRevision='a'.repeat(40)", context);
assert.equal(vm.runInContext('stagedCount()',context),0);
assert.ok(vm.runInContext('platformSelectionText()',context).includes('rebuild only'));
vm.runInContext("state.platformRevision='b'.repeat(40);state.status.job={status:'confirmed',platformRevision:'a'.repeat(40),platformChanges:[{path:'old.nix',before:null,after:'{}'}]}",context);
assert.equal(vm.runInContext('stagedCount()',context),1);
const platform = vm.runInContext('platformReview()',context);
assert.ok(platform.includes('Proposed: ') && platform.includes('Historical confirmed review'));
assert.ok(platform.includes('Historical platform files (1)'));
assert.ok(!platform.includes('Candidate:'));

// Panels: the page's first section opens, the rest collapse; Overview and Changes start collapsed.
vm.runInContext("state.page='network'; panelIndex = 0", context);
const first = vm.runInContext("card('One', '<p>a</p>')", context), second = vm.runInContext("card('Two', '<p>b</p>')", context);
assert.match(first, /<details class="card panel" data-panel="network:one" open>/);
assert.doesNotMatch(second, / open>/);
assert.match(vm.runInContext("card('Forced', 'x', '', {open: true})", context), / open>/);
vm.runInContext("state.page='overview'; panelIndex = 0", context);
assert.doesNotMatch(vm.runInContext("card('Host', 'x')", context), / open>/, "Overview panels start collapsed");

// The staged bar names each staged item and can undo it.
vm.runInContext("state.page='overview'; state.platformRevision='a'.repeat(40); state.status.release={revision:'b'.repeat(40)}", context);
const staged = vm.runInContext("stagedItems()", context);
assert.equal(staged.length, 1);
assert.match(staged[0].label, /Update Nixus to aaaaaaaaaaaa/);
assert.match(vm.runInContext("stagedBanner()", context), /data-undo-staged="0"/);
vm.runInContext("stagedItems()[0].undo()", context);
assert.equal(vm.runInContext("stagedCount()", context), 0);
console.log("Panels and staged items verified");
