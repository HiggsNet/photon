/* Local UI flow checks; no browser, router or real ubus acceptance is implied. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const packageDir = path.resolve(__dirname, '..');
const source = fs.readFileSync(path.join(packageDir,
	'htdocs/luci-static/resources/view/photon/overview.js'), 'utf8');

class Node {
	constructor(tag, attrs, children) {
		this.tagName = tag;
		this.attributes = attrs || {};
		this.style = {};
		this.children = [];
		this.value = '';
		this._text = '';
		(children || []).forEach(child => this.appendChild(child));
	}
	get firstChild() { return this.children[0]; }
	appendChild(child) { this.children.push(child); return child; }
	removeChild(child) { this.children.splice(this.children.indexOf(child), 1); }
	setAttribute(name, value) { this.attributes[name] = value; }
	get textContent() {
		return this._text + this.children.map(child => child instanceof Node ? child.textContent : String(child)).join('');
	}
	set textContent(text) { this._text = String(text); this.children = []; }
}

function E(tag, attrs, children) {
	return new Node(tag, attrs, children == null ? [] : Array.isArray(children) ? children : [children]);
}

function harness(options = {}) {
	const declarations = [];
	const calls = [];
	const polls = [];
	const snapshot = {
		ok: true,
		service: { running: true, pid: 123, enabled: true, boot_enabled: true },
		daemon: { daemon_online: true, managed_zone: '/mesh', known_peers: 3 },
		summary: { DaemonOnline: true, Peers: { Total: 3 }, Links: { Up: 1, Total: 2, Desired: 2 } }
	};
	const config = { ok: true, path: '/etc/photon/config.yaml', exists: true, content: 'name: initial\n', sha256: 'original-sha' };
	const handlers = {
		snapshot: () => snapshot,
		get_config: () => config,
		validate_config: () => ({ ok: true }),
		save_config: () => ({ ok: true, sha256: 'next-sha' }),
		service: () => ({ ok: true }),
		diagnostics: () => ({ ok: true, checks: [], preflight: 'checked', log: 'logs' })
	};
	const rpc = { declare(spec) {
		declarations.push(spec);
		return (...args) => {
			calls.push({ method: spec.method, args });
			return Promise.resolve().then(() => handlers[spec.method](...args));
		};
	} };
	const view = new Function('view', 'rpc', 'poll', 'E', '_', 'L', 'window', source)(
		{ extend: x => x }, rpc, { add: fn => polls.push(fn) }, E, x => x,
		{ hasViewPermission: () => !options.readonly }, { confirm: () => options.confirm !== false });
	return { view, handlers, calls, declarations, polls, snapshot, config,
		async render() { return view.render(await view.load()); } };
}

function withDetails(snapshot) {
	snapshot.peers = { peers: [{
		peer_id: 'canonical-peer', configured_addr: '192.0.2.5:33434',
		endpoints: [{ addr: '192.0.2.6:33434' }, { addr: '[2001:db8::7]:33434', selected: true }],
		active_pull_state: 'backoff', last_sync_unix: 1720000000,
		failure_count: 3, last_failure: { code: 'gossip_object_pull_failed', message: 'pull timed out' }
	}] };
	snapshot.links = { Inspection: { instances: [{
		id: 'canonical-link', peer_zone: '/mesh/neighbor', state: 'retrying', actual_state: 'installing',
		endpoint: '198.51.100.7:4500', interface_name: 'photon-xfrm42', child_sa_name: 'photon-child42',
		routing: { bird_state: 'starting' }, last_failure: { code: 'ipsec_link_failed', message: 'link not ready' }
	}], last_failure: { code: 'ipsec_reconcile_failed', message: 'reconcile pending' } } };
}

test('menu and ACL grant only the six Photon methods, with transport errors rejected', async () => {
	const h = harness();
	await h.render();
	assert.equal(h.declarations.length, 6);
	for (const declaration of h.declarations) {
		assert.equal(declaration.object, 'luci.photon');
		assert.equal(declaration.reject, true);
		assert.deepEqual(declaration.expect, { '': {} });
	}
	const acl = JSON.parse(fs.readFileSync(path.join(packageDir, 'root/usr/share/rpcd/acl.d/luci-app-photon.json')));
	assert.deepEqual(acl['luci-app-photon'].read, { ubus: { 'luci.photon': ['snapshot', 'get_config', 'diagnostics'] } });
	assert.deepEqual(acl['luci-app-photon'].write, { ubus: { 'luci.photon': ['validate_config', 'save_config', 'service'] } });
	const menu = JSON.parse(fs.readFileSync(path.join(packageDir, 'root/usr/share/luci/menu.d/luci-app-photon.json')));
	assert.equal(menu['admin/services/photon'].action.path, 'photon/overview');
});

test('concurrent-save conflict preserves edits and the original SHA; success advances SHA without restart', async () => {
	const h = harness();
	await h.render();
	h.view.editor.value = 'name: my edit\n';
	h.handlers.save_config = () => ({ ok: false, error: 'configuration changed; reload first' });
	await h.view.editConfig(true);
	assert.equal(h.view.editor.value, 'name: my edit\n');
	assert.equal(h.view.configSHA, 'original-sha');
	assert.match(h.view.configMessage.textContent, /configuration changed/);
	assert.equal(h.view.configButtons[1].disabled, false);
	assert.deepEqual(h.calls.find(call => call.method === 'save_config').args, ['name: my edit\n', 'original-sha']);
	h.handlers.save_config = () => ({ ok: true, sha256: 'new-version-sha' });
	await h.view.editConfig(true);
	assert.equal(h.view.configSHA, 'new-version-sha');
	assert.equal(h.view.savedContent, 'name: my edit\n');
	assert.equal(h.calls.filter(call => call.method === 'service').length, 0);
	h.view.editor.value = 'name: second edit\n';
	await h.view.editConfig(true);
	assert.deepEqual(h.calls.filter(call => call.method === 'save_config').at(-1).args, ['name: second edit\n', 'new-version-sha']);
});

test('validation and save transport errors keep text, restore controls and do not update the version', async () => {
	const h = harness();
	await h.render();
	h.view.editor.value = 'invalid: [';
	h.handlers.validate_config = () => ({ ok: false, error: 'invalid YAML' });
	await h.view.editConfig(false);
	assert.equal(h.view.editor.value, 'invalid: [');
	assert.match(h.view.configMessage.textContent, /invalid YAML/);
	h.handlers.save_config = () => { throw new Error('ubus denied'); };
	await h.view.editConfig(true);
	assert.equal(h.view.editor.value, 'invalid: [');
	assert.equal(h.view.configSHA, 'original-sha');
	assert.equal(h.view.editor.readOnly, false);
	assert.match(h.view.configMessage.textContent, /ubus denied/);
});

test('status refresh never changes unsaved text; failures clear live status rather than retaining a healthy snapshot', async () => {
	const h = harness();
	await h.render();
	assert.match(h.view.statusNode.textContent, /运行中，PID 123/);
	assert.match(h.view.statusNode.textContent, /1 \/ 2 \/ 2/);
	h.view.editor.value = 'unsaved';
	await h.polls[0]();
	assert.equal(h.view.editor.value, 'unsaved');
	h.handlers.snapshot = () => { throw new Error('connection lost'); };
	await h.polls[0]();
	assert.match(h.view.statusNode.textContent, /当前状态未知/);
	assert.doesNotMatch(h.view.statusNode.textContent, /PID 123|1 \/ 2 \/ 2/);
	assert.equal(h.view.editor.value, 'unsaved');
});

test('offline daemon suppresses cached peer and link counts despite a running process', async () => {
	const h = harness();
	h.snapshot.daemon.daemon_online = false;
	await h.render();
	assert.match(h.view.statusNode.textContent, /运行中/);
	assert.match(h.view.statusNode.textContent, /离线或尚未就绪/);
	assert.doesNotMatch(h.view.statusNode.textContent, /1 \/ 2 \/ 2|\/mesh/);
});

test('canonical peer and link fields map directly into the read-only detail tables', async () => {
	const h = harness();
	withDetails(h.snapshot);
	await h.render();
	const text = h.view.detailsNode.textContent;
	for (const value of ['canonical-peer', '[2001:db8::7]:33434', 'backoff',
		'gossip_object_pull_failed: pull timed out (3)', new Date(1720000000 * 1000).toLocaleString(),
		'/mesh/neighbor / canonical-link', 'photon-xfrm42 / 198.51.100.7:4500',
		'retrying / installing', 'photon-child42', 'starting',
		'ipsec_link_failed: link not ready', 'ipsec_reconcile_failed: reconcile pending'])
		assert.ok(text.includes(value), 'missing canonical detail: ' + value);
	assert.ok(!text.includes('192.0.2.5:33434'), 'configured address must not override selected endpoint');
	assert.ok(!text.includes('192.0.2.6:33434'), 'non-selected endpoint must not override selected endpoint');
});

test('an unselected configured address is clearly labelled rather than presented as selected', async () => {
	const h = harness();
	withDetails(h.snapshot);
	h.snapshot.peers.peers[0].endpoints = [];
	await h.render();
	assert.match(h.view.detailsNode.textContent, /192\.0\.2\.5:33434（配置地址，未选用）/);
});

test('either canonical offline marker clears previous live peers, addresses and links', async () => {
	for (const offlineSource of ['daemon', 'summary']) {
		const h = harness();
		withDetails(h.snapshot);
		await h.render();
		assert.match(h.view.detailsNode.textContent, /canonical-peer|canonical-link/);
		if (offlineSource === 'daemon')
			h.snapshot.daemon.daemon_online = false;
		else
			h.snapshot.summary.DaemonOnline = false;
		await h.view.refreshStatus();
		assert.match(h.view.detailsNode.textContent, /离线或实时状态尚未就绪/);
		assert.doesNotMatch(h.view.detailsNode.textContent, /canonical-peer|canonical-link|2001:db8|198\.51\.100|photon-xfrm42/);
	}
});

test('snapshot errors clear detailed node and link state rather than retaining prior addresses', async () => {
	const h = harness();
	withDetails(h.snapshot);
	await h.render();
	h.handlers.snapshot = () => { throw new Error('offline'); };
	await h.view.refreshStatus();
	assert.match(h.view.detailsNode.textContent, /状态未知/);
	assert.doesNotMatch(h.view.detailsNode.textContent, /canonical-peer|canonical-link|2001:db8|198\.51\.100/);
});

test('procd query failures show unknown process state, preserve known enable flags and display the error', async () => {
	const h = harness();
	h.snapshot.service = { running: false, enabled: true, boot_enabled: false, error: 'ubus service timeout' };
	await h.render();
	assert.match(h.view.statusNode.textContent, /procd 状态未知/);
	assert.match(h.view.statusNode.textContent, /ubus service timeout/);
	assert.match(h.view.statusNode.textContent, /服务开关已启用/);
	assert.match(h.view.statusNode.textContent, /开机启动已关闭/);
	assert.doesNotMatch(h.view.statusNode.textContent, /未运行/);
	assert.match(h.view.serviceButtons[4].textContent, /不停止当前进程/);
});

test('canonical inspect failure code and message are both displayed', async () => {
	const h = harness();
	h.snapshot.daemon.last_link_failure = { code: 'ipsec_reconcile_failed', message: 'VICI disconnected' };
	h.snapshot.daemon.last_routing_failure = { code: 'routing_reconcile_failed', message: 'BIRD unavailable' };
	await h.render();
	assert.match(h.view.statusNode.textContent, /ipsec_reconcile_failed: VICI disconnected/);
	assert.match(h.view.statusNode.textContent, /routing_reconcile_failed: BIRD unavailable/);
});

test('online pending admission shows canonical mode, stage and reason without claiming network acceptance', async () => {
	const h = harness();
	h.snapshot.summary.Mode = 'auto-join';
	h.snapshot.summary.AutoJoinStage = 'syncing_parent';
	h.snapshot.summary.Admission = { pending: true, reason_detail: 'waiting for bootstrap sync' };
	await h.render();
	assert.match(h.view.statusNode.textContent, /auto-join \/ syncing_parent/);
	assert.match(h.view.statusNode.textContent, /尚未完成接入：waiting for bootstrap sync/);
	h.snapshot.summary.DaemonOnline = false;
	await h.view.refreshStatus();
	assert.doesNotMatch(h.view.statusNode.textContent, /waiting for bootstrap sync|auto-join/);
});

test('saving or validating prevents service commands until the configuration operation finishes', async () => {
	for (const save of [false, true]) {
		const h = harness();
		await h.render();
		let release;
		h.handlers[save ? 'save_config' : 'validate_config'] = () => new Promise(resolve => { release = resolve; });
		const edit = h.view.editConfig(save);
		await Promise.resolve();
		assert.ok(h.view.serviceButtons.every(button => button.disabled));
		await h.view.serviceAction('restart');
		assert.equal(h.calls.filter(call => call.method === 'service').length, 0);
		release({ ok: true, sha256: 'saved-sha' });
		await edit;
		assert.ok(h.view.serviceButtons.every(button => !button.disabled));
	}
});

test('service operations lock configuration writes and reload until completion', async () => {
	const h = harness();
	await h.render();
	let release;
	h.handlers.service = () => new Promise(resolve => { release = resolve; });
	const restart = h.view.serviceAction('restart');
	await Promise.resolve();
	assert.ok(h.view.configButtons.every(button => button.disabled));
	assert.equal(h.view.editor.readOnly, true);
	assert.equal(h.view.reloadButton.disabled, true);
	await h.view.editConfig(true);
	await h.view.editConfig(false);
	await h.view.reloadConfig();
	assert.equal(h.calls.filter(call => ['save_config', 'validate_config'].includes(call.method)).length, 0);
	assert.equal(h.calls.filter(call => call.method === 'get_config').length, 1);
	// Failure must also release the mutual exclusion.
	release({ ok: false, error: 'restart failed' });
	await restart;
	assert.ok(h.view.configButtons.every(button => !button.disabled));
	assert.equal(h.view.editor.readOnly, false);
	assert.equal(h.view.reloadButton.disabled, false);
});

test('service failures remain errors; successful commands refresh status without touching config', async () => {
	const h = harness();
	await h.render();
	h.view.editor.value = 'unsaved';
	h.handlers.service = () => ({ ok: false, error: 'enable first' });
	await h.view.serviceAction('start');
	assert.match(h.view.serviceMessage.textContent, /enable first/);
	assert.equal(h.view.serviceButtons[0].disabled, false);
	h.handlers.service = () => ({ ok: true });
	const priorReads = h.calls.filter(call => call.method === 'snapshot').length;
	await h.view.serviceAction('enable');
	assert.match(h.view.serviceMessage.textContent, /请求已接受/);
	assert.equal(h.calls.filter(call => call.method === 'snapshot').length, priorReads + 1);
	assert.equal(h.view.editor.value, 'unsaved');
});

test('config load failure disables writes until a successful retry; cancelled reload keeps edits', async () => {
	const h = harness({ confirm: false });
	h.handlers.get_config = () => { throw new Error('permission denied'); };
	await h.render();
	assert.equal(h.view.configKnown, false);
	assert.equal(h.view.configButtons[1].disabled, true);
	h.handlers.get_config = () => h.config;
	await h.view.reloadConfig();
	assert.equal(h.view.configKnown, true);
	h.view.editor.value = 'keep me';
	const reads = h.calls.filter(call => call.method === 'get_config').length;
	await h.view.reloadConfig();
	assert.equal(h.calls.filter(call => call.method === 'get_config').length, reads);
	assert.equal(h.view.editor.value, 'keep me');
});

test('read-only sessions can inspect but cannot invoke write methods', async () => {
	const h = harness({ readonly: true });
	await h.render();
	assert.equal(h.view.editor.readOnly, true);
	assert.ok(h.view.configButtons.every(button => button.disabled));
	assert.ok(h.view.serviceButtons.every(button => button.disabled));
	await h.view.serviceAction('restart');
	await h.view.editConfig(true);
	await h.view.editConfig(false);
	assert.ok(h.calls.every(call => !['service', 'save_config', 'validate_config'].includes(call.method)));
	await h.view.loadDiagnostics();
	assert.match(h.view.diagnosticsNode.textContent, /checked|logs/);
});

test('status is marked unknown when the API returns a malformed success response', async () => {
	const h = harness();
	await h.render();
	h.handlers.snapshot = () => ({});
	await h.view.refreshStatus();
	assert.match(h.view.statusNode.textContent, /当前状态未知/);
	assert.doesNotMatch(h.view.statusNode.textContent, /PID 123/);
});
