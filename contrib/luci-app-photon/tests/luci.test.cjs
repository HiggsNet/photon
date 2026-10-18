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
		this.value = attrs && attrs.value || '';
		this.checked = false;
		this.selected = false;
		this._text = '';
		(children || []).forEach(child => this.appendChild(child));
	}
	get firstChild() { return this.children[0]; }
	get selectedOptions() { return this.children.filter(child => child.selected); }
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
	const network = {
		ok: true, settings: { wan_networks: [], announce_ipsec: false, auto_firewall: false },
		inventory: [{ name: 'wan', up: true, l3_device: 'eth0', ipv4_addresses: ['192.168.1.2'], ipv6_addresses: [] },
			{ name: 'wan6', up: false, l3_device: '', ipv4_addresses: [], ipv6_addresses: [] }],
		status: { ready: true, enabled: false }, runtime: { enabled: false, auto_firewall: false, addresses: [], devices: [], wan_networks: [] }
	};
	const handlers = {
		snapshot: () => snapshot,
		get_config: () => config,
		validate_config: () => ({ ok: true }),
		save_config: () => ({ ok: true, sha256: 'next-sha' }),
		service: () => ({ ok: true }),
		diagnostics: () => ({ ok: true, checks: [], preflight: 'checked', log: 'logs' }),
		network_settings: () => ({ ...network, sha256: config.sha256 }),
		save_network_settings: (encoded, sha) => {
			if (sha !== config.sha256) return { ok: false, error: 'configuration changed' };
			network.settings = JSON.parse(encoded);
			config.content = 'name: initial\nopenwrt: ' + encoded + '\n';
			config.sha256 = 'network-save-sha';
			return { ...config, settings: network.settings };
		}
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
	return { view, handlers, calls, declarations, polls, snapshot, config, network,
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

test('menu and ACL grant only the eight Photon methods, with transport errors rejected', async () => {
	const h = harness();
	await h.render();
	assert.equal(h.declarations.length, 8);
	for (const declaration of h.declarations) {
		assert.equal(declaration.object, 'luci.photon');
		assert.equal(declaration.reject, true);
		assert.deepEqual(declaration.expect, { '': {} });
	}
	const acl = JSON.parse(fs.readFileSync(path.join(packageDir, 'root/usr/share/rpcd/acl.d/luci-app-photon.json')));
	assert.deepEqual(acl['luci-app-photon'].read, { ubus: { 'luci.photon': ['snapshot', 'get_config', 'diagnostics', 'network_settings'] } });
	assert.deepEqual(acl['luci-app-photon'].write, { ubus: { 'luci.photon': ['validate_config', 'save_config', 'service', 'save_network_settings'] } });
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

test('network form defaults disabled and shows logical networks with canonical runtime state', async () => {
	const h = harness();
	h.network.runtime = { enabled: true, auto_firewall: true, firewall_applied: false,
		wan_networks: ['wan'], devices: ['eth0'], addresses: ['192.168.1.2'], last_error: 'fw4 chain unavailable' };
	await h.render();
	assert.equal(h.view.announceCheckbox.checked, false);
	assert.equal(h.view.firewallCheckbox.checked, false);
	assert.equal(h.view.networkSelect.children[0].value, 'wan');
	assert.match(h.view.networkSelect.textContent, /192\.168\.1\.2/);
	assert.match(h.view.networkRuntimeNode.textContent, /尚未应用或应用失败/);
	assert.match(h.view.networkRuntimeNode.textContent, /fw4 chain unavailable/);
	assert.doesNotMatch(h.view.networkRuntimeNode.textContent, /守护进程报告已应用/);
});

test('network form cannot overwrite dirty YAML and pending form edits lock the YAML and service controls', async () => {
	const h = harness();
	await h.render();
	h.view.editor.value = 'unsaved YAML';
	h.view.updateButtons();
	assert.equal(h.view.networkSaveButton.disabled, true);
	await h.view.saveNetworkSettings();
	assert.equal(h.calls.filter(c => c.method === 'save_network_settings').length, 0);
	h.view.editor.value = h.view.savedContent;
	h.view.announceCheckbox.checked = true;
	h.view.announceCheckbox.attributes.change();
	assert.equal(h.view.editor.readOnly, true);
	assert.ok(h.view.configButtons.every(b => b.disabled));
	assert.ok(h.view.serviceButtons.every(b => b.disabled));
	await h.view.serviceAction('restart');
	await h.view.editConfig(true);
	assert.ok(!h.calls.some(c => c.method === 'service' || c.method === 'save_config'));
});

test('network settings save uses the loaded YAML SHA and updates the same editor without restarting', async () => {
	const h = harness();
	await h.render();
	h.view.networkSelect.children[0].selected = true;
	h.view.announceCheckbox.checked = true;
	h.view.firewallCheckbox.checked = true;
	h.view.announceCheckbox.attributes.change();
	await h.view.saveNetworkSettings();
	const save = h.calls.find(c => c.method === 'save_network_settings');
	assert.equal(save.args[1], 'original-sha');
	assert.deepEqual(JSON.parse(save.args[0]), { wan_networks: ['wan'], announce_ipsec: true, auto_firewall: true });
	assert.equal(h.view.configSHA, 'network-save-sha');
	assert.equal(h.view.editor.value, h.config.content);
	assert.equal(h.view.savedContent, h.config.content);
	assert.equal(h.view.networkDirty, false);
	assert.match(h.view.configMessage.textContent, /尚未应用/);
	assert.ok(!h.calls.some(c => c.method === 'service'));
});

test('network settings SHA conflicts retain network choices, YAML and loaded version', async () => {
	const h = harness();
	await h.render();
	h.view.networkSelect.children[0].selected = true;
	h.view.firewallCheckbox.checked = true;
	h.view.firewallCheckbox.attributes.change();
	h.handlers.save_network_settings = () => ({ ok: false, error: 'stale network config' });
	await h.view.saveNetworkSettings();
	assert.equal(h.view.networkSelect.children[0].selected, true);
	assert.equal(h.view.firewallCheckbox.checked, true);
	assert.equal(h.view.editor.value, 'name: initial\n');
	assert.equal(h.view.configSHA, 'original-sha');
	assert.equal(h.view.networkDirty, true);
	assert.match(h.view.networkMessage.textContent, /stale network config/);
});

test('runtime polling never resets pending form choices, YAML or optimistic version', async () => {
	const h = harness();
	await h.render();
	h.view.networkSelect.children[1].selected = true;
	h.view.announceCheckbox.checked = true;
	h.view.announceCheckbox.attributes.change();
	h.network.runtime = { enabled: true, auto_firewall: true, firewall_applied: true, addresses: ['2001:db8::1'] };
	await h.polls[0]();
	assert.equal(h.view.networkSelect.children[1].selected, true);
	assert.equal(h.view.announceCheckbox.checked, true);
	assert.equal(h.view.networkDirty, true);
	assert.equal(h.view.configSHA, 'original-sha');
	assert.equal(h.view.editor.value, 'name: initial\n');
	assert.match(h.view.networkRuntimeNode.textContent, /守护进程报告已应用/);
});

test('read-only users cannot change network settings and inventory failure stays visible', async () => {
	const h = harness({ readonly: true });
	h.network.inventory_error = 'ubus unavailable';
	h.network.inventory = [];
	h.network.runtime = null;
	h.network.runtime_error = 'daemon offline';
	await h.render();
	assert.equal(h.view.networkSelect.disabled, true);
	assert.equal(h.view.announceCheckbox.disabled, true);
	assert.equal(h.view.networkSaveButton.disabled, true);
	await h.view.saveNetworkSettings();
	assert.ok(!h.calls.some(c => c.method === 'save_network_settings'));
	assert.match(h.view.networkMessage.textContent, /ubus unavailable/);
	assert.match(h.view.networkRuntimeNode.textContent, /daemon offline/);
});

test('a mismatched form/config snapshot cannot silently overwrite or adopt another version', async () => {
	const h = harness();
	h.handlers.network_settings = () => ({ ...h.network, sha256: 'other-session-version' });
	await h.render();
	assert.equal(h.view.networkKnown, false);
	assert.equal(h.view.networkSaveButton.disabled, true);
	assert.equal(h.view.editor.value, 'name: initial\n');
	assert.equal(h.view.configSHA, 'original-sha');
	assert.match(h.view.networkMessage.textContent, /版本不同/);
});

test('scheduled service tasks stay mutually exclusive with writes until a terminal procd snapshot', async () => {
	const h = harness();
	await h.render();
	h.view.editor.value = 'unsaved: still here\n';
	h.handlers.service = () => ({ ok: true, scheduled: true });
	h.snapshot.service.action = { running: true, action: 'restart' };
	await h.view.serviceAction('restart');
	assert.match(h.view.serviceMessage.textContent, /请求已提交给 procd/);
	assert.match(h.view.statusNode.textContent, /重启请求已提交，正在执行/);
	assert.equal(h.view.serviceBusy, false, 'HTTP acceptance has completed');
	assert.equal(h.view.serviceTaskRunning, true, 'procd task is still in progress');
	assert.ok(h.view.serviceButtons.every(b => b.disabled));
	assert.ok(h.view.configButtons.every(b => b.disabled));
	assert.equal(h.view.editor.readOnly, true);
	assert.equal(h.view.networkSaveButton.disabled, true);
	const before = h.calls.length;
	await h.view.serviceAction('stop');
	await h.view.editConfig(true);
	await h.view.saveNetworkSettings();
	assert.equal(h.calls.length, before, 'direct handlers cannot bypass the task lock');
	h.snapshot.service.action = { running: false, action: 'restart', exit_code: 0 };
	await h.view.refreshStatus();
	assert.match(h.view.statusNode.textContent, /重启任务已结束，退出码 0/);
	assert.equal(h.view.serviceTaskRunning, false);
	assert.ok(h.view.serviceButtons.every(b => !b.disabled));
	assert.ok(h.view.configButtons.every(b => !b.disabled));
	assert.equal(h.view.editor.value, 'unsaved: still here\n');
});

test('remote procd task state is respected on initial load and task failure remains visible', async () => {
	const h = harness();
	h.snapshot.service.action = { running: true, action: 'stop' };
	await h.render();
	assert.ok(h.view.serviceButtons.every(b => b.disabled));
	assert.equal(h.view.networkSaveButton.disabled, true);
	h.snapshot.service.action = { running: false, action: 'stop', exit_code: 42, error: 'cleanup failed' };
	await h.polls[0]();
	assert.match(h.view.statusNode.textContent, /停止任务已结束，退出码 42/);
	assert.match(h.view.statusNode.textContent, /服务操作错误：cleanup failed/);
	assert.ok(h.view.serviceButtons.every(b => !b.disabled));
	assert.match(h.view.statusNode.textContent, /运行中，PID 123/, 'task completion must not invent a stopped process');
});

test('lost or incomplete task snapshots never unlock a request already accepted by procd', async () => {
	const h = harness();
	await h.render();
	h.handlers.service = () => ({ ok: true, scheduled: true });
	h.handlers.snapshot = () => { throw new Error('rpcd unavailable'); };
	await h.view.serviceAction('stop');
	assert.equal(h.view.serviceTaskRunning, true);
	assert.ok(h.view.serviceButtons.every(b => b.disabled));
	assert.match(h.view.statusNode.textContent, /当前状态未知/);
	h.handlers.snapshot = () => h.snapshot;
	await h.view.refreshStatus();
	assert.equal(h.view.serviceTaskRunning, true);
	assert.match(h.view.statusNode.textContent, /操作状态尚未确认/);
	h.snapshot.service.action = { running: false, action: 'stop', exit_code: 0 };
	await h.view.refreshStatus();
	assert.equal(h.view.serviceTaskRunning, false);
});

test('unknown procd action state locks writes, while an explicit terminal failure permits retry', async () => {
	const h = harness();
	h.snapshot.service.action = { running: null, action: '', exit_code: null, error: 'procd task query failed' };
	await h.render();
	assert.match(h.view.statusNode.textContent, /procd 操作状态未知/);
	assert.match(h.view.statusNode.textContent, /procd task query failed/);
	assert.ok(h.view.serviceButtons.every(b => b.disabled));
	assert.ok(h.view.configButtons.every(b => b.disabled));
	assert.equal(h.view.networkSaveButton.disabled, true);
	h.snapshot.service.action = { running: false, action: 'restart', exit_code: 1, error: 'restart cleanup failed' };
	await h.view.refreshStatus();
	assert.match(h.view.statusNode.textContent, /重启任务已结束，退出码 1/);
	assert.match(h.view.statusNode.textContent, /restart cleanup failed/);
	assert.ok(h.view.serviceButtons.every(b => !b.disabled));
	assert.ok(h.view.configButtons.every(b => !b.disabled));
});
