'use strict';
'require view';
'require rpc';
'require poll';

function declare(method, params) {
	return rpc.declare({
		object: 'luci.photon',
		method: method,
		params: params || [],
		expect: { '': {} },
		reject: true
	});
}

var callSnapshot = declare('snapshot');
var callGetConfig = declare('get_config');
var callValidateConfig = declare('validate_config', ['content']);
var callSaveConfig = declare('save_config', ['content', 'sha256']);
var callService = declare('service', ['action']);
var callDiagnostics = declare('diagnostics');

function checked(reply) {
	if (!reply || reply.ok !== true)
		throw new Error(reply && reply.error || _('Photon 管理接口返回失败或无效结果。'));
	return reply;
}

function errorText(error) {
	return error && error.message ? error.message : String(error);
}

function replace(node, children) {
	while (node.firstChild)
		node.removeChild(node.firstChild);
	(children || []).forEach(function(child) { node.appendChild(child); });
}

function display(value) {
	return value === undefined || value === null || value === '' ? '—' : String(value);
}

function rowsTable(rows) {
	return E('table', { 'class': 'table' }, rows.map(function(row) {
		return E('tr', { 'class': 'tr' }, [
			E('th', { 'class': 'th', 'style': 'width: 30%' }, row[0]),
			E('td', { 'class': 'td', 'style': 'overflow-wrap: anywhere' }, display(row[1]))
		]);
	}));
}

function failureText(failure) {
	return failure ? [failure.code, failure.message].filter(Boolean).join(': ') : _('无已报告错误');
}

function detailTable(headers, rows, emptyMessage) {
	if (!rows.length)
		return E('p', {}, emptyMessage);
	return E('div', { 'style': 'overflow-x: auto' }, [
		E('table', { 'class': 'table' }, [
			E('tr', { 'class': 'tr' }, headers.map(function(header) {
				return E('th', { 'class': 'th' }, header);
			}))
		].concat(rows.map(function(row) {
			return E('tr', { 'class': 'tr' }, row.map(function(value) {
				return E('td', { 'class': 'td', 'style': 'overflow-wrap: anywhere' }, display(value));
			}));
		})))
	]);
}

function syncTime(timestamp) {
	return typeof timestamp === 'number' && timestamp > 0 ? new Date(timestamp * 1000).toLocaleString() : '—';
}

return view.extend({
	handleSaveApply: null,
	handleSave: null,
	handleReset: null,

	load: function() {
		return Promise.all([
			callSnapshot().then(checked).catch(function(e) { return { error: errorText(e) }; }),
			callGetConfig().then(checked).catch(function(e) { return { error: errorText(e) }; })
		]);
	},

	notice: function(node, message, error) {
		node.textContent = message;
		node.setAttribute('class', error ? 'alert-message error' : 'alert-message notice');
		node.style.display = message ? '' : 'none';
	},

	updateButtons: function() {
		var self = this;
		this.configButtons.forEach(function(button) {
			button.disabled = self.readonly || self.configBusy || self.serviceBusy || !self.configKnown;
		});
		this.reloadButton.disabled = this.configBusy || this.serviceBusy;
		this.editor.readOnly = this.readonly || this.configBusy || this.serviceBusy || !this.configKnown;
		this.serviceButtons.forEach(function(button) {
			button.disabled = self.readonly || self.serviceBusy || self.configBusy;
		});
		this.dirtyLabel.textContent = !this.configKnown ? _('尚未读取配置') :
			this.editor.value !== this.savedContent ? _('有未保存的修改') : _('无未保存的修改');
	},

	showSnapshot: function(snapshot) {
		if (!snapshot || snapshot.ok !== true) {
			replace(this.statusNode, [E('p', { 'class': 'alert-message error' },
				_('状态读取失败，当前状态未知：') + display(snapshot && snapshot.error))]);
			replace(this.detailsNode, [E('p', {}, _('节点与链路状态未知，已清除上次详情。'))]);
			return;
		}
		var service = snapshot.service || {};
		var daemon = snapshot.daemon || {};
		var summary = snapshot.summary;
		// Cached database summaries must never be presented as live connectivity.
		var online = daemon.daemon_online === true;
		var liveSummary = online && summary && summary.DaemonOnline === true ? summary : null;
		var links = liveSummary ? liveSummary.Links : null;
		var peers = liveSummary ? liveSummary.Peers : null;
		var admission = liveSummary && liveSummary.Admission || {};
		var processState = service.error || typeof service.running !== 'boolean' ? _('procd 状态未知') :
			service.running ? _('运行中，PID ') + display(service.pid) : _('未运行');
		replace(this.statusNode, [rowsTable([
			[_('Photon 进程'), processState],
			[_('服务开关'), typeof service.enabled !== 'boolean' ? _('状态未知') :
				service.enabled ? _('已启用') : _('已禁用；启动前需先启用')],
			[_('开机启动'), typeof service.boot_enabled !== 'boolean' ? _('状态未知') :
				service.boot_enabled ? _('已开启') : _('已关闭')],
			[_('控制接口'), online ? _('可响应') : _('离线或尚未就绪')],
			[_('接入状态 / 阶段'), liveSummary ? display(liveSummary.Mode) + ' / ' + display(liveSummary.AutoJoinStage) : null],
			[_('待授权 / 接入原因'), liveSummary ?
				(admission.pending === true ? _('尚未完成接入：') : '') + display(admission.reason_detail || admission.reason) : null],
			[_('管理区域'), online ? daemon.managed_zone : null],
			[_('已知节点'), online ? (peers ? peers.Total : daemon.known_peers || 0) : null],
			[_('链路运行数 / 总数 / 期望数'), links ?
				display(links.Up) + ' / ' + display(links.Total) + ' / ' + display(links.Desired) : null],
			[_('最近链路错误'), online ? failureText(daemon.last_link_failure) : null],
			[_('最近路由错误'), online ? failureText(daemon.last_routing_failure) : null]
		])].concat(service.error ? [E('p', { 'class': 'alert-message error' }, _('服务状态查询失败：') + service.error)] : [])
			.concat(snapshot.error ? [E('p', { 'class': 'alert-message warning' }, snapshot.error)] : []));
		this.showDetails(snapshot, online && summary && summary.DaemonOnline === true);
	},

	showDetails: function(snapshot, online) {
		if (!online) {
			replace(this.detailsNode, [E('p', {}, _('控制接口离线或实时状态尚未就绪，已清除上次节点与链路详情。'))]);
			return;
		}
		var peers = snapshot.peers && Array.isArray(snapshot.peers.peers) ? snapshot.peers.peers : null;
		var inspection = snapshot.links && snapshot.links.Inspection;
		var links = inspection && Array.isArray(inspection.instances) ? inspection.instances : null;
		replace(this.detailsNode, [
			E('h4', {}, _('节点')),
			peers ? detailTable([_('节点'), _('选用地址'), _('同步时间 / 拉取状态'), _('错误')], peers.map(function(peer) {
				var selected = (peer.endpoints || []).filter(function(endpoint) { return endpoint.selected === true; })[0];
				var address = selected ? selected.addr : peer.configured_addr ?
					peer.configured_addr + _('（配置地址，未选用）') : null;
				return [peer.peer_id, address,
					syncTime(peer.last_sync_unix) + ' / ' + display(peer.active_pull_state),
					failureText(peer.last_failure) + (peer.failure_count ? ' (' + peer.failure_count + ')' : '')];
			}), _('暂无节点。')) : E('p', {}, _('未获得实时节点详情。')),
			E('h4', {}, _('链路')),
			links ? detailTable([_('节点 / 链路'), _('接口 / 地址'), _('链路状态 / 实际状态'), 'CHILD', 'BIRD', _('错误')], links.map(function(link) {
				return [display(link.peer_zone) + ' / ' + display(link.id),
					display(link.interface_name) + ' / ' + display(link.endpoint),
					display(link.state) + ' / ' + display(link.actual_state),
					link.child_sa_name, link.routing && link.routing.bird_state, failureText(link.last_failure)];
			}), _('暂无链路。')) : E('p', {}, _('未获得实时链路详情。'))
		].concat(inspection && inspection.last_failure ?
			[E('p', { 'class': 'alert-message warning' }, failureText(inspection.last_failure))] : []));
	},

	refreshStatus: function() {
		var self = this;
		var generation = ++this.statusGeneration;
		return callSnapshot().then(checked).then(function(reply) {
			if (generation === self.statusGeneration)
				self.showSnapshot(reply);
		}).catch(function(error) {
			if (generation === self.statusGeneration)
				self.showSnapshot({ error: errorText(error) });
		});
	},

	installConfig: function(reply) {
		if (typeof reply.content !== 'string' || typeof reply.sha256 !== 'string')
			throw new Error(_('配置接口返回格式无效，未载入编辑器。'));
		this.configKnown = true;
		this.savedContent = reply.content;
		this.configSHA = reply.sha256;
		this.editor.value = reply.content;
		this.configPath.textContent = display(reply.path);
		this.notice(this.configMessage, reply.exists ? '' :
			_('配置文件尚不存在。这里展示示例；请填写自己的身份、可信根和 bootstrap，再校验保存。'), false);
		this.updateButtons();
	},

	reloadConfig: function() {
		var self = this;
		if (this.configBusy || this.serviceBusy)
			return Promise.resolve();
		if (this.configKnown && this.editor.value !== this.savedContent &&
			!window.confirm(_('重新读取会丢弃当前未保存的修改，是否继续？')))
			return Promise.resolve();
		this.configBusy = true;
		this.updateButtons();
		return callGetConfig().then(checked).then(function(reply) {
			self.installConfig(reply);
		}).catch(function(error) {
			self.notice(self.configMessage, errorText(error), true);
		}).finally(function() {
			self.configBusy = false;
			self.updateButtons();
		});
	},

	editConfig: function(save) {
		var self = this;
		if (this.readonly || this.configBusy || this.serviceBusy || !this.configKnown)
			return Promise.resolve();
		var content = this.editor.value;
		var sha = this.configSHA;
		this.configBusy = true;
		this.updateButtons();
		this.notice(this.configMessage, save ? _('正在校验并保存…') : _('正在校验…'), false);
		return (save ? callSaveConfig(content, sha) : callValidateConfig(content)).then(checked).then(function(reply) {
			if (save) {
				if (typeof reply.sha256 !== 'string' || !reply.sha256)
					throw new Error(_('保存结果缺少版本信息，请保留编辑内容并重新读取确认。'));
				self.configSHA = reply.sha256;
				self.savedContent = content;
			}
			self.notice(self.configMessage, save ?
				_('配置已保存，运行中的服务尚未应用。请在确认后点击“重启”。') :
				_('配置校验通过。校验不代表依赖就绪、网络权限已授权或实际流量通畅。'), false);
		}).catch(function(error) {
			self.notice(self.configMessage, errorText(error) + _(' 编辑内容已保留；如配置已被其他会话修改，请先复制自己的编辑，再重新读取合并。'), true);
		}).finally(function() {
			self.configBusy = false;
			self.updateButtons();
		});
	},

	serviceAction: function(action) {
		var self = this;
		if (this.readonly || this.serviceBusy || this.configBusy)
			return Promise.resolve();
		this.serviceBusy = true;
		this.updateButtons();
		return callService(action).then(checked).then(function() {
			self.notice(self.serviceMessage, _('操作请求已接受。服务状态将刷新，进程启动和网络就绪需要时间。'), false);
			return self.refreshStatus();
		}).catch(function(error) {
			self.notice(self.serviceMessage, errorText(error), true);
		}).finally(function() {
			self.serviceBusy = false;
			self.updateButtons();
		});
	},

	loadDiagnostics: function() {
		var self = this;
		this.diagnosticsButton.disabled = true;
		return callDiagnostics().then(checked).then(function(reply) {
			var checks = Array.isArray(reply.checks) ? reply.checks : [];
			replace(self.diagnosticsNode, [
				rowsTable(checks.map(function(check) {
					return [check.name, (check.available ? _('可用') : _('缺失或不可用')) + (check.detail ? ' — ' + check.detail : '')];
				})),
				E('h4', {}, _('只读设备检查')),
				E('pre', { 'style': 'white-space: pre-wrap; overflow-wrap: anywhere' }, reply.preflight || _('无输出')),
				E('h4', {}, _('近期 Photon 日志')),
				E('pre', { 'style': 'white-space: pre-wrap; overflow-wrap: anywhere' }, reply.log || _('无输出'))
			].concat(reply.error ? [E('p', { 'class': 'alert-message warning' }, reply.error)] : []));
		}).catch(function(error) {
			replace(self.diagnosticsNode, [E('p', { 'class': 'alert-message error' }, errorText(error))]);
		}).finally(function() { self.diagnosticsButton.disabled = false; });
	},

	render: function(data) {
		var self = this;
		this.readonly = !L.hasViewPermission();
		this.configKnown = false;
		this.configBusy = false;
		this.serviceBusy = false;
		this.statusGeneration = 0;
		this.savedContent = '';
		this.configSHA = '';
		this.statusNode = E('div');
		this.detailsNode = E('div');
		this.serviceMessage = E('p', { 'style': 'display: none', 'role': 'status' });
		this.configMessage = E('p', { 'style': 'display: none', 'role': 'status' });
		this.configPath = E('code');
		this.dirtyLabel = E('span', { 'role': 'status' });
		this.editor = E('textarea', {
			'rows': 25,
			'wrap': 'off',
			'spellcheck': 'false',
			'aria-label': _('Photon YAML 配置'),
			'style': 'width: 100%; font-family: monospace; box-sizing: border-box',
			'input': function() { self.updateButtons(); }
		});
		this.serviceButtons = [
			['start', _('启动')], ['stop', _('停止')], ['restart', _('重启')],
			['enable', _('启用服务及开机启动')], ['disable', _('禁用服务及开机启动（不停止当前进程）')]
		].map(function(item) {
			return E('button', { 'class': 'btn cbi-button', 'type': 'button',
				'click': function() { return self.serviceAction(item[0]); } }, item[1]);
		});
		this.configButtons = [
			E('button', { 'class': 'btn cbi-button', 'type': 'button',
				'click': function() { return self.editConfig(false); } }, _('校验')),
			E('button', { 'class': 'btn cbi-button cbi-button-save', 'type': 'button',
				'click': function() { return self.editConfig(true); } }, _('校验并保存'))
		];
		this.reloadButton = E('button', { 'class': 'btn cbi-button', 'type': 'button',
			'click': function() { return self.reloadConfig(); } }, _('重新读取配置'));
		this.diagnosticsNode = E('div', {}, _('点击“运行只读诊断”获取依赖、设备检查和日志。'));
		this.diagnosticsButton = E('button', { 'class': 'btn cbi-button', 'type': 'button',
			'click': function() { return self.loadDiagnostics(); } }, _('运行只读诊断'));
		this.showSnapshot(data[0]);
		try {
			this.installConfig(checked(data[1]));
		} catch (error) {
			this.notice(this.configMessage, errorText(error), true);
		}
		this.updateButtons();
		poll.add(function() { return self.refreshStatus(); }, 10);
		return E('div', { 'class': 'cbi-map' }, [
			E('h2', {}, 'Photon'),
			E('p', {}, _('通过系统 procd 管理 Photon，复用现有 charon/VICI 和 Photon 管理的 BIRD。')),
			E('section', { 'class': 'cbi-section' }, [
				E('h3', {}, _('概览与服务')),
				E('p', {}, _('进程运行、控制接口可响应和链路运行分别展示；这些状态均不等于 LAN 或端到端流量已通。VICI、IKE/CHILD、Babel 邻居和路由仍需进一步诊断与实机验收。')),
				this.statusNode,
				E('div', { 'class': 'cbi-page-actions' }, this.serviceButtons.concat([
					E('button', { 'class': 'btn cbi-button', 'type': 'button',
						'click': function() { return self.refreshStatus(); } }, _('刷新状态'))
				])), this.serviceMessage
			]),
			E('section', { 'class': 'cbi-section' }, [
				E('h3', {}, _('节点与链路')),
				this.detailsNode
			]),
			E('section', { 'class': 'cbi-section' }, [
				E('h3', {}, _('配置')),
				E('p', {}, [_('配置文件：'), this.configPath]),
				E('p', {}, _('YAML 管理本机 Photon 配置；服务开关由 UCI 管理。保存会校验并检测并发修改，不会自动重启服务。')),
				this.configMessage, this.editor, this.dirtyLabel,
				E('div', { 'class': 'cbi-page-actions' }, this.configButtons.concat([this.reloadButton]))
			]),
			E('section', { 'class': 'cbi-section' }, [
				E('h3', {}, _('诊断')),
				E('p', {}, _('以下检查只读取设备状态，不会加载内核模块、创建接口、修改路由或防火墙。检查通过不代表真实流量验收通过。')),
				this.diagnosticsButton, this.diagnosticsNode
			])
		]);
	}
});
