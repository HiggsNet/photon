import 'dart:convert';
import 'dart:io';

import 'package:fl_clash/common/common.dart';
import 'package:fl_clash/l10n/l10n.dart';
import 'package:fl_clash/pages/editor.dart';
import 'package:fl_clash/providers/app.dart';
import 'package:fl_clash/ui/icons/icons.dart';
import 'package:fl_clash/widgets/widgets.dart';
import 'package:flutter/services.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'controller.dart';
import 'proxy_bridge.dart';
import 'services.dart';
import 'setup_view.dart';
import 'template_help.dart';

enum _Page { overview, tunnels, peers, routes, services, diagnostics }

class PhotonView extends ConsumerStatefulWidget {
  const PhotonView({super.key, this.controller, this.isWindows});

  final PhotonController? controller;
  final bool? isWindows;

  @override
  ConsumerState<PhotonView> createState() => _PhotonViewState();
}

class _PhotonViewState extends ConsumerState<PhotonView> {
  _Page _page = _Page.overview;
  String _filter = '';
  bool _advanced = false;
  String? _templateConfig;
  Future<bool>? _hasTemplate;

  PhotonController get owner => widget.controller ?? photonController;

  @override
  void initState() {
    super.initState();
    if (widget.controller == null) photonProxyBridge.attach();
    owner.initialize();
  }

  @override
  Widget build(BuildContext context) {
    final safeMode = ref.watch(safeModeProvider);
    final allowed = (widget.isWindows ?? Platform.isWindows) && !safeMode;
    final l = context.appLocalizations;
    return ListenableBuilder(
      listenable: owner,
      builder: (context, _) {
        final config = owner.configPath;
        final canEdit =
            allowed && !owner.busy && !owner.closed && !owner.hasLease;
        void openSettings() {
          owner.pickConfig(() => editPhotonSettings(context, config: config));
        }

        final status = owner.observation;
        final connected = status?['tunnel_ready'] == true;
        final connections = _list(status?['connections']);
        final live = connections
            .where((item) => item['tunnel_ready'] == true)
            .length;
        final label = safeMode
            ? l.safeMode
            : owner.busy
            ? l.loading
            : connected
            ? l.photonTunnelReady
            : owner.hasLease
            ? l.photonTunnelNotReady
            : l.disconnected;
        final items = _items(l, status);
        return Scaffold(
          title: 'Photon',
          body: Builder(
            builder: (context) => CustomScrollView(
              key: PageStorageKey('photon-${_page.name}'),
              slivers: [
                SliverPadding(
                  padding: EdgeInsets.fromLTRB(
                    20,
                    context.sectionsTopPadding,
                    20,
                    0,
                  ),
                  sliver: SliverToBoxAdapter(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      spacing: 16,
                      children: [
                        Card(
                          child: Padding(
                            padding: const EdgeInsets.all(20),
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              spacing: 12,
                              children: [
                                Row(
                                  spacing: 12,
                                  children: [
                                    const GlyphIcon(AppGlyphs.vpn, size: 32),
                                    Expanded(
                                      child: Text(
                                        label,
                                        key: const ValueKey('photon-status'),
                                        style: AppTextStyle.title2.of(
                                          context,
                                          emphasized: true,
                                        ),
                                      ),
                                    ),
                                    FilledButton(
                                      onPressed: owner.busy || owner.closed
                                          ? null
                                          : owner.hasLease
                                          ? owner.stop
                                          : !allowed
                                          ? null
                                          : config == null
                                          ? openSettings
                                          : () => owner.start(allowed: allowed),
                                      child: Text(
                                        owner.hasLease
                                            ? l.stop
                                            : config == null
                                            ? l.photonSettings
                                            : l.start,
                                      ),
                                    ),
                                  ],
                                ),
                                if (config != null && _page == _Page.overview)
                                  Text(
                                    config,
                                    style: AppTextStyle.caption1.of(context),
                                  ),
                                if (config == null && !owner.hasLease)
                                  Text(l.photonSetupHint),
                                if (owner.hasLease && _page == _Page.overview)
                                  Text(
                                    l.photonStopToEdit,
                                    style: AppTextStyle.caption1.of(context),
                                  ),
                                Wrap(
                                  spacing: 12,
                                  runSpacing: 8,
                                  children: [
                                    if (config != null)
                                      TextButton(
                                        onPressed: canEdit
                                            ? openSettings
                                            : null,
                                        child: Text(l.photonSettings),
                                      ),
                                    if (!owner.hasLease) ...[
                                      TextButton(
                                        onPressed: canEdit
                                            ? () => owner.pickConfig(
                                                choosePhotonConfig,
                                              )
                                            : null,
                                        child: Text(l.photonUseConfigFile),
                                      ),
                                      if (config != null) ...[
                                        TextButton(
                                          onPressed: canEdit
                                              ? () => owner.pickConfig(
                                                  () => editPhotonSettings(
                                                    context,
                                                    chooseLocation: true,
                                                  ),
                                                )
                                              : null,
                                          child: Text(l.photonCreateConfig),
                                        ),
                                        TextButton(
                                          onPressed: canEdit
                                              ? () => owner.pickConfig(
                                                  () => showPhotonImport(
                                                    context,
                                                    config,
                                                  ),
                                                )
                                              : null,
                                          child: Text(l.photonImportIdentity),
                                        ),
                                      ],
                                    ],
                                    if (owner.hasLease)
                                      TextButton(
                                        onPressed: owner.busy
                                            ? null
                                            : () => owner.restart(
                                                allowed: allowed,
                                              ),
                                        child: Text(l.photonRestart),
                                      ),
                                    if (status != null)
                                      Text(
                                        '${l.photonTunnelReady}  $live / ${connections.length}',
                                      ),
                                  ],
                                ),
                              ],
                            ),
                          ),
                        ),
                        if (owner.error != null)
                          _DetailCard(
                            title: l.error,
                            lines: [(l.errorDetails, owner.error.toString())],
                          ),
                        SegmentedControl<_Page>(
                          segments: [
                            (_Page.overview, l.overview),
                            (_Page.tunnels, l.photonTunnel),
                            (_Page.peers, l.photonGossipPeers),
                            (_Page.routes, l.photonRoutes),
                            (_Page.services, l.photonServices),
                            (_Page.diagnostics, l.photonDiagnostics),
                          ],
                          value: _page,
                          onChanged: (page) => setState(() {
                            _page = page;
                            _filter = '';
                          }),
                        ),
                        if (_page == _Page.tunnels ||
                            _page == _Page.peers ||
                            _page == _Page.routes ||
                            _page == _Page.services)
                          TextField(
                            key: ValueKey(_page),
                            decoration: InputDecoration(
                              hintText: l.photonSearch,
                            ),
                            autocorrect: false,
                            onChanged: (value) =>
                                setState(() => _filter = value.toLowerCase()),
                          ),
                        if (_page == _Page.services && status != null)
                          _proxyControls(l, status, config, allowed),
                        if (status == null && config != null)
                          _DetailCard(
                            title: l.disconnected,
                            lines: [(l.photonName, l.photonOffline)],
                          ),
                      ],
                    ),
                  ),
                ),
                SliverPadding(
                  padding: const EdgeInsets.fromLTRB(20, 16, 20, 0),
                  sliver: switch (_page) {
                    _Page.tunnels when status != null => _tunnelTable(
                      l,
                      status,
                      connections,
                    ),
                    _Page.peers when status != null => _gossipTable(l, status),
                    _Page.routes when status != null => _routeTable(l, status),
                    _Page.services when status != null => _proxyTable(l),
                    _ => SliverPrismList(
                      itemCount: items.length,
                      itemBuilder: (context, index) => Padding(
                        padding: const EdgeInsets.only(bottom: 12),
                        child: items[index](),
                      ),
                    ),
                  },
                ),
                SliverToBoxAdapter(
                  child: SizedBox(height: 20 + context.bottomInset),
                ),
              ],
            ),
          ),
        );
      },
    );
  }

  List<Widget Function()> _items(
    AppLocalizations l,
    Map<String, dynamic>? status,
  ) {
    if (status == null) return [];
    final admission = _map(status['admission']);
    final wintun = _map(status['wintun']);
    switch (_page) {
      case _Page.overview:
        return [
          () => _DetailCard(
            title: l.photonIdentity,
            lines: [
              (l.photonIdentity, _text(admission['managed_zone'])),
              (
                l.status,
                switch (admission['pending']) {
                  true => l.photonWaiting,
                  false => l.authorized,
                  _ => l.unknown,
                },
              ),
              if (_text(admission['reason_detail']).isNotEmpty)
                (l.errorDetails, _text(admission['reason_detail'])),
            ],
          ),
          () => _DetailCard(
            title: l.ipAddress,
            lines: [
              (l.ipAddress, _strings(wintun['addresses'])),
              (l.photonRoutes, _strings(wintun['split_routes'])),
              (l.address, _text(status['udp_address'])),
            ],
          ),
          if (admission['pending'] == true &&
              _text(admission['join_request_b64']).isNotEmpty)
            () => _DetailCard(
              title: l.photonWaiting,
              lines: [(l.photonIdentity, _text(admission['managed_zone']))],
              footer: TextButton(
                onPressed: () => Clipboard.setData(
                  ClipboardData(text: _text(admission['join_request_b64'])),
                ),
                child: Text(l.copy),
              ),
            ),
        ];
      case _Page.tunnels:
      case _Page.peers:
      case _Page.services:
      case _Page.routes:
        return [];
      case _Page.diagnostics:
        final readiness = _map(status['readiness']);
        return [
          () => _DetailCard(
            title: l.photonDiagnostics,
            lines: [
              (
                l.status,
                status['tunnel_ready'] == true
                    ? l.connected
                    : _text(readiness['stage']),
              ),
              (l.errorDetails, _text(readiness['reason'])),
              (l.photonRevision, _text(status['revision'])),
              (l.lastUpdated, _date(status['observed_at'])),
            ],
            footer: Wrap(
              spacing: 12,
              children: [
                TextButton(
                  onPressed: () => Clipboard.setData(
                    ClipboardData(
                      text: const JsonEncoder.withIndent('  ').convert(status),
                    ),
                  ),
                  child: Text(l.photonSaveDiagnostics),
                ),
                TextButton(
                  onPressed: () => setState(() => _advanced = !_advanced),
                  child: Text(l.photonAdvanced),
                ),
              ],
            ),
          ),
          if (_advanced)
            () => _DetailCard(
              title: l.photonAdvanced,
              lines: [],
              footer: SelectableText(
                const JsonEncoder.withIndent('  ').convert(status),
                style: AppTextStyle.caption1.of(context),
              ),
            ),
        ];
    }
  }

  Widget _tunnelTable(
    AppLocalizations l,
    Map<String, dynamic> status,
    List<Map<String, dynamic>> connections,
  ) {
    final gateways = <String, List<Map<String, dynamic>>>{};
    for (final entry in connections) {
      (gateways[_text(entry['peer'])] ??= []).add(entry);
    }
    final visible = gateways.keys.where((peer) {
      return gateways[peer]!.any((entry) {
        final ike = _map(entry['ike']);
        return _matches([
          peer,
          _outerFamily(entry),
          _text(ike['attempt_remote_endpoint']),
          _ikeState(l, ike),
        ]);
      });
    }).toList()..sort(_compareGatewayNames);
    return _PhotonTable(
      columns: [
        TableColumn('gateway', l.photonGateway, flex: 2.6),
        TableColumn('ready', l.status, flex: 1.15),
        const TableColumn('ike', 'IKE', flex: 1.4),
        const TableColumn('esp', 'ESP', flex: 0.7),
        const TableColumn('babel', 'Babel', flex: 0.8),
        const TableColumn('ipv4', 'IPv4', flex: 0.75),
        const TableColumn('ipv6', 'IPv6', flex: 0.75),
        TableColumn('outer', '${l.photonOuter} 4/6', flex: 1.1),
      ],
      wideColumn: TableColumn('remote', l.remote, flex: 1.9),
      detailsTitle: l.photonTunnel,
      truncated: status['connections_truncated'] == true,
      length: visible.length,
      rowAt: (context, index) {
        final peer = visible[index];
        final entries = gateways[peer]!;
        final ready = entries.any((entry) => entry['tunnel_ready'] == true);
        final ikes = entries.map((entry) => _map(entry['ike']));
        final ikeState = ikes.any((ike) => ike['live'] == true)
            ? l.connected
            : ikes.map((ike) => _ikeState(l, ike)).toSet().join(' / ');
        final esp = _combinedState(ikes.map((ike) => ike['child_live']));
        final babel = _combinedState(
          entries.map((entry) => entry['babel_live']),
        );
        final ipv4 = _combinedState(
          entries.map((entry) => _routeReady(entry, 'ipv4_route_ready')),
        );
        final ipv6 = _combinedState(
          entries.map((entry) => _routeReady(entry, 'ipv6_route_ready')),
        );
        final remote = entries
            .map(
              (entry) => _text(_map(entry['ike'])['attempt_remote_endpoint']),
            )
            .where((value) => value.isNotEmpty)
            .join(' / ');
        final colors = context.colorScheme;
        return _PhotonTableRow(
          title: peer,
          id: peer,
          cells: [
            Text(peer),
            Text(
              ready ? l.photonReady : l.photonNotReady,
              style: TextStyle(
                color: ready ? colors.primary : colors.onSurfaceVariant,
              ),
            ),
            Text(ikeState),
            _statusMark(_linkState(l, esp), esp),
            _statusMark(_linkState(l, babel), babel),
            _statusMark(_routeState(l, ipv4), ipv4),
            _statusMark(_routeState(l, ipv6), ipv6),
            Row(
              spacing: 6,
              children: [
                for (final family in ['IPv4', 'IPv6'])
                  () {
                    final tunnels = entries.where(
                      (entry) => _outerFamily(entry) == family,
                    );
                    final Object? live =
                        tunnels.isEmpty &&
                            status['connections_truncated'] == true
                        ? null
                        : tunnels.any((entry) => entry['tunnel_ready'] == true);
                    final label = live == null
                        ? l.unknown
                        : live == true
                        ? l.photonTunnelReady
                        : l.photonTunnelNotReady;
                    return _statusMark('$family · $label', live);
                  }(),
              ],
            ),
            Text(remote.isEmpty ? '—' : remote),
          ],
          details: [
            for (final entry in entries)
              for (final (label, value) in _tunnelDetails(l, entry))
                ('${_outerFamily(entry)} · $label', value),
          ],
        );
      },
    );
  }

  Widget _gossipTable(AppLocalizations l, Map<String, dynamic> status) {
    final peers =
        _list(status['peers'])
            .where(
              (entry) =>
                  entry['authorization'] != 'revoked' &&
                  entry['sync_status'] != 'revoked' &&
                  _matches([
                    _text(entry['peer_id']),
                    _text(entry['sync_status']),
                  ]),
            )
            .toList()
          ..sort(
            (a, b) =>
                _compareGatewayNames(_text(a['peer_id']), _text(b['peer_id'])),
          );
    return _PhotonTable(
      columns: [
        TableColumn('peer', l.photonNode, flex: 3),
        TableColumn('state', l.status, flex: 2),
      ],
      wideColumn: TableColumn('last_sync', l.photonLastSync, flex: 2),
      detailsTitle: l.photonGossipPeers,
      length: peers.length,
      truncated: status['peers_truncated'] == true,
      rowAt: (context, index) {
        final entry = peers[index];
        final peer = _text(entry['peer_id']);
        final state = _text(entry['sync_status']);
        final lastSync = _unix(entry['last_sync_unix']);
        final failure = _map(entry['last_failure']);
        return _PhotonTableRow(
          title: peer,
          cells: [Text(peer), Text(state), Text(lastSync)],
          details: [
            (l.status, state),
            (l.photonIdentity, _text(entry['authorization'])),
            (l.address, _text(entry['selected_addr'])),
            (l.photonLastSync, lastSync),
            (l.photonLastFailure, _text(failure['message'] ?? failure['code'])),
          ],
        );
      },
    );
  }

  Widget _proxyControls(
    AppLocalizations l,
    Map<String, dynamic> status,
    String? config,
    bool allowed,
  ) {
    final directory = owner.directory;
    final hasEndpoints = directory?.endpoints.isNotEmpty == true;
    final ready = status['tunnel_ready'] == true;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      spacing: 8,
      children: [
        FilledButton(
          onPressed:
              widget.controller != null ||
                  owner.busy ||
                  !owner.directoryFresh ||
                  !hasEndpoints ||
                  !ready
              ? null
              : () => owner.applyProxies(photonProxyBridge.apply),
          child: Text(l.photonApply),
        ),
        Text(l.photonMultiTip),
        if (config != null && allowed) _templateControls(l, config),
        if (!ready) Text(l.photonProxyRequiresTunnel),
        if (ready && !owner.directoryFresh) Text(l.photonStale),
      ],
    );
  }

  Widget _templateControls(AppLocalizations l, String config) {
    final file = photonProxyTemplateFile(config);
    if (_templateConfig != config) {
      _templateConfig = config;
      _hasTemplate = file.exists();
    }
    return FutureBuilder<bool>(
      key: ValueKey(config),
      future: _hasTemplate,
      builder: (context, snapshot) {
        final hasTemplate = snapshot.data == true;
        final editable =
            !owner.busy &&
            !owner.closed &&
            snapshot.connectionState == ConnectionState.done;
        return Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          spacing: 4,
          children: [
            Text(
              l.photonProxyTemplate,
              style: AppTextStyle.headline.of(context),
            ),
            Text(
              hasTemplate ? file.uri.pathSegments.last : l.photonBuiltinRules,
            ),
            Text(l.photonTemplateHint),
            Wrap(
              spacing: 8,
              children: [
                TextButton(
                  onPressed: () => showPhotonTemplateHelp(context),
                  child: Text(l.photonTemplateHelp),
                ),
                TextButton(
                  onPressed: editable ? () => _importTemplate(config) : null,
                  child: Text(l.photonImportTemplate),
                ),
                TextButton(
                  onPressed: editable
                      ? () => _editTemplate(config, file)
                      : null,
                  child: Text(l.photonEditTemplate),
                ),
                if (hasTemplate)
                  TextButton(
                    onPressed: editable ? () => _resetTemplate(config) : null,
                    child: Text(l.photonBuiltinRules),
                  ),
              ],
            ),
          ],
        );
      },
    );
  }

  Future<void> _resetTemplate(String config) async {
    final l = context.appLocalizations;
    final confirmed = await dialogs.showMessage(
      title: l.photonBuiltinRules,
      message: TextSpan(text: l.photonRemoveTemplate),
      destructive: true,
    );
    if (confirmed == true && mounted) await _changeTemplate(config, null);
  }

  Future<void> _importTemplate(String config) async {
    try {
      final input = await choosePhotonConfig();
      if (input == null || !mounted) return;
      final source = await readPhotonProxyTemplate(File(input));
      if (!mounted) return;
      await _changeTemplate(config, source);
    } catch (error) {
      if (mounted) await dialogs.showAlert(message: TextSpan(text: '$error'));
    }
  }

  Future<void> _editTemplate(String config, File file) async {
    try {
      final source = await file.exists()
          ? await readPhotonProxyTemplate(file)
          : 'rules:\n  - MATCH,Photon\n';
      if (!mounted) return;
      final l = context.appLocalizations;
      await BaseNavigator.push<void>(
        context,
        EditorPage(
          title: l.photonEditTemplate,
          content: source,
          onSave: (context, _, content) async {
            final saved = await _changeTemplate(
              config,
              await content.readText(),
            );
            if (saved && context.mounted) Navigator.of(context).pop();
          },
          onPop: (context, _, content) async {
            final answer = await dialogs.showSaveChanges(
              title: l.photonEditTemplate,
            );
            if (answer == null || !context.mounted) return false;
            return !answer ||
                await _changeTemplate(config, await content.readText());
          },
        ),
      );
    } catch (error) {
      if (mounted) await dialogs.showAlert(message: TextSpan(text: '$error'));
    }
  }

  Future<bool> _changeTemplate(String config, String? source) async {
    if (!mounted || owner.closed || owner.configPath != config) return false;
    final file = photonProxyTemplateFile(config);
    Object? problem;
    var changed = false;
    await owner.applyProxies(() async {
      if (owner.closed || owner.configPath != config) return;
      try {
        if (source == null) {
          if (await file.exists()) await file.delete();
        } else {
          await photonProxyBridge.saveTemplate(config, source);
        }
        changed = true;
      } catch (error) {
        problem = error;
      }
    });
    if (!mounted) return changed;
    if (problem != null) {
      await dialogs.showAlert(message: TextSpan(text: '$problem'));
      return false;
    }
    if (changed) {
      setState(() => _hasTemplate = file.exists());
      await owner.refresh();
    }
    return changed;
  }

  Widget _proxyTable(AppLocalizations l) {
    final endpoints = owner.directoryFresh ? owner.directory?.endpoints : null;
    final byNode = <String, ({Set<String> regions, int count})>{};
    for (final endpoint in endpoints ?? const <PhotonEndpoint>[]) {
      final previous = byNode[endpoint.owner];
      byNode[endpoint.owner] = (
        regions: {...?previous?.regions, endpoint.region},
        count: (previous?.count ?? 0) + 1,
      );
    }
    final nodes =
        byNode.keys
            .where((node) => _matches([node, ...byNode[node]!.regions]))
            .toList()
          ..sort((a, b) => b.compareTo(a));
    return _PhotonTable(
      columns: [
        TableColumn('node', l.photonNode, flex: 3),
        TableColumn('region', l.photonRegion, flex: 2),
        TableColumn('count', l.photonEndpointCount, flex: 1),
      ],
      length: nodes.length,
      rowAt: (context, index) {
        final node = nodes[index];
        final entry = byNode[node]!;
        final regions = entry.regions.toList()..sort();
        return _PhotonTableRow(
          title: node,
          cells: [
            Text(node),
            Text(regions.join(' · ')),
            Text('${entry.count}'),
          ],
        );
      },
    );
  }

  bool _matches(List<String> values) =>
      _filter.isEmpty ||
      values.any((value) => value.toLowerCase().contains(_filter));

  Widget _routeTable(AppLocalizations l, Map<String, dynamic> status) {
    final routes =
        <({String prefix, String source}), List<Map<String, dynamic>>>{};
    for (final route in _list(_map(status['babel'])['routes'])) {
      final key = (
        prefix: _text(route['prefix']),
        source: _text(route['source_prefix']),
      );
      (routes[key] ??= []).add(route);
    }
    final visible =
        routes.entries.where((group) {
          return group.value.any(
            (route) => _matches([
              group.key.prefix,
              group.key.source,
              _text(route['peer']),
              _text(route['next_hop']),
              _text(route['outer_family']),
              _text(route['origin']),
            ]),
          );
        }).toList()..sort((a, b) {
          final prefix = a.key.prefix.compareTo(b.key.prefix);
          return prefix != 0 ? prefix : a.key.source.compareTo(b.key.source);
        });
    return _PhotonTable(
      columns: [
        TableColumn('prefix', l.routeAddress, flex: 2.5),
        TableColumn('next_hop', l.photonNextHop, flex: 3),
        TableColumn('metric', l.photonMetric, flex: 1.2),
        TableColumn('delay', l.delay, flex: 0.8),
        TableColumn('paths', l.photonNextHopCount, flex: 1),
      ],
      wideColumn: TableColumn('source', l.source, flex: 2),
      detailsTitle: l.photonRoutes,
      truncated: status['routes_truncated'] == true,
      length: visible.length,
      rowAt: (context, index) {
        final group = visible[index];
        final paths = group.value..sort(_compareRoutePaths);
        final bestMetric = _routeMetric(paths.first);
        final nextHops = paths
            .where((path) => _routeMetric(path) == bestMetric)
            .map(_routeNextHop)
            .toSet()
            .join(' / ');
        return _PhotonTableRow(
          title: group.key.prefix,
          id: group.key,
          cells: [
            Text(group.key.prefix),
            Tooltip(message: nextHops, child: Text(nextHops)),
            Text(_text(paths.first['metric'])),
            Tooltip(message: l.photonUnprobed, child: const Text('—')),
            Text('${paths.length}'),
            Text(group.key.source.isEmpty ? '—' : group.key.source),
          ],
          details: [
            (l.source, group.key.source),
            for (var i = 0; i < paths.length; i++) ...[
              ('${i + 1} · ${l.photonNextHop}', _routeNextHop(paths[i])),
              ('${i + 1} · ${l.address}', _text(paths[i]['next_hop'])),
              ('${i + 1} · ${l.photonOuter}', _outerFamily(paths[i])),
              ('${i + 1} · ${l.photonMetric}', _text(paths[i]['metric'])),
              ('${i + 1} · ${l.delay}', l.photonUnprobed),
              ('${i + 1} · ${l.photonIdentity}', _text(paths[i]['origin'])),
            ],
          ],
        );
      },
    );
  }
}

class _PhotonTableRow {
  const _PhotonTableRow({
    required this.title,
    required this.cells,
    this.id,
    this.details = const [],
  });

  final String title;
  final Object? id;
  final List<Widget> cells;
  final List<(String, String)> details;
}

class _PhotonTable extends StatelessWidget {
  const _PhotonTable({
    required this.columns,
    required this.length,
    required this.rowAt,
    this.wideColumn,
    this.detailsTitle,
    this.truncated = false,
  });

  final List<TableColumn> columns;
  final int length;
  final _PhotonTableRow Function(BuildContext, int) rowAt;
  final TableColumn? wideColumn;
  final String? detailsTitle;
  final bool truncated;

  @override
  Widget build(BuildContext context) {
    final l = context.appLocalizations;
    return SliverLayoutBuilder(
      builder: (context, constraints) {
        final width = constraints.crossAxisExtent;
        final scale = MediaQuery.textScalerOf(context);
        final showWide = wideColumn != null && width >= scale.scale(780);
        final headers = [
          ...columns,
          if (showWide) wideColumn!,
          if (detailsTitle != null) const TableColumn('details', '', width: 30),
        ];
        final widths = tableColumnWidths(headers, width);
        final colors = context.colorScheme;
        final stripe = SurfaceLevel.block.colorOf(colors);
        Widget cells(List<Widget> content, {bool header = false}) =>
            DefaultTextStyle.merge(
              style: AppTextStyle.caption1.of(context, emphasized: header),
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              child: TableCells(
                columns: headers,
                widths: widths,
                height: scale.scale(header ? 32 : 36),
                inset: 6,
                cells: content,
              ),
            );

        return SliverMainAxisGroup(
          slivers: [
            if (truncated) SliverToBoxAdapter(child: Text(l.photonTruncated)),
            SliverToBoxAdapter(
              child: DecoratedBox(
                decoration: ShapeDecoration(
                  color: stripe,
                  shape: AppShape.top(AppCorner.md),
                ),
                child: cells([
                  for (final column in headers)
                    Semantics(header: true, child: Text(column.label)),
                ], header: true),
              ),
            ),
            if (length == 0)
              SliverToBoxAdapter(
                child: Padding(
                  padding: const EdgeInsets.symmetric(vertical: 16),
                  child: Text(l.photonEmpty, textAlign: TextAlign.center),
                ),
              ),
            SliverPrismList(
              itemCount: length,
              itemBuilder: (context, index) {
                final row = rowAt(context, index);
                final fill = index.isEven
                    ? SurfaceLevel.card.colorOf(colors)
                    : stripe;
                final title = detailsTitle;
                final content = cells([
                  ...row.cells.take(columns.length + (showWide ? 1 : 0)),
                  if (title != null)
                    const GlyphIcon(AppGlyphs.chevronForward, size: 14),
                ]);
                if (title == null) {
                  return ColoredBox(color: fill, child: content);
                }
                return PressSurface(
                  key: ValueKey(row.id ?? row.title),
                  fill: fill,
                  shape: AppShape.none,
                  onPressed: () => showSheet<void>(
                    context: context,
                    builder: (context) => Scaffold(
                      title: row.title,
                      body: SingleChildScrollView(
                        padding: EdgeInsets.fromLTRB(
                          16,
                          context.sectionsTopPadding,
                          16,
                          16,
                        ),
                        child: _DetailCard(title: title, lines: row.details),
                      ),
                    ),
                  ),
                  child: content,
                );
              },
            ),
          ],
        );
      },
    );
  }
}

String _routeNextHop(Map<String, dynamic> route) =>
    _text(route['peer']).isNotEmpty
    ? _text(route['peer'])
    : _text(route['next_hop']).isNotEmpty
    ? _text(route['next_hop'])
    : '—';

int _routeMetric(Map<String, dynamic> route) =>
    int.tryParse(_text(route['metric'])) ?? 65535;

int _compareRoutePaths(Map<String, dynamic> a, Map<String, dynamic> b) {
  final metric = _routeMetric(a).compareTo(_routeMetric(b));
  if (metric != 0) return metric;
  final peer = _compareGatewayNames(_routeNextHop(a), _routeNextHop(b));
  if (peer != 0) return peer;
  final family = _text(a['outer_family']).compareTo(_text(b['outer_family']));
  return family != 0
      ? family
      : _text(a['next_hop']).compareTo(_text(b['next_hop']));
}

int _compareGatewayNames(String a, String b) {
  final aLabels = a.split('.').reversed.toList();
  final bLabels = b.split('.').reversed.toList();
  for (var i = 0; i < aLabels.length && i < bLabels.length; i++) {
    final aParts = aLabels[i].split('-').reversed.toList();
    final bParts = bLabels[i].split('-').reversed.toList();
    for (var j = 0; j < aParts.length && j < bParts.length; j++) {
      final order = bParts[j].compareTo(aParts[j]);
      if (order != 0) return order;
    }
    final order = bParts.length.compareTo(aParts.length);
    if (order != 0) return order;
  }
  return bLabels.length.compareTo(aLabels.length);
}

Object? _combinedState(Iterable<Object?> values) {
  if (values.any((value) => value == true)) return true;
  return values.any((value) => value == null) ? null : false;
}

List<(String, String)> _tunnelDetails(
  AppLocalizations l,
  Map<String, dynamic> entry,
) {
  final ike = _map(entry['ike']);
  return [
    (
      l.status,
      entry['tunnel_ready'] == true
          ? l.photonTunnelReady
          : l.photonTunnelNotReady,
    ),
    (l.remote, _text(ike['attempt_remote_endpoint'])),
    ('IKE', _ikeState(l, ike)),
    ('ESP', _linkState(l, ike['child_live'])),
    ('Babel', _linkState(l, entry['babel_live'])),
    ('IPv4', _routeState(l, _routeReady(entry, 'ipv4_route_ready'))),
    ('IPv6', _routeState(l, _routeReady(entry, 'ipv6_route_ready'))),
    if (ike['live'] == true && ike['mobike'] != null)
      ('MOBIKE', ike['mobike'] == true ? l.enabled : l.disabled),
    (l.expireTime, _date(ike['child_expires_at'])),
    (l.photonLastFailure, _tunnelFailure(l, ike['last_failure'])),
    (l.time, _date(_map(ike['last_failure'])['at'])),
  ];
}

String _outerFamily(Map<String, dynamic> entry) {
  switch (entry['outer_family']) {
    case 'ipv4':
      return 'IPv4';
    case 'ipv6':
      return 'IPv6';
  }
  final endpoint = _text(_map(entry['ike'])['attempt_remote_endpoint']);
  if (endpoint.isEmpty) return '';
  return endpoint.startsWith('[') ? 'IPv6' : 'IPv4';
}

String _ikeState(AppLocalizations l, Map<String, dynamic> ike) =>
    ike['live'] == true
    ? l.connected
    : switch (ike['phase']) {
        'init' => l.photonIkeInit,
        'auth' => l.authentication,
        'idle' || 'established' => l.disconnected,
        _ => l.unknown,
      };

String _linkState(AppLocalizations l, Object? value) => switch (value) {
  true => l.connected,
  false => l.disconnected,
  _ => l.unknown,
};

Object? _routeReady(Map<String, dynamic> entry, String field) {
  final value = entry[field];
  return value == false && entry['routes_truncated'] == true ? null : value;
}

String _routeState(AppLocalizations l, Object? value) => switch (value) {
  true => l.photonRouteReady,
  false => l.photonNoRoute,
  _ => l.unknown,
};

Widget _statusMark(String label, Object? value) => Tooltip(
  message: label,
  child: value == true
      ? const GlyphIcon(AppGlyphs.check, size: 14)
      : Text(value == false ? '—' : '?'),
);

String _tunnelFailure(AppLocalizations l, Object? value) {
  final failure = _map(value);
  final message = _failure(failure);
  if (failure['event'] != 'network_rebind') {
    return message == 'local network endpoint replaced'
        ? l.photonNetworkRebound
        : message;
  }
  return switch (message) {
    'outer_path_changed' => l.photonPathChanged,
    'system_resumed' => l.photonResumeRebind,
    'manual_rebind' => l.photonManualRebind,
    'socket_failed' => l.photonSocketRebind,
    'mobike_not_negotiated' => l.photonMobikeRebind,
    _ => message,
  };
}

class _DetailCard extends StatelessWidget {
  const _DetailCard({required this.title, required this.lines, this.footer});

  final String title;
  final List<(String, String)> lines;
  final Widget? footer;

  @override
  Widget build(BuildContext context) => Card(
    child: Padding(
      padding: const EdgeInsets.all(20),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        spacing: 12,
        children: [
          Text(
            title,
            style: AppTextStyle.headline.of(context, emphasized: true),
          ),
          for (final (label, value) in lines)
            if (value.isNotEmpty)
              Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                spacing: 16,
                children: [
                  SizedBox(
                    width: 132,
                    child: Text(
                      label,
                      style: AppTextStyle.subheadline.of(context),
                    ),
                  ),
                  Expanded(
                    child: SelectableText(
                      value,
                      style: AppTextStyle.body.of(context),
                    ),
                  ),
                ],
              ),
          ?footer,
        ],
      ),
    ),
  );
}

Map<String, dynamic> _map(dynamic value) =>
    value is Map ? Map<String, dynamic>.from(value) : {};
List<Map<String, dynamic>> _list(dynamic value) => value is List
    ? value
          .whereType<Map>()
          .map((item) => Map<String, dynamic>.from(item))
          .toList()
    : [];
String _text(dynamic value) => value == null ? '' : '$value';
String _strings(dynamic value) => value is List ? value.join('\n') : '';
String _date(dynamic value) {
  final date = DateTime.tryParse(_text(value));
  return date == null || date.year < 2000
      ? ''
      : date.toLocal().toString().split('.').first;
}

String _unix(dynamic value) => value is int && value > 0
    ? DateTime.fromMillisecondsSinceEpoch(
        value * 1000,
        isUtc: true,
      ).toIso8601String().replaceFirst('.000Z', 'Z')
    : 'never';
String _failure(dynamic value) {
  final data = _map(value);
  return _text(data['message'] ?? data['detail'] ?? data['code']);
}
