import 'dart:convert';
import 'dart:io';

import 'package:fl_clash/common/common.dart';
import 'package:fl_clash/l10n/l10n.dart';
import 'package:fl_clash/providers/app.dart';
import 'package:fl_clash/ui/icons/icons.dart';
import 'package:fl_clash/widgets/widgets.dart';
import 'package:flutter/services.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'controller.dart';
import 'proxy_bridge.dart';
import 'settings_view.dart';
import 'status_table.dart';

enum _Page { overview, tunnels, peers, routes, diagnostics, settings }

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
  final _expandedRoutes = <({String prefix, String source})>{};

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
                          key: const ValueKey('photon-connection-bar'),
                          child: Padding(
                            padding: const EdgeInsets.symmetric(
                              horizontal: 20,
                              vertical: 12,
                            ),
                            child: Row(
                              spacing: 12,
                              children: [
                                Tooltip(
                                  key: const ValueKey('photon-status'),
                                  message: label,
                                  child: GlyphIcon(
                                    AppGlyphs.vpn,
                                    size: 24,
                                    color: connected
                                        ? context.colorScheme.primary
                                        : context.colorScheme.onSurfaceVariant,
                                  ),
                                ),
                                Expanded(
                                  child: Text(
                                    '${l.photonTunnel}  $live / ${connections.length}',
                                    key: const ValueKey('photon-tunnel-count'),
                                    style: AppTextStyle.callout.of(
                                      context,
                                      emphasized: true,
                                    ),
                                  ),
                                ),
                                TextButton(
                                  onPressed:
                                      !allowed ||
                                          owner.busy ||
                                          owner.closed ||
                                          owner.hasLease ||
                                          config == null
                                      ? null
                                      : () => owner.start(allowed: allowed),
                                  child: Text(l.photonConnect),
                                ),
                                FilledButton(
                                  onPressed:
                                      owner.busy ||
                                          owner.closed ||
                                          !owner.hasLease
                                      ? null
                                      : owner.stop,
                                  child: Text(l.photonDisconnect),
                                ),
                              ],
                            ),
                          ),
                        ),
                        if (owner.error != null)
                          PhotonDetailCard(
                            title: l.error,
                            lines: [(l.errorDetails, owner.error.toString())],
                          ),
                        SegmentedControl<_Page>(
                          segments: [
                            (_Page.overview, l.overview),
                            (_Page.tunnels, l.photonTunnel),
                            (_Page.peers, l.photonGossipPeers),
                            (_Page.routes, l.photonRoutes),
                            (_Page.diagnostics, l.photonDiagnostics),
                            (_Page.settings, l.settings),
                          ],
                          value: _page,
                          onChanged: (page) => setState(() {
                            _page = page;
                            _filter = '';
                          }),
                        ),
                        if (_page == _Page.tunnels ||
                            _page == _Page.peers ||
                            _page == _Page.routes)
                          TextField(
                            key: ValueKey(_page),
                            decoration: InputDecoration(
                              hintText: l.photonSearch,
                            ),
                            autocorrect: false,
                            onChanged: (value) =>
                                setState(() => _filter = value.toLowerCase()),
                          ),
                        if (_page == _Page.overview && config == null)
                          Card(
                            onPressed: () =>
                                setState(() => _page = _Page.settings),
                            child: ListRow(
                              title: Text(l.photonSettings),
                              subtitle: Text(l.photonSetupHint),
                              trailing: const GlyphIcon(
                                AppGlyphs.chevronForward,
                              ),
                            ),
                          ),
                        if (_page == _Page.overview &&
                            status == null &&
                            config != null)
                          PhotonDetailCard(
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
                    _Page.settings => SliverToBoxAdapter(
                      child: PhotonSettings(owner: owner, allowed: allowed),
                    ),
                    _Page.tunnels when status != null => _tunnelTable(
                      l,
                      status,
                      connections,
                    ),
                    _Page.peers when status != null => _gossipTable(l, status),
                    _Page.routes when status != null => _routeTable(l, status),
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
          () => PhotonDetailCard(
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
          () => PhotonDetailCard(
            title: l.ipAddress,
            lines: [
              (l.ipAddress, _strings(wintun['addresses'])),
              (l.photonRoutes, _strings(wintun['split_routes'])),
              (l.address, _text(status['udp_address'])),
            ],
          ),
          if (admission['pending'] == true &&
              _text(admission['join_request_b64']).isNotEmpty)
            () => PhotonDetailCard(
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
      case _Page.settings:
      case _Page.tunnels:
      case _Page.peers:
      case _Page.routes:
        return [];
      case _Page.diagnostics:
        final readiness = _map(status['readiness']);
        return [
          () => PhotonDetailCard(
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
            () => PhotonDetailCard(
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
    }).toList()..sort(comparePhotonNodeNames);
    return PhotonTable(
      columns: [
        TableColumn('gateway', l.photonGateway, flex: 2.6, end: true),
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
        return PhotonTableRow(
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
            photonStatusMark(_linkState(l, esp), esp),
            photonStatusMark(_linkState(l, babel), babel),
            photonStatusMark(
              '${l.photonInnerIPv4Route} · ${_routeState(l, ipv4)}',
              ipv4,
            ),
            photonStatusMark(
              '${l.photonInnerIPv6Route} · ${_routeState(l, ipv6)}',
              ipv6,
            ),
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
                    return photonStatusMark('$family · $label', live);
                  }(),
              ],
            ),
            Text(remote.isEmpty ? '—' : remote),
          ],
          detailSections: [
            for (final entry in entries)
              (
                title: '${l.photonOuterTunnel} · ${_outerFamily(entry)}',
                lines: _tunnelDetails(l, entry),
              ),
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
            (a, b) => comparePhotonNodeNames(
              _text(a['peer_id']),
              _text(b['peer_id']),
            ),
          );
    return PhotonTable(
      columns: [
        TableColumn('peer', l.photonNode, flex: 3, end: true),
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
        return PhotonTableRow(
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
    _expandedRoutes.retainAll(routes.keys);
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
    return SliverMainAxisGroup(
      slivers: [
        SliverToBoxAdapter(
          child: Padding(
            padding: const EdgeInsets.only(bottom: 12),
            child: Text(
              l.photonRouteMetricHint,
              style: AppTextStyle.caption1.of(context),
            ),
          ),
        ),
        PhotonTable(
          columns: [
            TableColumn('prefix', l.routeAddress, flex: 2.5),
            TableColumn('next_hop', l.photonNextHop, flex: 3),
            TableColumn('metric', l.photonMetric, flex: 1.2, end: true),
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
            return PhotonTableRow(
              title: group.key.prefix,
              id: group.key,
              onPressed: () => setState(() {
                if (!_expandedRoutes.add(group.key)) {
                  _expandedRoutes.remove(group.key);
                }
              }),
              expanded: _expandedRoutes.contains(group.key)
                  ? _RoutePathsTable(
                      key: ValueKey(('route-paths', group.key)),
                      prefix: group.key.prefix,
                      source: group.key.source,
                      paths: paths,
                    )
                  : null,
              cells: [
                Text(group.key.prefix),
                Tooltip(message: nextHops, child: Text(nextHops)),
                Text(_text(paths.first['metric'])),
                Text('${paths.length}'),
                Text(group.key.source.isEmpty ? '—' : group.key.source),
              ],
            );
          },
        ),
      ],
    );
  }
}

class _RoutePathsTable extends StatelessWidget {
  const _RoutePathsTable({
    super.key,
    required this.prefix,
    required this.source,
    required this.paths,
  });

  final String prefix;
  final String source;
  final List<Map<String, dynamic>> paths;

  @override
  Widget build(BuildContext context) {
    final l = context.appLocalizations;
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 8, 16, 16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        spacing: 8,
        children: [
          Text(
            '${l.routeAddress}: $prefix\n${l.source}: ${source.isEmpty ? '—' : source}',
            style: AppTextStyle.caption1.of(context),
          ),
          LayoutBuilder(
            builder: (context, constraints) {
              final columns = [
                TableColumn('peer', l.photonNode, flex: 3, end: true),
                TableColumn('next_hop', l.photonNextHop, flex: 2.5),
                TableColumn('outer', l.photonOuter, flex: 1),
                TableColumn('metric', l.photonMetric, flex: 1, end: true),
              ];
              final widths = tableColumnWidths(columns, constraints.maxWidth);
              final scale = MediaQuery.textScalerOf(context);
              Widget cells(List<Widget> values, {bool header = false}) =>
                  DefaultTextStyle.merge(
                    style: AppTextStyle.caption1.of(
                      context,
                      emphasized: header,
                    ),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    child: TableCells(
                      columns: columns,
                      widths: widths,
                      height: scale.scale(header ? 32 : 36),
                      inset: 6,
                      cells: values,
                    ),
                  );
              return Column(
                children: [
                  cells([
                    for (final column in columns)
                      Semantics(header: true, child: Text(column.label)),
                  ], header: true),
                  for (final path in paths)
                    cells([
                      Tooltip(
                        message: _routeNextHop(path),
                        child: Text(_routeNextHop(path)),
                      ),
                      Tooltip(
                        message: _text(path['next_hop']),
                        child: Text(_text(path['next_hop'])),
                      ),
                      Text(_outerFamily(path)),
                      Text(_text(path['metric'])),
                    ]),
                ],
              );
            },
          ),
        ],
      ),
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
  final peer = comparePhotonNodeNames(_routeNextHop(a), _routeNextHop(b));
  if (peer != 0) return peer;
  final family = _text(a['outer_family']).compareTo(_text(b['outer_family']));
  return family != 0
      ? family
      : _text(a['next_hop']).compareTo(_text(b['next_hop']));
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
  final failure = _map(ike['last_failure']);
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
    (
      l.photonInnerIPv4Route,
      _routeState(l, _routeReady(entry, 'ipv4_route_ready')),
    ),
    (
      l.photonInnerIPv6Route,
      _routeState(l, _routeReady(entry, 'ipv6_route_ready')),
    ),
    if (ike['live'] == true && ike['mobike'] != null)
      ('MOBIKE', ike['mobike'] == true ? l.enabled : l.disabled),
    (l.expireTime, _date(ike['child_expires_at'])),
    if (!(ike['live'] == true && ike['child_live'] == true) &&
        failure.isNotEmpty) ...[
      (l.photonLastFailure, _tunnelFailure(l, failure)),
      (l.time, _date(failure['at'])),
    ],
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
