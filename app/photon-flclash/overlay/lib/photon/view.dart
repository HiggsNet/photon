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
import 'services.dart';
import 'setup_view.dart';

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
                          _proxyControls(l, status),
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
    final babel = _map(status['babel']);
    final routes = _list(babel['routes']);
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
        return [];
      case _Page.routes:
        return _rows(
          routes,
          l,
          (entry) => _DetailCard(
            title: _text(entry['prefix']),
            lines: [
              (l.peers, _text(entry['peer'])),
              (l.photonMetric, _text(entry['metric'])),
              (l.photonIdentity, _text(entry['origin'])),
              (l.address, _text(entry['source_prefix'])),
            ],
          ),
          truncated: status['routes_truncated'] == true,
        );
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
    final visible = connections.where((entry) {
      final ike = _map(entry['ike']);
      return _matches([
        _text(entry['peer']),
        _text(ike['attempt_remote_endpoint']),
        _ikeState(l, ike),
      ]);
    }).toList()..sort((a, b) => _text(b['peer']).compareTo(_text(a['peer'])));
    return _PhotonTable(
      columns: [
        TableColumn('gateway', l.photonGateway, flex: 2.6),
        TableColumn('ready', l.status, flex: 1.15),
        const TableColumn('ike', 'IKE', flex: 1.4),
        const TableColumn('esp', 'ESP', flex: 0.7),
        const TableColumn('babel', 'Babel', flex: 0.8),
        const TableColumn('ipv4', 'IPv4', flex: 0.75),
        const TableColumn('ipv6', 'IPv6', flex: 0.75),
        TableColumn('outer', l.photonOuter, flex: 0.9),
      ],
      wideColumn: TableColumn('remote', l.remote, flex: 1.9),
      detailsTitle: l.photonTunnel,
      truncated: status['connections_truncated'] == true,
      length: visible.length,
      rowAt: (context, index) {
        final entry = visible[index];
        final peer = _text(entry['peer']);
        final ready = entry['tunnel_ready'] == true;
        final ike = _map(entry['ike']);
        final remote = _text(ike['attempt_remote_endpoint']);
        final outer = remote.isEmpty
            ? ''
            : remote.startsWith('[')
            ? 'IPv6'
            : 'IPv4';
        final ipv4 = _routeReady(entry, 'ipv4_route_ready');
        final ipv6 = _routeReady(entry, 'ipv6_route_ready');
        final colors = context.colorScheme;
        return _PhotonTableRow(
          title: peer,
          cells: [
            Text(peer),
            Text(
              ready ? l.photonReady : l.photonNotReady,
              style: TextStyle(
                color: ready ? colors.primary : colors.onSurfaceVariant,
              ),
            ),
            Text(_ikeState(l, ike)),
            _statusMark(_linkState(l, ike['child_live']), ike['child_live']),
            _statusMark(
              _linkState(l, entry['babel_live']),
              entry['babel_live'],
            ),
            _statusMark(_routeState(l, ipv4), ipv4),
            _statusMark(_routeState(l, ipv6), ipv6),
            Text(outer.isEmpty ? '—' : outer),
            Text(remote.isEmpty ? '—' : remote),
          ],
          details: [
            (l.status, ready ? l.photonTunnelReady : l.photonTunnelNotReady),
            (l.photonOuter, outer),
            (l.remote, remote),
            ('IKE', _ikeState(l, ike)),
            ('ESP', _linkState(l, ike['child_live'])),
            ('Babel', _linkState(l, entry['babel_live'])),
            ('IPv4', _routeState(l, ipv4)),
            ('IPv6', _routeState(l, ipv6)),
            if (ike['live'] == true && ike['mobike'] != null)
              ('MOBIKE', ike['mobike'] == true ? l.enabled : l.disabled),
            (l.expireTime, _date(ike['child_expires_at'])),
            (l.photonLastFailure, _tunnelFailure(l, ike['last_failure'])),
            (l.time, _date(_map(ike['last_failure'])['at'])),
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
                  _matches([_text(entry['peer']), _gossipState(l, entry)]),
            )
            .toList()
          ..sort((a, b) => _text(b['peer']).compareTo(_text(a['peer'])));
    return _PhotonTable(
      columns: [
        TableColumn('peer', l.photonNode, flex: 3),
        TableColumn('state', l.status, flex: 2),
      ],
      detailsTitle: l.photonGossipPeers,
      length: peers.length,
      truncated: status['peers_truncated'] == true,
      rowAt: (context, index) {
        final entry = peers[index];
        final peer = _text(entry['peer']);
        final state = _gossipState(l, entry);
        final failure = _map(entry['session_failure']);
        return _PhotonTableRow(
          title: peer,
          cells: [Text(peer), Text(state)],
          details: [
            (l.status, state),
            (l.photonLastSync, _unix(entry['last_sync_unix'])),
            (
              l.photonLastFailure,
              failure['code'] == 'timeout'
                  ? l.photonGossipTimeout
                  : _text(
                      failure['message'] ??
                          failure['code'] ??
                          entry['last_pull_error'],
                    ),
            ),
          ],
        );
      },
    );
  }

  Widget _proxyControls(AppLocalizations l, Map<String, dynamic> status) {
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
        if (!ready) Text(l.photonProxyRequiresTunnel),
        if (ready && !owner.directoryFresh) Text(l.photonStale),
      ],
    );
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

  List<Widget Function()> _rows(
    List<Map<String, dynamic>> rows,
    AppLocalizations l,
    Widget Function(Map<String, dynamic>) builder, {
    bool truncated = false,
  }) {
    final visible = rows
        .where(
          (row) =>
              _filter.isEmpty ||
              row.values.whereType<String>().any(
                (value) => value.toLowerCase().contains(_filter),
              ),
        )
        .toList();
    return [
      if (truncated) () => _DetailCard(title: l.photonTruncated, lines: []),
      if (visible.isEmpty) () => _DetailCard(title: l.photonEmpty, lines: []),
      for (final row in visible) () => builder(row),
    ];
  }
}

class _PhotonTableRow {
  const _PhotonTableRow({
    required this.title,
    required this.cells,
    this.details = const [],
  });

  final String title;
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
                  key: ValueKey(row.title),
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

String _gossipState(AppLocalizations l, Map<String, dynamic> entry) {
  switch (entry['pull_state']) {
    case 'ping_sent' ||
        'summary_sent' ||
        'catalog_diffing' ||
        'object_pulling' ||
        'chunk_fallback':
      return l.photonGossipSyncing;
    case 'completed' || 'synced':
      return l.photonGossipSynced;
    case 'failed':
      return l.photonGossipFailed;
  }
  final failure = _map(entry['session_failure']);
  final lastSync = entry['last_sync_unix'];
  if (failure.isNotEmpty &&
      (lastSync is! int ||
          lastSync <= 0 ||
          failure['at_unix'] is int &&
              (failure['at_unix'] as int) > lastSync)) {
    return l.photonGossipFailed;
  }
  return lastSync is int && lastSync > 0
      ? l.photonGossipSynced
      : l.photonGossipWaiting;
}

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
    ? _date(
        DateTime.fromMillisecondsSinceEpoch(
          value * 1000,
          isUtc: true,
        ).toIso8601String(),
      )
    : '';
String _failure(dynamic value) {
  final data = _map(value);
  return _text(data['message'] ?? data['detail'] ?? data['code']);
}
