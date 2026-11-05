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
            ? l.connected
            : owner.hasLease
            ? l.connecting
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
                                          : !allowed || owner.configPath == null
                                          ? null
                                          : () => owner.start(allowed: allowed),
                                      child: Text(
                                        owner.hasLease ? l.stop : l.start,
                                      ),
                                    ),
                                  ],
                                ),
                                if (owner.configPath != null)
                                  Text(
                                    owner.configPath!,
                                    style: AppTextStyle.caption1.of(context),
                                  ),
                                Wrap(
                                  spacing: 12,
                                  runSpacing: 8,
                                  children: [
                                    if (!owner.hasLease) ...[
                                      TextButton(
                                        onPressed: allowed && !owner.busy
                                            ? () => owner.pickConfig(
                                                choosePhotonConfig,
                                              )
                                            : null,
                                        child: Text(l.importFile),
                                      ),
                                      TextButton(
                                        onPressed: allowed && !owner.busy
                                            ? () => owner.pickConfig(
                                                () =>
                                                    editPhotonSettings(context),
                                              )
                                            : null,
                                        child: Text(l.photonCreateConfig),
                                      ),
                                      if (owner.configPath
                                          case final String config) ...[
                                        TextButton(
                                          onPressed: allowed && !owner.busy
                                              ? () => owner.pickConfig(
                                                  () => editPhotonSettings(
                                                    context,
                                                    config: config,
                                                  ),
                                                )
                                              : null,
                                          child: Text(l.photonSettings),
                                        ),
                                        TextButton(
                                          onPressed: allowed && !owner.busy
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
                                        '${l.connections}: $live / ${connections.length}',
                                      ),
                                    if (status != null)
                                      Text(
                                        '${l.lastUpdated}: ${_date(status['observed_at'])}',
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
                            (_Page.peers, l.peers),
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
                        if (status == null)
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
                  sliver: SliverPrismList(
                    itemCount: status == null ? 0 : items.length,
                    itemBuilder: (context, index) => Padding(
                      padding: const EdgeInsets.only(bottom: 12),
                      child: items[index](),
                    ),
                  ),
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
    final ike = _map(status['ike']);
    final babel = _map(status['babel']);
    final peers = _list(status['peers']);
    final connections = _list(status['connections']);
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
                admission['pending'] == true ? l.photonWaiting : l.connected,
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
          () => _DetailCard(
            title: l.photonTunnel,
            lines: [
              ('IKE', ike['live'] == true ? l.connected : l.disconnected),
              ('ESP', ike['child_live'] == true ? l.connected : l.disconnected),
              ('Babel', babel['live'] == true ? l.connected : l.disconnected),
              (l.photonRevision, _text(status['revision'])),
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
        return _rows(connections, l, (entry) {
          final security = _map(entry['ike']);
          return _DetailCard(
            title: _text(entry['peer']),
            lines: [
              (
                l.status,
                entry['tunnel_ready'] == true
                    ? l.connected
                    : _text(security['phase']),
              ),
              (l.address, _text(security['attempt_remote_endpoint'])),
              ('IKE', security['live'] == true ? l.connected : l.disconnected),
              (
                'ESP',
                security['child_live'] == true ? l.connected : l.disconnected,
              ),
              (
                'Babel',
                entry['babel_live'] == true ? l.connected : l.disconnected,
              ),
              (l.expireTime, _date(security['child_expires_at'])),
              if (security['last_failure'] != null)
                (l.errorDetails, _failure(security['last_failure'])),
            ],
          );
        }, truncated: status['connections_truncated'] == true);
      case _Page.peers:
        return _rows(
          peers,
          l,
          (entry) => _DetailCard(
            title: _text(entry['peer']),
            lines: [
              (l.status, _text(entry['pull_state'])),
              (l.lastUpdated, _unix(entry['last_sync_unix'])),
              (l.photonAdvanced, _text(entry['last_event'])),
              (
                l.download,
                '${entry['pull_successes'] ?? 0} / ${entry['pull_attempts'] ?? 0}',
              ),
              if (entry['last_pull_error'] != null)
                (l.errorDetails, _text(entry['last_pull_error'])),
            ],
          ),
          truncated: status['peers_truncated'] == true,
        );
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
      case _Page.services:
        final directory = owner.directory;
        return [
          () => _DetailCard(
            title: l.photonServices,
            lines: [
              (l.photonSelected, '${owner.selected.length}'),
              (l.photonName, l.photonMultiTip),
              if (!owner.directoryFresh) (l.status, l.photonStale),
            ],
            footer: FilledButton(
              onPressed:
                  widget.controller != null ||
                      owner.busy ||
                      !owner.directoryFresh ||
                      owner.selected.isEmpty ||
                      status['tunnel_ready'] != true
                  ? null
                  : () => owner.applyProxies(photonProxyBridge.apply),
              child: Text(l.photonApply),
            ),
          ),
          if (directory != null)
            for (final service in directory.services)
              () => _DetailCard(
                title: service.owner,
                lines: [
                  (
                    l.status,
                    service.status == 'active'
                        ? l.photonTrusted
                        : service.status == 'withdrawn'
                        ? l.photonWithdrawn
                        : l.photonUnauthorized,
                  ),
                  if (service.diagnostic.isNotEmpty)
                    (l.errorDetails, service.diagnostic),
                ],
                footer: Column(
                  children: [
                    for (final endpoint in service.endpoints)
                      ListItem.checkbox(
                        key: ValueKey(endpoint.id),
                        title: Text(endpoint.region),
                        subtitle: Text(
                          '${endpoint.authority}\n${l.photonUnprobed}',
                        ),
                        value: owner.selected.contains(endpoint.id),
                        onChanged: !owner.directoryFresh || owner.busy
                            ? null
                            : (value) => owner.toggleEndpoint(
                                endpoint.id,
                                value == true,
                              ),
                      ),
                  ],
                ),
              ),
          if (directory != null && directory.services.isEmpty)
            () => _DetailCard(title: l.photonEmpty, lines: []),
        ];
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
