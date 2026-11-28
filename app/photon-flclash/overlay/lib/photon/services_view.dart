import 'package:fl_clash/common/common.dart';
import 'package:fl_clash/l10n/l10n.dart';
import 'package:fl_clash/providers/app.dart';
import 'package:fl_clash/widgets/widgets.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'controller.dart';
import 'proxy_bridge.dart';
import 'proxy_selection_view.dart';
import 'services.dart';
import 'status_table.dart';

class PhotonServicesView extends ConsumerStatefulWidget {
  const PhotonServicesView({super.key, this.controller});

  final PhotonController? controller;

  @override
  ConsumerState<PhotonServicesView> createState() => _PhotonServicesViewState();
}

class _PhotonServicesViewState extends ConsumerState<PhotonServicesView> {
  String _filter = '';

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
    final l = context.appLocalizations;
    return Scaffold(
      title: l.photonServices,
      body: ListenableBuilder(
        listenable: owner,
        builder: (context, _) {
          final status = owner.observation;
          return CustomScrollView(
            key: const PageStorageKey('photon-services'),
            slivers: [
              SliverPadding(
                padding: EdgeInsets.fromLTRB(
                  20,
                  context.sectionsTopPadding,
                  20,
                  16,
                ),
                sliver: SliverToBoxAdapter(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    spacing: 16,
                    children: [
                      if (safeMode)
                        Text(l.safeMode)
                      else ...[
                        _proxyControls(l, status),
                        if (owner.error case final error?)
                          PhotonDetailCard(
                            title: l.error,
                            lines: [(l.errorDetails, '$error')],
                          ),
                        if (status != null)
                          TextField(
                            decoration: InputDecoration(
                              hintText: l.photonSearch,
                            ),
                            autocorrect: false,
                            onChanged: (value) =>
                                setState(() => _filter = value.toLowerCase()),
                          ),
                      ],
                    ],
                  ),
                ),
              ),
              if (!safeMode && status != null)
                SliverPadding(
                  padding: const EdgeInsets.symmetric(horizontal: 20),
                  sliver: _proxyTable(l),
                ),
              SliverToBoxAdapter(
                child: SizedBox(height: 20 + context.bottomInset),
              ),
            ],
          );
        },
      ),
    );
  }

  Widget _proxyControls(AppLocalizations l, Map<String, dynamic>? status) {
    final directory = owner.directory;
    final hasEndpoints = directory?.endpoints.isNotEmpty == true;
    final ready = status?['tunnel_ready'] == true;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          spacing: 16,
          children: [
            Row(
              spacing: 12,
              children: [
                Expanded(
                  child: Text(
                    !ready
                        ? l.photonProxyRequiresTunnel
                        : !owner.directoryFresh
                        ? l.photonStale
                        : l.photonMultiTip,
                    style: AppTextStyle.caption1.of(context),
                  ),
                ),
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
              ],
            ),
            if (status != null)
              PhotonProxySelectionView(
                directory: directory,
                load: photonProxyBridge.loadSelection,
                onSave: (selection) => owner.applyProxies(
                  () => photonProxyBridge.saveSelection(selection),
                ),
                enabled: !owner.busy && !owner.closed,
              ),
          ],
        ),
      ),
    );
  }

  Widget _proxyTable(AppLocalizations l) {
    final endpoints = owner.directoryFresh ? owner.directory?.endpoints : null;
    final byNode = <String, Set<String>>{};
    for (final endpoint in endpoints ?? const <PhotonEndpoint>[]) {
      (byNode[endpoint.owner] ??= {}).add(endpoint.region);
    }
    final regions =
        {
          'local',
          for (final published in byNode.values) ...published,
          'global',
        }.toList()..sort((a, b) {
          if (a == b) return 0;
          if (a == 'local' || b == 'global') return -1;
          if (b == 'local' || a == 'global') return 1;
          return a.compareTo(b);
        });
    final nodes =
        byNode.keys
            .where(
              (node) => _matches([
                node,
                ...byNode[node]!,
                for (final region in byNode[node]!)
                  _proxyRegionLabel(l, region),
              ]),
            )
            .toList()
          ..sort(comparePhotonNodeNames);
    return PhotonTable(
      columns: [
        TableColumn('node', l.photonNode, flex: 3, end: true),
        for (final region in regions)
          TableColumn('region-$region', _proxyRegionLabel(l, region), flex: 1),
      ],
      length: nodes.length,
      rowAt: (context, index) {
        final node = nodes[index];
        final published = byNode[node]!;
        return PhotonTableRow(
          title: node,
          cells: [
            Text(node),
            for (final region in regions)
              photonStatusMark(
                _proxyRegionLabel(l, region),
                published.contains(region),
              ),
          ],
        );
      },
    );
  }

  bool _matches(List<String> values) =>
      _filter.isEmpty ||
      values.any((value) => value.toLowerCase().contains(_filter));
}

String _proxyRegionLabel(AppLocalizations l, String region) => switch (region) {
  'local' => l.local,
  'cn' => l.photonChina,
  'hk' => l.photonHongKong,
  'jp' => l.photonJapan,
  'sg' => l.photonSingapore,
  'us' => l.photonUnitedStates,
  'global' => l.global,
  _ => region,
};
