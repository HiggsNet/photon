import 'package:fl_clash/common/common.dart';
import 'package:fl_clash/widgets/widgets.dart';
import 'package:flutter/widgets.dart';

import 'proxy_selection.dart';
import 'services.dart';

enum _SelectionField { protocols, regions, nodes }

class PhotonProxySelectionView extends StatefulWidget {
  const PhotonProxySelectionView({
    super.key,
    required this.directory,
    required this.load,
    required this.onSave,
    required this.enabled,
  });

  final PhotonDirectory? directory;
  final Future<PhotonProxySelection> Function() load;
  final Future<void> Function(PhotonProxySelection) onSave;
  final bool enabled;

  @override
  State<PhotonProxySelectionView> createState() => _SelectionState();
}

class _SelectionState extends State<PhotonProxySelectionView> {
  late final _loaded = widget.load();
  PhotonProxySelection? _draft;

  @override
  Widget build(BuildContext context) => FutureBuilder<PhotonProxySelection>(
    future: _loaded,
    builder: (context, snapshot) {
      if (snapshot.hasError) return Text('${snapshot.error}');
      final selection = _draft ?? snapshot.data;
      if (selection == null) return const SizedBox.shrink();
      final l = context.appLocalizations;
      final available = widget.directory?.proxyEndpoints ?? <PhotonEndpoint>[];
      final regions =
          <String>{
            ...available.map((e) => e.region),
            ...selection.excludedRegions,
          }.toList()..sort((a, b) {
            if (a == b) return 0;
            if (a == 'local' || b == 'global') return -1;
            if (b == 'local' || a == 'global') return 1;
            return a.compareTo(b);
          });
      final nodes = <String>{
        ...available.where((e) => e.region == 'local').map((e) => e.owner),
        ...selection.excludedNodes,
      }.toList()..sort();
      final selected = available
          .where(
            (e) => selection.allows(
              type: e.type,
              region: e.region,
              owner: e.owner,
            ),
          )
          .length;
      Widget checks(
        String title,
        List<String> values,
        Set<String> set, {
        bool excluded = false,
        required _SelectionField field,
      }) => Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            title,
            style: AppTextStyle.callout.of(context, emphasized: true),
          ),
          Wrap(
            spacing: 16,
            children: [
              for (final value in values)
                Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Checkbox(
                      value: excluded
                          ? !set.contains(value)
                          : set.contains(value),
                      onChanged: !widget.enabled
                          ? null
                          : (checked) {
                              final next = {...set};
                              if ((checked == true) != excluded) {
                                next.add(value);
                              } else {
                                next.remove(value);
                              }
                              setState(
                                () => _draft = PhotonProxySelection(
                                  protocols: field == _SelectionField.protocols
                                      ? next
                                      : selection.protocols,
                                  excludedRegions:
                                      field == _SelectionField.regions
                                      ? next
                                      : selection.excludedRegions,
                                  excludedNodes: field == _SelectionField.nodes
                                      ? next
                                      : selection.excludedNodes,
                                ),
                              );
                            },
                    ),
                    Text(switch (value) {
                      'socks5' => 'SOCKS5',
                      'http' => 'HTTP',
                      'trusttunnel' => 'TrustTunnel',
                      _ => value,
                    }),
                  ],
                ),
            ],
          ),
        ],
      );
      return Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        spacing: 8,
        children: [
          Text(
            l.photonProxySelectionTip,
            style: AppTextStyle.caption1.of(context),
          ),
          checks(
            l.photonProxyProtocols,
            const ['socks5', 'http', 'trusttunnel'],
            selection.protocols,
            field: _SelectionField.protocols,
          ),
          if (regions.isNotEmpty)
            checks(
              l.photonProxyRegions,
              regions,
              selection.excludedRegions,
              field: _SelectionField.regions,
              excluded: true,
            ),
          if (nodes.isNotEmpty)
            checks(
              l.photonProxyLocalNodes,
              nodes,
              selection.excludedNodes,
              field: _SelectionField.nodes,
              excluded: true,
            ),
          Text('${l.photonProxySelected}: $selected / ${available.length}'),
          if (selected == 0) Text(l.photonProxySelectionEmpty),
          TextButton(
            onPressed: !widget.enabled ? null : () => widget.onSave(selection),
            child: Text(l.photonProxySaveSelection),
          ),
        ],
      );
    },
  );
}
