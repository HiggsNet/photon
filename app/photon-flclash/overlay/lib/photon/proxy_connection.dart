import 'package:fl_clash/common/common.dart';
import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/providers/app.dart';
import 'package:fl_clash/widgets/widgets.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'controller.dart';

class PhotonProxyConnection extends ConsumerWidget {
  const PhotonProxyConnection({
    super.key,
    required this.owner,
    required this.safeMode,
    this.enabled = true,
  });

  final PhotonController owner;
  final bool safeMode;
  final bool enabled;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final l = context.appLocalizations;
    if (safeMode) return Text(l.safeMode);
    final configured = owner.configPath != null;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      spacing: 12,
      children: [
        if (!configured) Text(l.photonSetupHint),
        FilledButton(
          onPressed: !enabled || owner.busy || owner.closed
              ? null
              : configured
              ? () => owner.start(allowed: true)
              : () => ref
                    .read(currentPageLabelProvider.notifier)
                    .toPage(PageLabel.photon),
          child: Text(configured ? l.photonConnectToPhoton : l.photonName),
        ),
        if (owner.error case final error?)
          Text('$error', style: TextStyle(color: context.colorScheme.error)),
      ],
    );
  }
}
