import 'dart:io';

import 'package:fl_clash/common/common.dart';
import 'package:fl_clash/providers/app.dart';
import 'package:fl_clash/widgets/widgets.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'controller.dart';

class PhotonView extends ConsumerWidget {
  const PhotonView({super.key, this.controller, this.isWindows});

  final PhotonController? controller;
  final bool? isWindows;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final owner = controller ?? photonController;
    final safeMode = ref.watch(safeModeProvider);
    final allowed = (isWindows ?? Platform.isWindows) && !safeMode;
    final l = context.appLocalizations;
    return ListenableBuilder(
      listenable: owner,
      builder: (context, _) {
        final status = owner.observation;
        final connected = status?['tunnel_ready'] == true;
        final addresses = status?['wintun']?['addresses'] as List? ?? const [];
        final peers = status?['connections'] as List? ?? const [];
        final connectedPeers = peers
            .where((peer) => peer['tunnel_ready'] == true)
            .length;
        return Scaffold(
          title: 'Photon',
          body: Builder(
            builder: (context) => ListView(
              padding: const EdgeInsets.symmetric(horizontal: 16).copyWith(
                top: context.sectionsTopPadding,
                bottom: 16 + context.bottomInset,
              ),
              children: [
                generateSection(
                  items: [
                    ListItem(
                      title: Text(l.status),
                      subtitle: Text(
                        safeMode
                            ? l.safeMode
                            : owner.busy
                            ? l.loading
                            : connected
                            ? l.connected
                            : owner.hasLease
                            ? l.connecting
                            : l.disconnected,
                      ),
                    ),
                    ListItem(
                      title: Text(l.importFile),
                      subtitle: owner.configPath == null
                          ? null
                          : Text(owner.configPath!),
                      onTap: !allowed || owner.busy || owner.hasLease
                          ? null
                          : () => owner.pickConfig(() async {
                              final file = await picker.pickerFile();
                              final uri = file?.uri;
                              if (uri != null && uri.scheme == 'file') {
                                return uri.toFilePath();
                              }
                              return null;
                            }),
                    ),
                    ListItem(
                      title: Text(owner.hasLease ? l.stop : l.start),
                      onTap: owner.busy || owner.closed
                          ? null
                          : owner.hasLease
                          ? owner.stop
                          : !allowed || owner.configPath == null
                          ? null
                          : () => owner.start(allowed: allowed),
                    ),
                  ],
                ),
                if (owner.error != null)
                  generateSection(
                    items: [
                      ListItem(
                        title: Text(l.error),
                        subtitle: Text(owner.error.toString()),
                      ),
                    ],
                  ),
                if (status != null)
                  generateSection(
                    items: [
                      ListItem(
                        title: Text(l.ipAddress),
                        subtitle: Text(addresses.join('\n')),
                      ),
                      ListItem(
                        title: Text(l.connections),
                        subtitle: Text('$connectedPeers'),
                      ),
                    ],
                  ),
              ],
            ),
          ),
        );
      },
    );
  }
}
