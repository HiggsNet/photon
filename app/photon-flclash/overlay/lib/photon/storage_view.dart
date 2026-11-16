import 'dart:io';

import 'package:file_picker/file_picker.dart';
import 'package:fl_clash/common/common.dart';
import 'package:fl_clash/ui/icons/icons.dart';
import 'package:fl_clash/widgets/widgets.dart';
import 'package:flutter/widgets.dart';
import 'package:path/path.dart' as path;
import 'package:url_launcher/url_launcher.dart';

import 'controller.dart';
import 'setup.dart';

class PhotonStorage extends StatelessWidget {
  const PhotonStorage({super.key, required this.owner, required this.allowed});

  final PhotonController owner;
  final bool allowed;

  @override
  Widget build(BuildContext context) {
    final l = context.appLocalizations;
    final config = owner.configPath;
    return generateSection(
      title: l.photonDataDirectory,
      footer: l.photonStorageHint,
      items: [
        FutureBuilder<String>(
          future: config == null
              ? appPath.homeDirPath.then((root) => path.join(root, 'photon'))
              : Future.value(File(config).parent.path),
          builder: (context, snapshot) => ListItem(
            title: snapshot.hasData
                ? SelectableText(snapshot.data!)
                : const SizedBox.shrink(),
            trailing: TextButton(
              onPressed: owner.busy || owner.closed
                  ? null
                  : () => owner.applyProxies(() async {
                      final directory = Directory(
                        await (config == null
                            ? appPath.homeDirPath.then(
                                (root) => path.join(root, 'photon'),
                              )
                            : Future.value(File(config).parent.path)),
                      );
                      await directory.create(recursive: true);
                      if (!await launchUrl(directory.uri)) {
                        throw StateError('Could not open data directory');
                      }
                    }),
              child: Text(l.photonOpenDirectory),
            ),
          ),
        ),
        if (config != null)
          ListItem(
            title: Text(l.photonMigrateDirectory),
            trailing: const GlyphIcon(AppGlyphs.chevronForward, size: 18),
            onTap: !allowed || owner.closed || owner.busy || owner.hasLease
                ? null
                : () => owner.pickConfig(() async {
                    final folder = await FilePicker.getDirectoryPath(
                      dialogTitle: l.photonMigrateDirectory,
                    );
                    if (folder == null) return null;
                    final destination = path.join(
                      folder,
                      path.basename(config),
                    );
                    await copyPhotonConfiguration(config, destination);
                    return destination;
                  }),
          ),
      ],
    );
  }
}
