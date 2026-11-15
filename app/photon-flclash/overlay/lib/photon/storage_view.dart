import 'dart:io';

import 'package:file_picker/file_picker.dart';
import 'package:fl_clash/common/common.dart';
import 'package:fl_clash/widgets/widgets.dart';
import 'package:flutter/widgets.dart';
import 'package:path/path.dart' as path;
import 'package:url_launcher/url_launcher.dart';

import 'controller.dart';
import 'setup.dart';

class PhotonStorage extends StatelessWidget {
  const PhotonStorage({super.key, required this.owner});

  final PhotonController owner;

  @override
  Widget build(BuildContext context) {
    final l = context.appLocalizations;
    final config = owner.configPath;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        FutureBuilder<String>(
          future: config == null
              ? appPath.homeDirPath.then((root) => path.join(root, 'photon'))
              : Future.value(File(config).parent.path),
          builder: (context, snapshot) => snapshot.hasData
              ? SelectableText('${l.photonDataDirectory}: ${snapshot.data}')
              : const SizedBox.shrink(),
        ),
        Wrap(
          spacing: 12,
          children: [
            TextButton(
              onPressed: owner.busy
                  ? null
                  : () async {
                      final directory = config == null
                          ? Directory(
                              path.join(await appPath.homeDirPath, 'photon'),
                            )
                          : File(config).parent;
                      await owner.applyProxies(() async {
                        await directory.create(recursive: true);
                        if (!await launchUrl(directory.uri)) {
                          throw StateError('Could not open data directory');
                        }
                      });
                    },
              child: Text(l.photonOpenDirectory),
            ),
            if (config != null)
              TextButton(
                onPressed: owner.busy || owner.hasLease
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
                child: Text(l.photonMigrateDirectory),
              ),
          ],
        ),
        Text(l.photonStorageHint, style: AppTextStyle.caption1.of(context)),
      ],
    );
  }
}
