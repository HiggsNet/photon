import 'package:fl_clash/common/common.dart';
import 'package:fl_clash/ui/icons/icons.dart';
import 'package:fl_clash/widgets/widgets.dart';
import 'package:flutter/widgets.dart';
import 'package:path/path.dart' as path;

import 'controller.dart';
import 'setup_view.dart';
import 'storage_view.dart';

class PhotonSettings extends StatelessWidget {
  const PhotonSettings({super.key, required this.owner, required this.allowed});

  final PhotonController owner;
  final bool allowed;

  @override
  Widget build(BuildContext context) {
    final l = context.appLocalizations;
    final config = owner.configPath;
    final editable = allowed && !owner.busy && !owner.closed && !owner.hasLease;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      spacing: 20,
      children: [
        generateSection(
          title: l.photonCurrentConfig,
          footer: owner.hasLease ? l.photonStopToEdit : null,
          items: [
            ListItem(
              leading: const GlyphIcon(AppGlyphs.settings),
              title: Text(
                config == null ? l.photonSettings : path.basename(config),
              ),
              subtitle: config == null
                  ? Text(l.photonSetupHint)
                  : SelectableText(config),
              trailing: TextButton(
                onPressed: editable
                    ? () => owner.pickConfig(
                        () => editPhotonSettings(context, config: config),
                      )
                    : null,
                child: Text(config == null ? l.photonCreateConfig : l.edit),
              ),
            ),
          ],
        ),
        if (editable)
          generateSection(
            title: l.photonConfiguration,
            items: [
              ListItem(
                leading: const GlyphIcon(AppGlyphs.importFile),
                title: Text(l.photonImportConfig),
                trailing: const GlyphIcon(AppGlyphs.chevronForward, size: 18),
                onTap: () => owner.pickConfig(importPhotonConfig),
              ),
              ListItem(
                leading: const GlyphIcon(AppGlyphs.openExternal),
                title: Text(l.photonUseConfigFile),
                trailing: const GlyphIcon(AppGlyphs.chevronForward, size: 18),
                onTap: () => owner.pickConfig(choosePhotonConfig),
              ),
              if (config != null) ...[
                ListItem(
                  leading: const GlyphIcon(AppGlyphs.add),
                  title: Text(l.photonCreateConfig),
                  trailing: const GlyphIcon(AppGlyphs.chevronForward, size: 18),
                  onTap: () => owner.pickConfig(
                    () => editPhotonSettings(context, chooseLocation: true),
                  ),
                ),
                ListItem(
                  leading: const GlyphIcon(AppGlyphs.key),
                  title: Text(l.photonImportIdentity),
                  trailing: const GlyphIcon(AppGlyphs.chevronForward, size: 18),
                  onTap: () =>
                      owner.pickConfig(() => showPhotonImport(context, config)),
                ),
              ],
            ],
          ),
        PhotonStorage(owner: owner, allowed: allowed),
      ],
    );
  }
}
