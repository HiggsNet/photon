import 'dart:io';

import 'package:fl_clash/common/common.dart';
import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/pages/editor.dart';
import 'package:fl_clash/providers/app.dart';
import 'package:fl_clash/ui/icons/icons.dart';
import 'package:fl_clash/widgets/widgets.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'controller.dart';
import 'proxy_bridge.dart';
import 'setup_view.dart';
import 'template_help.dart';

const _starterRules = '''rules:
  # - DOMAIN-SUFFIX,example.org,Photon Paths
  - MATCH,Photon
''';

class PhotonTemplateView extends ConsumerStatefulWidget {
  const PhotonTemplateView({super.key, this.controller});

  final PhotonController? controller;

  @override
  ConsumerState<PhotonTemplateView> createState() => _PhotonTemplateViewState();
}

class _PhotonTemplateViewState extends ConsumerState<PhotonTemplateView> {
  String? _templateConfig;
  Future<bool>? _hasTemplate;

  PhotonController get owner => widget.controller ?? photonController;

  @override
  void initState() {
    super.initState();
    owner.initialize();
  }

  @override
  Widget build(BuildContext context) {
    final safeMode = ref.watch(safeModeProvider);
    final l = context.appLocalizations;
    return Scaffold(
      title: l.photonTemplate,
      body: ListenableBuilder(
        listenable: owner,
        builder: (context, _) {
          final config = owner.configPath;
          return SingleChildScrollView(
            key: const PageStorageKey('photon-template'),
            padding: EdgeInsets.fromLTRB(
              20,
              context.sectionsTopPadding,
              20,
              20 + context.bottomInset,
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              spacing: 16,
              children: [
                if (safeMode)
                  Text(l.safeMode)
                else if (config != null)
                  _templateControls(config)
                else if (!owner.busy) ...[
                  Text(l.photonTemplateNeedsConfig),
                  Align(
                    alignment: Alignment.centerLeft,
                    child: FilledButton(
                      onPressed: () => ref
                          .read(currentPageLabelProvider.notifier)
                          .toPage(PageLabel.photon),
                      child: Text(l.photonName),
                    ),
                  ),
                ],
                Text(l.photonTemplateHint),
                Text(l.photonTemplatePathsHint),
                Align(
                  alignment: Alignment.centerLeft,
                  child: TextButton.icon(
                    onPressed: () => showPhotonTemplateHelp(context),
                    icon: const GlyphIcon(AppGlyphs.info, size: 20),
                    label: Text(l.photonTemplateHelp),
                  ),
                ),
              ],
            ),
          );
        },
      ),
    );
  }

  Widget _templateControls(String config) {
    final l = context.appLocalizations;
    final file = photonProxyTemplateFile(config);
    if (_templateConfig != config) {
      _templateConfig = config;
      _hasTemplate = file.exists();
    }
    return FutureBuilder<bool>(
      key: ValueKey(config),
      future: _hasTemplate,
      builder: (context, snapshot) {
        final hasTemplate = snapshot.data == true;
        final editable =
            !owner.busy &&
            !owner.closed &&
            snapshot.connectionState == ConnectionState.done;
        return Card(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            spacing: 12,
            children: [
              if (snapshot.connectionState == ConnectionState.done)
                Text(
                  hasTemplate
                      ? file.uri.pathSegments.last
                      : l.photonBuiltinRules,
                  style: AppTextStyle.headline.of(context),
                ),
              Wrap(
                spacing: 8,
                runSpacing: 8,
                children: [
                  FilledButton(
                    onPressed: editable
                        ? () => _editTemplate(config, file)
                        : null,
                    child: Text(l.photonEditTemplate),
                  ),
                  OutlinedButton(
                    onPressed: editable ? () => _importTemplate(config) : null,
                    child: Text(l.photonImportTemplate),
                  ),
                  if (hasTemplate)
                    TextButton(
                      onPressed: editable ? () => _resetTemplate(config) : null,
                      child: Text(l.photonBuiltinRules),
                    ),
                ],
              ),
            ],
          ),
        );
      },
    );
  }

  Future<void> _resetTemplate(String config) async {
    final l = context.appLocalizations;
    final confirmed = await dialogs.showMessage(
      title: l.photonBuiltinRules,
      message: TextSpan(text: l.photonRemoveTemplate),
      destructive: true,
    );
    if (confirmed == true && mounted) await _changeTemplate(config, null);
  }

  Future<void> _importTemplate(String config) async {
    try {
      final input = await choosePhotonConfig();
      if (input == null || !mounted) return;
      final source = await readPhotonProxyTemplate(File(input));
      if (!mounted) return;
      await _changeTemplate(config, source);
    } catch (error) {
      if (mounted) await dialogs.showAlert(message: TextSpan(text: '$error'));
    }
  }

  Future<void> _editTemplate(String config, File file) async {
    try {
      final source = await file.exists()
          ? await readPhotonProxyTemplate(file)
          : _starterRules;
      if (!mounted) return;
      final l = context.appLocalizations;
      await BaseNavigator.push<void>(
        context,
        EditorPage(
          title: l.photonEditTemplate,
          content: source,
          schema: EditorSchema.photonTemplate,
          onSave: (context, _, content) async {
            final saved = await _changeTemplate(
              config,
              await content.readText(),
            );
            if (saved && context.mounted) Navigator.of(context).pop();
          },
          onPop: (context, _, content) async {
            final answer = await dialogs.showSaveChanges(
              title: l.photonEditTemplate,
            );
            if (answer == null || !context.mounted) return false;
            return !answer ||
                await _changeTemplate(config, await content.readText());
          },
        ),
      );
    } catch (error) {
      if (mounted) await dialogs.showAlert(message: TextSpan(text: '$error'));
    }
  }

  Future<bool> _changeTemplate(String config, String? source) async {
    if (!mounted || owner.closed || owner.configPath != config) return false;
    final file = photonProxyTemplateFile(config);
    Object? problem;
    var changed = false;
    await owner.applyProxies(() async {
      if (owner.closed || owner.configPath != config) return;
      try {
        if (source == null) {
          if (await file.exists()) await file.delete();
          changed = true;
        } else {
          await photonProxyBridge.saveTemplate(config, source);
          changed = true;
        }
      } catch (error) {
        problem = error;
      }
    });
    if (!mounted) return changed;
    if (changed) setState(() => _hasTemplate = file.exists());
    if (problem != null) {
      await dialogs.showAlert(message: TextSpan(text: '$problem'));
      return false;
    }
    if (changed) await owner.refresh();
    return changed;
  }
}
