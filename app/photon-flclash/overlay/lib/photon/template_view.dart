import 'dart:io';

import 'package:fl_clash/common/common.dart';
import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/pages/editor.dart';
import 'package:fl_clash/providers/app.dart';
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
  const PhotonTemplateView({super.key, this.controller, this.applyProfile});

  final PhotonController? controller;
  final Future<void> Function()? applyProfile;

  @override
  ConsumerState<PhotonTemplateView> createState() => _PhotonTemplateViewState();
}

class _PhotonTemplateViewState extends ConsumerState<PhotonTemplateView> {
  String? _templateConfig;
  Future<bool>? _hasTemplate;
  bool _applying = false;

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
                else if (config != null) ...[
                  _templateControls(config),
                  if (owner.error case final error?)
                    Text(
                      '$error',
                      style: TextStyle(color: context.colorScheme.error),
                    ),
                ] else if (!owner.busy) ...[
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
                const PhotonTemplateHelp(),
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
        final idle = !_applying && !owner.busy && !owner.closed;
        final editable =
            idle && snapshot.connectionState == ConnectionState.done;
        final directory = owner.directory;
        final canApply =
            idle &&
            owner.hasLease &&
            directory != null &&
            (directory.proxyPaths.isNotEmpty ||
                (owner.observation?['tunnel_ready'] == true &&
                    directory.endpoints.isNotEmpty &&
                    directory.adapterName.isNotEmpty));
        return Wrap(
          spacing: 8,
          runSpacing: 8,
          children: [
            FilledButton(
              onPressed: canApply ? _applyProfile : null,
              child: Text(l.photonApply),
            ),
            OutlinedButton(
              onPressed: editable ? () => _editTemplate(config, file) : null,
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
        );
      },
    );
  }

  Future<void> _applyProfile() async {
    if (_applying) return;
    final controller = owner;
    final apply = widget.applyProfile ?? photonProxyBridge.apply;
    setState(() => _applying = true);
    try {
      await controller.refresh();
      await controller.applyProxies(apply);
    } finally {
      if (mounted) setState(() => _applying = false);
    }
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
