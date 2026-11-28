import 'dart:convert';
import 'dart:io';

import 'package:fl_clash/common/common.dart';
import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/models/models.dart';
import 'package:fl_clash/providers/providers.dart';
import 'package:fl_clash/state.dart';
import 'package:flutter/foundation.dart' show compute, setEquals;
import 'package:flutter_riverpod/flutter_riverpod.dart' show Provider;
import 'package:path/path.dart' as path;
import 'package:yaml/yaml.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'proxy_selection.dart';

import 'controller.dart';
import 'profile.dart';
import 'services.dart';

const photonProfileSource = 'photon://local/services';
const _templateLimit = 4 * 1024 * 1024;

File photonProxyTemplateFile(String configPath) =>
    File('${path.withoutExtension(configPath)}.proxy.yaml');

Future<String> readPhotonProxyTemplate(File file) async {
  if (await file.length() > _templateLimit) {
    throw const FormatException('The Photon proxy template exceeds 4 MiB');
  }
  return file.readAsString();
}

Map<String, dynamic> _parseTemplate(String text) {
  final yaml = loadYaml(text);
  if (yaml is! Map) {
    throw const FormatException(
      'The Photon proxy template must be a YAML mapping',
    );
  }
  final template = Map<String, dynamic>.from(yaml);
  validatePhotonProxyTemplate(template);
  return template;
}

final class PhotonProxyBridge {
  PhotonProxyBridge({PhotonController? controller})
    : _controller = controller ?? photonController;

  final PhotonController _controller;
  PhotonProxySelection _selection = PhotonProxySelection();
  Future<void>? _selectionFuture;

  Future<PhotonProxySelection> loadSelection() async {
    await (_selectionFuture ??= () async {
      final stored = (await SharedPreferences.getInstance()).getString(
        'photon.v1.proxy_selection',
      );
      if (stored != null) {
        _selection = PhotonProxySelection.fromJson(
          Map<String, dynamic>.from(jsonDecode(stored) as Map),
        );
      }
    }());
    return _selection;
  }

  Future<void> saveSelection(PhotonProxySelection selection) async {
    await loadSelection();
    if (!await (await SharedPreferences.getInstance()).setString(
      'photon.v1.proxy_selection',
      jsonEncode(selection.toJson()),
    )) {
      throw StateError('Photon proxy selection could not be saved');
    }
    _selection = selection;
  }

  Future<Set<String>> includedPaths() async {
    final configPath = _controller.configPath;
    if (configPath == null) return {};
    final preferences = await SharedPreferences.getInstance();
    return (preferences.getStringList('photon.v2.paths.$configPath') ?? [])
        .toSet();
  }

  Future<void> includePath(String name, bool include) async {
    final configPath = _controller.configPath;
    if (configPath == null) throw StateError('Select a Photon configuration');
    final preferences = await SharedPreferences.getInstance();
    final key = 'photon.v2.paths.$configPath';
    final paths = (preferences.getStringList(key) ?? []).toSet();
    if (include) {
      paths.add(name);
    } else {
      paths.remove(name);
    }
    if (!await preferences.setStringList(key, paths.toList()..sort())) {
      throw StateError('Could not save Photon path selection');
    }
  }

  bool _attached = false;
  String? _templateText;
  Map<String, dynamic>? _template;
  ({int profileId, PhotonProxyCardTitles titles})? _cardTitles;
  ({int id, DateTime? updatedAt, Map<String, dynamic> content})? _savedProfile;
  ({int id, bool offline, Set<String> blocked})? _appliedAccess;

  PhotonDirectory? get _authorizedDirectory =>
      _controller.directoryFresh ? _controller.directory : null;

  bool get ready => _authorizedDirectory != null;

  Map<String, dynamic> authorizeProfile(Map<String, dynamic> profile) =>
      restrictPhotonProxies(
        profile,
        unauthorizedPhotonProxies(profile, _authorizedDirectory),
      );

  void attach() {
    if (_attached) return;
    _attached = true;
    _controller.onServicesChanged = (_) => _syncAppliedAccess();
    _controller.onServicesInvalidated = _syncAppliedAccess;
  }

  Map<String, dynamic> _profile(
    PhotonDirectory directory, {
    Map<String, dynamic>? template,
    Set<String> includedPaths = const {},
    PhotonProxyCardTitles? cardTitles,
  }) => photonProxyProfile(
    directory: directory,
    now: DateTime.now(),
    splitRoutes: List<String>.from(
      (_controller.observation?['wintun'] as Map?)?['split_routes'] as List? ??
          [],
    ),
    adapter: directory.adapterName,
    backendPath: path.join(
      File(Platform.resolvedExecutable).parent.path,
      'photon-windows.exe',
    ),
    template: template,
    selection: _selection,
    includedPaths: includedPaths,
    cardTitles: cardTitles,
  );

  Future<Map<String, dynamic>?> _readTemplate() async {
    final configPath = _controller.configPath;
    if (configPath == null) return null;
    final file = photonProxyTemplateFile(configPath);
    if (!await file.exists()) {
      _templateText = null;
      _template = null;
      return null;
    }
    final source = await readPhotonProxyTemplate(file);
    if (source != _templateText) {
      _template = await compute(_parseTemplate, source);
      _templateText = source;
    }
    return _template;
  }

  Future<void> saveTemplate(String configPath, String source) async {
    if (utf8.encode(source).length > _templateLimit) {
      throw const FormatException('The Photon proxy template exceeds 4 MiB');
    }
    final template = await compute(_parseTemplate, source);
    final directory = _controller.directory;
    final now = DateTime.now();
    final paths = await includedPaths();
    final profile =
        directory != null &&
            directory.fresh(now) &&
            ((directory.endpoints.isNotEmpty &&
                    directory.adapterName.isNotEmpty) ||
                directory.proxyPaths.any((route) => paths.contains(route.name)))
        ? _profile(directory, template: template, includedPaths: paths)
        : photonProxyTemplatePreview(template);
    await _validateProfile(
      encodePhotonProfile(profile),
      _managed()?.ageSecretKey ?? '',
    );
    await photonProxyTemplateFile(configPath).writeAsStringAtomically(source);
  }

  Future<void> _validateProfile(String content, String secret) async {
    final file = File(await appPath.tempFilePath);
    try {
      await file.safeWriteAsString(content);
      final core = globalState.container.read(coreHandlerProvider);
      if (await core.validateProfile(file.path, secret) case final issue?) {
        throw MessageException(issue);
      }
    } finally {
      await file.safeDelete();
    }
  }

  Profile? _managed() {
    final profiles = globalState.container.read(profilesProvider);
    final current = globalState.container.read(currentProfileProvider);
    if (current?.url == photonProfileSource &&
        current?.type == ProfileType.file) {
      return current;
    }
    for (final profile in profiles) {
      if (profile.url == photonProfileSource &&
          profile.type == ProfileType.file) {
        return profile;
      }
    }
    return null;
  }

  Future<void> apply() async {
    attach();
    final directory = _authorizedDirectory;
    final paths = await includedPaths();
    if (directory == null ||
        (_controller.observation?['tunnel_ready'] != true &&
            directory.proxyPaths.isEmpty)) {
      throw StateError('Establish the Photon tunnel before using proxies');
    }
    await loadSelection();
    final template = await _readTemplate();
    final cardTitles = PhotonProxyCardTitles();
    final generated = _profile(
      directory,
      template: template,
      includedPaths: paths,
      cardTitles: cardTitles,
    );
    final content = encodePhotonProfile(generated);
    final container = globalState.container;
    final previousProfile = _managed();
    final profile =
        previousProfile ??
        Profile.normal(label: 'Photon')
            .copyWith(url: photonProfileSource, autoUpdate: false);
    final file = await profile.file;
    final previousContent = await file.exists()
        ? await file.readAsString()
        : null;
    await _validateProfile(content, profile.ageSecretKey);
    if (!directory.fresh(DateTime.now())) {
      throw StateError('Photon service information expired while applying');
    }
    final updated = profile.copyWith(lastUpdateDate: DateTime.now());
    if (content != previousContent) await file.writeAsStringAtomically(content);
    final previousId = container.read(currentProfileIdProvider);
    final profiles = container.read(profilesActionProvider.notifier);
    final setup = container.read(setupActionProvider.notifier);
    profiles.putProfile(updated);
    container.read(currentProfileIdProvider.notifier).value = profile.id;
    try {
      if (!await setup.applyProfile(force: true, silence: true)) {
        throw StateError('Photon proxy profile could not be applied');
      }
      if (!directory.fresh(DateTime.now())) {
        throw StateError('Photon service information expired while applying');
      }
    } catch (error) {
      if (previousContent == null) {
        await file.safeDelete();
      } else if (content != previousContent) {
        await file.writeAsStringAtomically(previousContent);
      }
      final restoreSelection =
          container.read(currentProfileIdProvider) == profile.id;
      if (restoreSelection) {
        container.read(currentProfileIdProvider.notifier).value = previousId;
      }
      if (previousProfile == null) {
        await profiles.deleteProfile(profile.id);
      } else {
        profiles.putProfile(previousProfile);
      }
      if (restoreSelection &&
          previousId != null &&
          !await setup.applyProfile(force: true, silence: true)) {
        throw StateError(
          '$error\nCould not restore the previous proxy profile',
        );
      }
      rethrow;
    }
    _savedProfile = (
      id: profile.id,
      updatedAt: updated.lastUpdateDate,
      content: generated,
    );
    _appliedAccess = (id: profile.id, offline: false, blocked: const {});
    _cardTitles = (profileId: profile.id, titles: cardTitles);
    if (content != previousContent &&
        previousId == profile.id &&
        container.read(currentProfileIdProvider) == profile.id) {
      await container.read(coreHandlerProvider).closeConnections();
    }
    container.read(currentPageLabelProvider.notifier).toPage(PageLabel.proxies);
  }

  Future<void> _syncAppliedAccess() async {
    final container = globalState.container;
    final current = container.read(currentProfileProvider);
    if (current == null || current.url != photonProfileSource) {
      _appliedAccess = null;
      return;
    }
    var saved = _savedProfile;
    if (saved == null ||
        saved.id != current.id ||
        saved.updatedAt != current.lastUpdateDate) {
      Map<String, dynamic> content;
      try {
        content = await readPhotonProfile(current.id);
        _savedProfile = (
          id: current.id,
          updatedAt: current.lastUpdateDate,
          content: content,
        );
      } catch (_) {
        if (ready) rethrow;
        content = {};
      }
      saved = (
        id: current.id,
        updatedAt: current.lastUpdateDate,
        content: content,
      );
    }
    final directory = _authorizedDirectory;
    final blocked = unauthorizedPhotonProxies(saved.content, directory);
    final previous = _appliedAccess;
    final offline = directory == null;
    if (previous?.id == current.id &&
        previous?.offline == offline &&
        setEquals(previous?.blocked, blocked)) {
      return;
    }
    if (container.read(currentProfileIdProvider) != current.id) return;
    final applied = await container
        .read(setupActionProvider.notifier)
        .applyProfile(force: true, silence: true);
    if (!applied) throw StateError('Could not update Photon proxy access');
    if (container.read(currentProfileIdProvider) != current.id) return;
    if (blocked.isNotEmpty) {
      final core = container.read(coreHandlerProvider);
      final connections = await core.getConnections();
      if (container.read(currentProfileIdProvider) != current.id) return;
      for (final connection in connections) {
        if (connection.chains.any(blocked.contains)) {
          await core.closeConnection(connection.id);
        }
      }
    }
    _appliedAccess = (id: current.id, offline: offline, blocked: blocked);
  }
}

final photonProxyBridge = PhotonProxyBridge();

final photonProxyCardTitlesProvider = Provider<PhotonProxyCardTitles>((ref) {
  final profile = ref.watch(currentProfileProvider);
  final cardTitles = photonProxyBridge._cardTitles;
  if (profile?.url != photonProfileSource ||
      cardTitles == null ||
      profile?.id != cardTitles.profileId) {
    return const {};
  }
  return cardTitles.titles;
});
