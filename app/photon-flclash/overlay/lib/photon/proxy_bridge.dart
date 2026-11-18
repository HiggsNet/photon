import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:fl_clash/common/common.dart';
import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/models/models.dart';
import 'package:fl_clash/providers/providers.dart';
import 'package:fl_clash/state.dart';
import 'package:flutter/foundation.dart' show compute;
import 'package:flutter_riverpod/flutter_riverpod.dart' show Provider;
import 'package:path/path.dart' as path;
import 'package:yaml/yaml.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'proxy_selection.dart';

import 'controller.dart';
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
    final directory = photonController.directory;
    try {
      if (directory != null && photonController.directoryFresh) {
        await _refresh(directory);
      }
    } catch (_) {
      await _invalidate();
      rethrow;
    }
  }

  bool _attached = false;
  String? _published;
  String? _profileDigest;
  String? _templateText;
  Map<String, dynamic>? _template;
  ({int profileId, PhotonProxyCardTitles titles})? _cardTitles;
  bool _applying = false;
  int? _blockedProfileId;

  bool get ready =>
      photonController.directoryFresh &&
      photonController.observation?['tunnel_ready'] == true &&
      _published != null &&
      _published == _desired();

  void attach() {
    if (_attached) return;
    _attached = true;
    photonController.onServicesChanged = _refresh;
    photonController.onServicesInvalidated = _invalidate;
  }

  Map<String, dynamic> _profile(
    PhotonDirectory directory, {
    Map<String, dynamic>? template,
    PhotonProxyCardTitles? cardTitles,
  }) => photonProxyProfile(
    directory: directory,
    now: DateTime.now(),
    splitRoutes: List<String>.from(
      (photonController.observation?['wintun'] as Map?)?['split_routes']
              as List? ??
          [],
    ),
    adapter: directory.adapterName,
    backendPath: path.join(
      File(Platform.resolvedExecutable).parent.path,
      'photon-windows.exe',
    ),
    template: template,
    selection: _selection,
    cardTitles: cardTitles,
  );

  Future<Map<String, dynamic>?> _readTemplate() async {
    final configPath = photonController.configPath;
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

  /// Called on the controller queue so an in-flight refresh cannot publish
  /// between validating and replacing the template.
  Future<void> saveTemplate(String configPath, String source) async {
    if (utf8.encode(source).length > _templateLimit) {
      throw const FormatException('The Photon proxy template exceeds 4 MiB');
    }
    final template = await compute(_parseTemplate, source);
    final directory = photonController.directory;
    final now = DateTime.now();
    final profile =
        directory != null &&
            directory.fresh(now) &&
            directory.endpoints.isNotEmpty &&
            directory.adapterName.isNotEmpty
        ? _profile(directory, template: template)
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

  String? _desired() {
    final directory = photonController.directory;
    if (directory == null ||
        !photonController.directoryFresh ||
        directory.proxyEndpoints.isEmpty ||
        directory.adapterName.isEmpty) {
      return null;
    }
    return sha256
        .convert(utf8.encode(encodePhotonProfile(_profile(directory))))
        .toString();
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
    if (_applying) return;
    attach();
    _applying = true;
    try {
      final directory = photonController.directory;
      if (directory == null ||
          !photonController.directoryFresh ||
          photonController.observation?['tunnel_ready'] != true) {
        throw StateError('Establish the Photon tunnel before using proxies');
      }
      await _publish(directory, create: true);
      final profile = _managed();
      if (profile == null || !ready) {
        throw StateError('Photon proxy profile is unavailable');
      }
      final container = globalState.container;
      final alreadySelected =
          container.read(currentProfileIdProvider) == profile.id;
      container.read(currentProfileIdProvider.notifier).value = profile.id;
      final applied = await container
          .read(setupActionProvider.notifier)
          .applyProfile(force: true, silence: true);
      if (!applied) {
        throw StateError('Photon proxy profile could not be applied');
      }
      if (alreadySelected &&
          container.read(currentProfileIdProvider) == profile.id) {
        await container.read(coreHandlerProvider).closeConnections();
      }
      container
          .read(currentPageLabelProvider.notifier)
          .toPage(PageLabel.proxies);
    } catch (_) {
      await _invalidate();
      rethrow;
    } finally {
      _applying = false;
    }
  }

  Future<void> _refresh(PhotonDirectory directory) async {
    if (_managed() == null) return;
    if (directory.proxyEndpoints.isEmpty ||
        photonController.observation?['tunnel_ready'] != true) {
      await _invalidate();
      return;
    }
    await _publish(directory);
  }

  Future<void> _publish(
    PhotonDirectory directory, {
    bool create = false,
  }) async {
    await loadSelection();
    final template = await _readTemplate();
    final cardTitles = PhotonProxyCardTitles();
    final networkContent = encodePhotonProfile(
      _profile(directory, cardTitles: template == null ? cardTitles : null),
    );
    final networkDigest = sha256
        .convert(utf8.encode(networkContent))
        .toString();
    final content = template == null
        ? networkContent
        : encodePhotonProfile(
            _profile(directory, template: template, cardTitles: cardTitles),
          );
    final digest = sha256.convert(utf8.encode(content)).toString();
    final container = globalState.container;
    var profile = _managed();
    if (profile == null && !create) return;
    profile ??= Profile.normal(label: 'Photon')
        .copyWith(url: photonProfileSource, autoUpdate: false);
    if (_profileDigest == digest && _published == networkDigest) return;
    await _validateProfile(content, profile.ageSecretKey);
    if (!directory.fresh(DateTime.now())) {
      throw StateError('Photon service information expired while applying');
    }
    _published = null;
    await (await profile.file).writeAsStringAtomically(content);
    final latest =
        container.read(profilesProvider).getProfile(profile.id) ?? profile;
    _cardTitles = (profileId: profile.id, titles: cardTitles);
    container
        .read(profilesActionProvider.notifier)
        .putProfile(latest.copyWith(lastUpdateDate: DateTime.now()));
    _profileDigest = digest;
    _published = networkDigest;
    _blockedProfileId = null;
    if (!create &&
        container.read(currentProfileProvider)?.url == photonProfileSource) {
      final applied = await container
          .read(setupActionProvider.notifier)
          .applyProfile(force: true, silence: true);
      if (!applied) {
        throw StateError('Photon proxy profile could not be applied');
      }
      await container.read(coreHandlerProvider).closeConnections();
    }
  }

  Future<void> _invalidate() async {
    _published = null;
    final container = globalState.container;
    final current = container.read(currentProfileProvider);
    if (current == null ||
        current.url != photonProfileSource ||
        current.id == _blockedProfileId) {
      return;
    }
    final applied = await container
        .read(setupActionProvider.notifier)
        .applyProfile(force: true, silence: true);
    if (!applied) throw StateError('Could not pause the Photon proxy profile');
    if (container.read(currentProfileIdProvider) == current.id) {
      await container.read(coreHandlerProvider).closeConnections();
      _blockedProfileId = current.id;
    }
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
