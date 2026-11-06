import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/models/models.dart';
import 'package:fl_clash/providers/providers.dart';
import 'package:fl_clash/state.dart';
import 'package:path/path.dart' as path;

import 'controller.dart';
import 'services.dart';

const photonProfileSource = 'photon://local/services';

final class PhotonProxyBridge {
  bool _attached = false;
  String? _published;
  String? _profileDigest;
  bool _applying = false;
  int? _blockedProfileId;

  bool get ready =>
      photonController.directoryFresh &&
      photonController.observation?['tunnel_ready'] == true &&
      photonController.selected.isNotEmpty &&
      _published == _desired();

  void attach() {
    if (_attached) return;
    _attached = true;
    photonController.onServicesChanged = _refresh;
    photonController.onServicesInvalidated = _invalidate;
  }

  Map<String, dynamic> _profile(
    PhotonDirectory directory,
    Set<String> selected,
  ) => photonProxyProfile(
    directory: directory,
    selected: selected,
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
  );

  String? _desired() {
    final directory = photonController.directory;
    if (directory == null ||
        !photonController.directoryFresh ||
        photonController.selected.isEmpty) {
      return null;
    }
    return sha256
        .convert(
          utf8.encode(
            encodePhotonProfile(_profile(directory, photonController.selected)),
          ),
        )
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
      await _publish(directory, photonController.selected, create: true);
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

  Future<void> _refresh(PhotonDirectory directory, Set<String> selected) async {
    if (_managed() == null) return;
    if (selected.isEmpty ||
        photonController.observation?['tunnel_ready'] != true) {
      await _invalidate();
      return;
    }
    await _publish(directory, selected);
  }

  Future<void> _publish(
    PhotonDirectory directory,
    Set<String> selected, {
    bool create = false,
  }) async {
    final generated = _profile(directory, selected);
    final content = encodePhotonProfile(generated);
    final digest = sha256.convert(utf8.encode(content)).toString();
    final container = globalState.container;
    var profile = _managed();
    if (profile == null && !create) return;
    profile ??= Profile.normal(
      label: 'Photon',
    ).copyWith(url: photonProfileSource, autoUpdate: false);
    if (_profileDigest == digest && _published == digest) return;
    _published = null;
    final core = container.read(coreHandlerProvider);
    final saved = await profile.saveFile(
      Uint8List.fromList(utf8.encode(content)),
      validate: core.validateProfile,
    );
    if (!directory.fresh(DateTime.now())) {
      throw StateError('Photon service information expired while applying');
    }
    final latest =
        container.read(profilesProvider).getProfile(profile.id) ?? profile;
    container
        .read(profilesActionProvider.notifier)
        .putProfile(latest.copyWith(lastUpdateDate: saved.lastUpdateDate));
    _profileDigest = digest;
    _published = digest;
    _blockedProfileId = null;
    if (!create &&
        container.read(currentProfileProvider)?.url == photonProfileSource) {
      final applied = await container
          .read(setupActionProvider.notifier)
          .applyProfile(force: true, silence: true);
      if (!applied) {
        throw StateError('Photon proxy profile could not be applied');
      }
      await core.closeConnections();
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
