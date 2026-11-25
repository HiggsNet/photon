import 'dart:io';

import 'package:fl_clash/common/common.dart';
import 'package:fl_clash/models/models.dart';
import 'package:flutter/foundation.dart' show compute;

import 'services.dart';

Future<Map<String, dynamic>> readPhotonProfile(int profileId) async {
  final file = File(await appPath.getProfilePath(profileId.toString()));
  return compute(_decodePhotonProfile, await file.readAsString());
}

Map<String, dynamic> _decodePhotonProfile(String content) {
  final profile = loadPlainYaml(content);
  if (profile is! Map<String, dynamic>) {
    throw const FormatException(
      'The generated Photon profile must be a YAML mapping',
    );
  }
  return profile;
}

/// Keep the normal FlClash composition order, then restore only the required
/// Photon safeguards. The stored profile owns their metadata even when offline.
Future<RealProfile> makePhotonProfileTask(MakeRealProfileState data) async {
  final composed = await makeRealProfileTask(data);
  final profile = protectPhotonProxyProfile(
    Map<String, dynamic>.from(loadPlainYaml(composed.yaml) as Map),
    source: data.rawConfig,
    stripMetadata: true,
  );
  final content = await encodeYamlTask(profile);
  return (yaml: content, md5: content.toMd5(), counts: configCountsOf(profile));
}
