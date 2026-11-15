import 'package:fl_clash/common/common.dart';
import 'package:fl_clash/models/models.dart';

import 'services.dart';

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
