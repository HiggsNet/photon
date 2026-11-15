import 'dart:io';

import 'package:fl_clash/common/path.dart';
import 'package:path/path.dart' as path;
import 'package:shared_preferences/shared_preferences.dart';

abstract interface class PhotonPreferences {
  Future<String?> configPath();
  Future<void> saveConfigPath(String value);
}

final class StoredPhotonPreferences implements PhotonPreferences {
  @override
  Future<String?> configPath() async {
    final value = (await SharedPreferences.getInstance()).getString(
      'photon.v1.config_path',
    );
    final root = await appPath.homeDirPath;
    if (value != null) return path.normalize(path.join(root, value));
    final managed = path.join(root, 'photon', 'photon.yaml');
    return await File(managed).exists() ? managed : null;
  }

  @override
  Future<void> saveConfigPath(String value) async {
    final root = await appPath.homeDirPath;
    final stored = path.isWithin(root, value)
        ? path.relative(value, from: root)
        : value;
    if (!await (await SharedPreferences.getInstance()).setString(
      'photon.v1.config_path',
      stored,
    )) {
      throw StateError('Photon config path could not be saved');
    }
  }
}
