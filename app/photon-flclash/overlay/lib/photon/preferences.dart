import 'package:shared_preferences/shared_preferences.dart';

abstract interface class PhotonPreferences {
  Future<String?> configPath();
  Future<void> saveConfigPath(String value);
}

final class StoredPhotonPreferences implements PhotonPreferences {
  @override
  Future<String?> configPath() async => (await SharedPreferences.getInstance())
      .getString('photon.v1.config_path');

  @override
  Future<void> saveConfigPath(String value) async {
    if (!await (await SharedPreferences.getInstance()).setString(
      'photon.v1.config_path',
      value,
    )) {
      throw StateError('Photon config path could not be saved');
    }
  }
}
