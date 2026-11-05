import 'package:shared_preferences/shared_preferences.dart';

abstract interface class PhotonPreferences {
  Future<String?> configPath();
  Future<void> saveConfigPath(String value);
  Future<Set<String>> selection(String scope);
  Future<void> saveSelection(String scope, Set<String> selected);
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

  @override
  Future<Set<String>> selection(String scope) async =>
      (await SharedPreferences.getInstance())
          .getStringList('photon.v1.selected.$scope')
          ?.toSet() ??
      {};

  @override
  Future<void> saveSelection(String scope, Set<String> selected) async {
    if (!await (await SharedPreferences.getInstance()).setStringList(
      'photon.v1.selected.$scope',
      selected.toList()..sort(),
    )) {
      throw StateError('Photon proxy selection could not be saved');
    }
  }
}
