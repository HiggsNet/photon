import 'dart:io';

import 'package:fl_clash/common/portable_data.dart';
import 'package:fl_clash/photon/preferences.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:path/path.dart' as path;
import 'package:shared_preferences/shared_preferences.dart';

import '../helpers/app_paths.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  late Directory root;
  late Directory executable;
  late Directory support;

  setUp(() async {
    root = await Directory.systemTemp.createTemp('photon-storage-');
    executable = await Directory(path.join(root.path, 'program')).create();
    support = await Directory(path.join(root.path, 'appdata')).create();
    SharedPreferences.setMockInitialValues({});
  });

  tearDown(() => root.delete(recursive: true));

  Future<Directory> resolve() => windowsDataDirectory(
    executableDirectory: executable,
    supportDirectory: support,
  );

  test(
    'new portable uses EXE data and marker keeps it independent of AppData',
    () async {
      final first = await resolve();
      expect(first.path, path.join(executable.path, 'data'));
      await File(path.join(support.path, 'config.yaml')).writeAsString('old');
      expect((await resolve()).path, first.path);
    },
  );

  test(
    'installed build uses AppData even with portable data present',
    () async {
      await resolve();
      await File(path.join(executable.path, 'unins000.exe')).writeAsString('');
      expect((await resolve()).path, support.path);
    },
  );

  test(
    'existing settings stay visible rather than silently starting fresh',
    () async {
      await File(path.join(support.path, 'shared_preferences.json'))
          .writeAsString('{}');
      expect((await resolve()).path, support.path);
    },
  );

  test('managed selection survives moving the entire data directory', () async {
    final old = await Directory(path.join(root.path, 'old')).create();
    await useAppPaths(old);
    final preferences = StoredPhotonPreferences();
    await preferences.saveConfigPath(
      path.join(old.path, 'photon', 'photon.yaml'),
    );
    expect(
      (await SharedPreferences.getInstance()).getString(
        'photon.v1.config_path',
      ),
      path.join('photon', 'photon.yaml'),
    );
    final moved = await Directory(path.join(root.path, 'moved')).create();
    await useAppPaths(moved);
    expect(
      await preferences.configPath(),
      path.join(moved.path, 'photon', 'photon.yaml'),
    );
  });

  test(
    'external configuration remains an explicit absolute reference',
    () async {
      await useAppPaths(support);
      final preferences = StoredPhotonPreferences();
      final external = path.join(executable.path, 'external.yaml');
      await preferences.saveConfigPath(external);
      expect(await preferences.configPath(), external);
    },
  );
}
