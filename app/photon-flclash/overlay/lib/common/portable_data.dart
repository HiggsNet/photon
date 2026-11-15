import 'dart:io';

import 'package:path/path.dart' as path;
import 'package:path_provider/path_provider.dart';

Future<Directory> photonApplicationDataDirectory() async {
  final support = await getApplicationSupportDirectory();
  if (!Platform.isWindows) return support;
  return windowsDataDirectory(
    executableDirectory: File(Platform.resolvedExecutable).parent,
    supportDirectory: support,
  );
}

Future<Directory> windowsDataDirectory({
  required Directory executableDirectory,
  required Directory supportDirectory,
}) async {
  if (await File(path.join(executableDirectory.path, 'unins000.exe'))
      .exists()) {
    return supportDirectory;
  }
  final portable = Directory(path.join(executableDirectory.path, 'data'));
  final marker = File(path.join(portable.path, '.photon-portable'));
  if (!await marker.exists()) {
    // Existing installations keep their settings and identity until explicitly copied.
    for (final name in [
      'config.yaml',
      'database.sqlite',
      'shared_preferences.json',
    ]) {
      if (await File(path.join(supportDirectory.path, name)).exists()) {
        return supportDirectory;
      }
    }
    await portable.create(recursive: true);
    await marker.writeAsString('1\n', flush: true);
  }
  return portable;
}
