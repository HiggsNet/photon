import 'dart:async';
import 'dart:io';

import 'package:fl_clash/photon/backend.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:path/path.dart' as path;

void main() {
  late Directory directory;
  late File config;
  late File marker;
  late PhotonProcess backend;

  setUp(() async {
    directory = await Directory.systemTemp.createTemp('photon-ipc-');
    marker = File(path.join(directory.path, 'calls.txt'));
    config = File(path.join(directory.path, 'config.yaml'));
    backend = PhotonProcess(
      executable: Platform.environment['PHOTON_DART'] ?? 'dart',
      arguments: [File('test/photon/fixtures/backend.dart').absolute.path],
      timeout: const Duration(seconds: 5),
    );
  });

  Future<void> configure(String mode) => config.writeAsString(
    'fixture: $mode\nstate:\n  path: ${path.join(directory.path, 'identity.db')}\nmarker: ${marker.path}\n',
  );

  tearDown(() async {
    await backend.stop();
    await directory.delete(recursive: true);
  });

  test(
    'private framed session checks startup and serializes concurrent calls',
    () async {
      await configure('normal');
      await backend.start(config.path);
      final samples = await Future.wait([backend.status(), backend.services()]);
      expect(samples.every((sample) => sample['tunnel_ready'] == true), isTrue);
      await backend.stop();
      expect(backend.hasProcess, isFalse);
      expect(await marker.readAsLines(), [
        'status',
        'services',
        'stop',
        'exited',
      ]);
    },
  );

  for (final mode in ['wrong-pid', 'wrong-config', 'wrong-path', 'oversized']) {
    test('rejects $mode and joins the child', () async {
      await configure(mode);
      await expectLater(backend.start(config.path), throwsFormatException);
      expect(backend.hasProcess, isFalse);
    });
  }

  test(
    'relative identity path is resolved against YAML before handshake',
    () async {
      await config.writeAsString(
        'fixture: normal\nstate:\n  path: identity.db\n',
      );
      await backend.start(config.path);
      expect(backend.hasProcess, isTrue);
      await backend.stop();
    },
  );

  test('crashed child cannot leave stale usable state', () async {
    await configure('crash');
    await backend.start(config.path);
    await expectLater(backend.status(), throwsFormatException);
    expect(await backend.exitCode, 23);
    await backend.stop();
    expect(backend.hasProcess, isFalse);
  });

  for (final recover in [true, false]) {
    test(
      recover
          ? 'late status reply recovers the same child'
          : 'stop reclaims a child stuck on status',
      () async {
        await configure('timeout');
        backend = PhotonProcess(
          executable: Platform.environment['PHOTON_DART'] ?? 'dart',
          arguments: [File('test/photon/fixtures/backend.dart').absolute.path],
          timeout: const Duration(seconds: 1),
          shutdownTimeout: const Duration(seconds: 1),
        );
        await backend.start(config.path);
        final exit = backend.exitCode;
        await expectLater(backend.status(), throwsA(isA<TimeoutException>()));
        expect(backend.exitCode, same(exit));
        if (recover) {
          await expectLater(backend.status(), throwsA(isA<TimeoutException>()));
          expect(await marker.readAsLines(), ['status']);
          await File('${marker.path}.release').create();
          expect((await backend.status())['tunnel_ready'], isTrue);
          expect((await backend.services())['running'], isTrue);
          expect(backend.exitCode, same(exit));
        }
        await backend.stop().timeout(const Duration(seconds: 5));
        expect(backend.hasProcess, isFalse);
        if (recover) {
          expect(await marker.readAsLines(), [
            'status',
            'services',
            'stop',
            'exited',
          ]);
        }
      },
    );
  }
}
