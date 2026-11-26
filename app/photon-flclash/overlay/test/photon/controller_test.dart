import 'dart:async';

import 'package:fl_clash/photon/backend.dart';
import 'package:fl_clash/photon/controller.dart';
import 'package:fl_clash/photon/preferences.dart';
import 'package:flutter_test/flutter_test.dart';

class FakeBackend implements PhotonBackend {
  final calls = <String>[];
  final exited = Completer<int>();
  Completer<void>? starting;
  Completer<void>? servicesWait;
  Object? statusError;
  Exception? servicesError;
  Map<String, dynamic> sample = {'running': true, 'tunnel_ready': true};
  bool failStop = false;
  Map<String, dynamic>? serviceSample;
  @override
  bool hasProcess = false;
  @override
  Future<int> get exitCode => exited.future;
  @override
  Future<void> start(String configPath) async {
    calls.add('start');
    hasProcess = true;
    await starting?.future;
  }

  @override
  Future<Map<String, dynamic>> status() async {
    calls.add('status');
    if (statusError case final Exception error) throw error;
    if (statusError case final Error error) throw error;
    return sample;
  }

  @override
  Future<Map<String, dynamic>> services() async {
    await servicesWait?.future;
    if (servicesError case final error?) throw error;
    final now = DateTime.now().toUtc();
    return serviceSample ??
        {
          'instance_id': 'test',
          'root_fingerprint': 'a' * 64,
          'managed_zone': 'windows-test.catofes.',
          'revision': 1,
          'observed_at': now.toIso8601String(),
          'valid_until': now.add(const Duration(seconds: 5)).toIso8601String(),
          'services': [],
        };
  }

  @override
  Future<void> stop() async {
    calls.add('stop');
    if (failStop) throw StateError('Exit unconfirmed');
    hasProcess = false;
    if (!exited.isCompleted) exited.complete(0);
  }
}

class FailingPreferences implements PhotonPreferences {
  @override
  Future<String?> configPath() async => null;

  @override
  Future<void> saveConfigPath(String value) async {
    throw StateError('Storage is unavailable');
  }
}

void main() {
  late List<FakeBackend> backends;
  late PhotonController controller;
  setUp(() {
    backends = [];
    controller = PhotonController(
      createBackend: () {
        final backend = FakeBackend();
        backends.add(backend);
        return backend;
      },
    );
    controller.selectConfig('/test/config.yaml');
  });
  tearDown(() async {
    await controller.close();
    controller.dispose();
  });

  test(
    'failed persistence retains the original active configuration',
    () async {
      final owner = PhotonController(
        createBackend: FakeBackend.new,
        preferences: FailingPreferences(),
      )..selectConfig('/original/config.yaml');
      await owner.pickConfig(() async => '/copy/config.yaml');
      expect(owner.configPath, '/original/config.yaml');
      expect(owner.error, isA<StateError>());
      await owner.close();
      owner.dispose();
    },
  );

  test('safe mode does not create a backend', () async {
    await controller.start(allowed: false);
    expect(backends, isEmpty);
    expect(controller.hasLease, isFalse);
  });

  test('page listeners can detach without stopping the backend', () async {
    void listener() {}
    controller.addListener(listener);
    await controller.start(allowed: true);
    controller.removeListener(listener);
    expect(controller.observation?['tunnel_ready'], isTrue);
    expect(backends.single.calls, ['start', 'status']);
    await controller.stop();
    expect(controller.hasLease, isFalse);
    expect(controller.observation, isNull);
  });

  test(
    'proxy publication and cleanup failures keep the Photon lease',
    () async {
      const problem = FormatException('Invalid proxy template');
      controller.onServicesChanged = (_) async => throw problem;
      controller.onServicesInvalidated = () async {
        throw StateError('Could not pause the Photon proxy profile');
      };

      await controller.start(allowed: true);
      expect(controller.hasLease, isTrue);
      expect(controller.observation?['tunnel_ready'], isTrue);
      expect(controller.directory, isNull);
      expect(controller.error.toString(), contains(problem.message));
      expect(controller.error.toString(), contains('Could not pause'));
      expect(backends.single.calls, ['start', 'status']);

      controller.onServicesChanged = null;
      controller.onServicesInvalidated = null;
      await controller.refresh();
      expect(controller.error, isNull);
      expect(controller.directoryFresh, isTrue);
      expect(backends.single.calls, ['start', 'status', 'status']);
    },
  );

  test(
    'terminal close during startup joins the child and prohibits a restart',
    () async {
      final gate = Completer<void>();
      controller.dispose();
      controller = PhotonController(
        createBackend: () {
          final backend = FakeBackend()..starting = gate;
          backends.add(backend);
          return backend;
        },
      )..selectConfig('/test/config.yaml');
      final starting = controller.start(allowed: true);
      await Future<void>.delayed(Duration.zero);
      final closing = controller.close();
      gate.complete();
      await Future.wait([starting, closing]);
      await controller.start(allowed: true);
      expect(backends.single.calls, ['start', 'stop']);
      expect(controller.hasLease, isFalse);
    },
  );

  test('temporary status failures retain a verified directory and recover the same backend', () async {
    var invalidations = 0;
    controller.onServicesInvalidated = () async {
      invalidations++;
    };
    await controller.start(allowed: true);
    expect(controller.directoryFresh, isTrue);
    final backend = backends.single;
    for (final error in [
      TimeoutException('Photon control request timed out'),
      const PhotonControlException('unavailable', 'status is unavailable'),
    ]) {
      backend.statusError = error;
      await controller.refresh();
      expect(controller.error, same(error));
      expect(controller.observation, isNull);
      expect(controller.directoryFresh, isTrue);
      expect(controller.hasLease, isTrue);
      expect(backend.calls, isNot(contains('stop')));
    }
    expect(invalidations, 0);
    backend.statusError = null;
    await controller.refresh();
    expect(backends, hasLength(1));
    expect(controller.observation?['tunnel_ready'], isTrue);
    expect(controller.directoryFresh, isTrue);
    expect(controller.error, isNull);
  });

  test(
    'service read timeout retains the directory until authorization expires',
    () async {
      await controller.start(allowed: true);
      final directory = controller.directory;
      final backend = backends.single;
      backend.servicesError = TimeoutException('service read timed out');
      await controller.refresh();
      expect(controller.directory, same(directory));

      final now = DateTime.now().toUtc();
      backend.servicesError = null;
      backend.serviceSample = {
        ...await backend.services(),
        'observed_at': now
            .subtract(const Duration(seconds: 2))
            .toIso8601String(),
        'valid_until': now
            .subtract(const Duration(seconds: 1))
            .toIso8601String(),
      };
      await controller.refresh();
      expect(controller.directory, isNull);
    },
  );

  test('IPC failure clears observation, joins the backend and allows explicit restart', () async {
    await controller.start(allowed: true);
    backends.single.statusError = StateError('IPC lost');
    await controller.refresh();
    expect(controller.observation, isNull);
    expect(controller.error, isNotNull);
    expect(controller.hasLease, isFalse);
    await controller.start(allowed: true);
    expect(backends, hasLength(2));
  });

  test(
    'unconfirmed cleanup retains ownership and blocks another launch',
    () async {
      await controller.start(allowed: true);
      backends.single.failStop = true;
      await controller.stop();
      await controller.start(allowed: true);
      expect(backends, hasLength(1));
      expect(controller.hasLease, isTrue);
      expect(controller.error, isNotNull);
      backends.single.failStop = false;
      await controller.stop();
      expect(controller.hasLease, isFalse);
    },
  );
}
