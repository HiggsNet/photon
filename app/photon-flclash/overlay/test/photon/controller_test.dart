import 'dart:async';

import 'package:fl_clash/photon/backend.dart';
import 'package:fl_clash/photon/controller.dart';
import 'package:flutter_test/flutter_test.dart';

class FakeBackend implements PhotonBackend {
  final calls = <String>[];
  final exited = Completer<int>();
  Completer<void>? starting;
  StateError? statusError;
  Map<String, dynamic> sample = {'running': true, 'tunnel_ready': true};
  bool failStop = false;
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
    if (statusError != null) throw statusError!;
    return sample;
  }

  @override
  Future<void> stop() async {
    calls.add('stop');
    if (failStop) throw StateError('Exit unconfirmed');
    hasProcess = false;
    if (!exited.isCompleted) exited.complete(0);
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

  test(
    'IPC failure clears observation, joins the backend and allows explicit restart',
    () async {
      await controller.start(allowed: true);
      backends.single.statusError = StateError('IPC lost');
      await controller.refresh();
      expect(controller.observation, isNull);
      expect(controller.error, isNotNull);
      expect(controller.hasLease, isFalse);
      await controller.start(allowed: true);
      expect(backends, hasLength(2));
    },
  );

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
