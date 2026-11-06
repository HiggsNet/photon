import 'dart:async';
import 'package:fl_clash/photon/controller.dart';
import 'package:fl_clash/photon/preferences.dart';
import 'package:fl_clash/photon/services.dart';
import 'package:flutter_test/flutter_test.dart';

import 'controller_test.dart' show FakeBackend;

Map<String, dynamic> directoryFixture({
  DateTime? now,
  String root = 'a',
  bool withdrawn = false,
}) {
  final at = now ?? DateTime.now().toUtc();
  return {
    'instance_id': 'fixture',
    'root_fingerprint': root * 64,
    'managed_zone': 'windows-test.catofes.',
    'revision': 7,
    'observed_at': at.toIso8601String(),
    'valid_until': at.add(const Duration(seconds: 5)).toIso8601String(),
    'adapter_name': 'Photon Test',
    'bypass_prefixes': ['192.0.2.1/32', 'fd42::/16'],
    'bypass_domains': ['gateway.example'],
    'services': [
      {
        'id': 'owner/services/socks5',
        'owner': 'owner.catofes.',
        'status': withdrawn ? 'withdrawn' : 'active',
        'endpoints': withdrawn
            ? []
            : [
                {
                  'id': '1' * 32,
                  'region': 'cn',
                  'address': 'fd42:1::20',
                  'port': 1080,
                },
                {
                  'id': '2' * 32,
                  'region': 'jp',
                  'address': 'fd42:1::21',
                  'port': 2080,
                },
              ],
      },
    ],
  };
}

class MemoryPhotonPreferences implements PhotonPreferences {
  String? savedPath;
  final selections = <String, Set<String>>{};
  @override
  Future<String?> configPath() async => savedPath;
  @override
  Future<void> saveConfigPath(String value) async {
    savedPath = value;
  }

  @override
  Future<Set<String>> selection(String scope) async => {...?selections[scope]};
  @override
  Future<void> saveSelection(String scope, Set<String> selected) async {
    selections[scope] = {...selected};
  }
}

void main() {
  test(
    'multiple selected SOCKS5 endpoints form stable manual, auto and balance groups',
    () {
      final directory = PhotonDirectory.fromJson(directoryFixture());
      Map<String, dynamic> build(Set<String> selected) => photonProxyProfile(
        directory: directory,
        selected: selected,
        now: DateTime.now(),
        splitRoutes: ['fd42::/16'],
        adapter: directory.adapterName,
        backendPath: r'C:\Photon\photon-windows.exe',
      );
      final profile = build({'2' * 32, '1' * 32});
      expect(profile['proxies'], hasLength(2));
      expect(
        encodePhotonProfile(profile),
        encodePhotonProfile(build({'1' * 32, '2' * 32})),
      );
      final groups = profile['proxy-groups'] as List;
      expect(groups.map((group) => group['type']), [
        'select',
        'url-test',
        'load-balance',
      ]);
      expect(groups.first['proxies'], isNot(contains('DIRECT')));
      final dns = profile['dns'] as Map;
      expect(dns['fake-ip-filter'], contains('gateway.example'));
      expect(
        (dns['nameserver-policy'] as Map)['gateway.example'],
        everyElement(endsWith('#DIRECT')),
      );
      final tun = profile['tun'] as Map;
      expect(tun['enable'], isFalse);
      expect(
        tun['route-exclude-address'],
        containsAll([
          '192.0.2.1/32',
          'fd42::/16',
          'fd42:1::20/128',
          'fd42:1::21/128',
        ]),
      );
      for (final proxy in profile['proxies'] as List) {
        expect(proxy['interface-name'], 'Photon Test');
      }
    },
  );

  test(
    'expired snapshots, invalid endpoint identities and empty selections cannot generate a profile',
    () {
      final directory = PhotonDirectory.fromJson(
        directoryFixture(
          now: DateTime.now().subtract(const Duration(seconds: 10)),
        ),
      );
      expect(
        () => photonProxyProfile(
          directory: directory,
          selected: {'1' * 32},
          now: DateTime.now(),
          splitRoutes: [],
          adapter: 'Photon Test',
          backendPath: 'backend',
        ),
        throwsStateError,
      );
      final invalid = directoryFixture();
      (invalid['services'] as List).first['endpoints'][0]['port'] = 0;
      expect(() => PhotonDirectory.fromJson(invalid), throwsFormatException);
      final active = PhotonDirectory.fromJson(directoryFixture());
      expect(
        () => photonProxyProfile(
          directory: active,
          selected: {},
          now: DateTime.now(),
          splitRoutes: [],
          adapter: active.adapterName,
          backendPath: 'backend',
        ),
        throwsStateError,
      );
    },
  );

  test(
    'config path and multi-selection survive restart, revocation removes selection, roots are isolated',
    () async {
      final prefs = MemoryPhotonPreferences();
      final backend = FakeBackend()..serviceSample = directoryFixture();
      var controller = PhotonController(
        createBackend: () => backend,
        preferences: prefs,
      );
      await controller.pickConfig(() async => '/test/config.yaml');
      await controller.start(allowed: true);
      await controller.toggleEndpoint('1' * 32, true);
      await controller.toggleEndpoint('2' * 32, true);
      expect(controller.selected, hasLength(2));
      await controller.close();
      controller.dispose();
      final restarted = FakeBackend()..serviceSample = directoryFixture();
      controller = PhotonController(
        createBackend: () => restarted,
        preferences: prefs,
      );
      await controller.initialize();
      expect(controller.configPath, '/test/config.yaml');
      await controller.start(allowed: true);
      expect(controller.selected, hasLength(2));
      restarted.serviceSample = directoryFixture(withdrawn: true);
      await controller.refresh();
      expect(controller.selected, isEmpty);
      restarted.serviceSample = directoryFixture(root: 'b');
      await controller.refresh();
      expect(controller.selected, isEmpty);
      await controller.close();
      controller.dispose();
    },
  );

  test(
    'directory expiry invalidates the proxy owner while leaving Photon connected',
    () async {
      final backend = FakeBackend()
        ..serviceSample = directoryFixture(
          now: DateTime.now().subtract(const Duration(milliseconds: 4000)),
        );
      final controller = PhotonController(createBackend: () => backend)
        ..selectConfig('/test/config.yaml');
      var invalidations = 0;
      controller.onServicesInvalidated = () async {
        invalidations++;
      };
      await controller.start(allowed: true);
      expect(controller.directoryFresh, isTrue);
      await Future<void>.delayed(const Duration(milliseconds: 1100));
      expect(controller.directory, isNull);
      expect(invalidations, 1);
      expect(controller.hasLease, isTrue);
      await controller.close();
      controller.dispose();
    },
  );

  test('queued expiry cannot invalidate a newer service snapshot', () async {
    final backend = FakeBackend()
      ..serviceSample = directoryFixture(
        now: DateTime.now().subtract(const Duration(milliseconds: 4000)),
      );
    final controller = PhotonController(createBackend: () => backend)
      ..selectConfig('/test/config.yaml');
    await controller.start(allowed: true);
    final gate = Completer<void>();
    backend.servicesWait = gate;
    final refreshing = controller.refresh();
    await Future<void>.delayed(const Duration(milliseconds: 1100));
    backend.serviceSample = directoryFixture();
    gate.complete();
    await refreshing;
    await Future<void>.delayed(Duration.zero);
    expect(controller.directoryFresh, isTrue);
    expect(controller.hasLease, isTrue);
    await controller.close();
    controller.dispose();
  });

  test('failed proxy cleanup still joins the Photon backend', () async {
    final backend = FakeBackend();
    final controller = PhotonController(createBackend: () => backend)
      ..selectConfig('/test/config.yaml');
    await controller.start(allowed: true);
    controller.onServicesInvalidated = () async {
      throw StateError('Core already exited');
    };
    await controller.stop();
    expect(controller.hasLease, isFalse);
    expect(backend.hasProcess, isFalse);
    await controller.close();
    controller.dispose();
  });

  test(
    'a selection refreshes expired authorization before applying intent',
    () async {
      final backend = FakeBackend()
        ..serviceSample = directoryFixture(
          now: DateTime.now().subtract(const Duration(milliseconds: 4000)),
        );
      final controller = PhotonController(createBackend: () => backend)
        ..selectConfig('/test/config.yaml');
      await controller.start(allowed: true);
      await Future<void>.delayed(const Duration(milliseconds: 1100));
      expect(controller.directoryFresh, isFalse);
      backend.serviceSample = directoryFixture();
      await controller.toggleEndpoint('1' * 32, true);
      expect(controller.selected, {'1' * 32});
      expect(controller.directoryFresh, isTrue);
      await controller.close();
      controller.dispose();
    },
  );
}
