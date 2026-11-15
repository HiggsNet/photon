import 'dart:async';

import 'package:fl_clash/photon/controller.dart';
import 'package:fl_clash/photon/preferences.dart';
import 'package:fl_clash/photon/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:yaml/yaml.dart';

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
  @override
  Future<String?> configPath() async => savedPath;
  @override
  Future<void> saveConfigPath(String value) async {
    savedPath = value;
  }
}

Map<String, dynamic> anycastDirectoryFixture({bool local = true}) => {
  ...directoryFixture(),
  'services': [
    for (var node = 1; node <= 3; node++)
      {
        'id': 'node-$node/services/socks5',
        'owner': 'node-$node.catofes.',
        'status': 'active',
        'endpoints': [
          {
            'id': (node * 3).toRadixString(16).padLeft(32, '0'),
            'region': 'global',
            'address': 'fd42:ffff::1',
            'port': 3128,
          },
          {
            'id': (node * 3 + 1).toRadixString(16).padLeft(32, '0'),
            'region': 'jp',
            'address': 'fd42:ff01::1',
            'port': 3128,
          },
          if (local)
            {
              'id': (node * 3 + 2).toRadixString(16).padLeft(32, '0'),
              'region': 'local',
              'address': 'fd42:1::$node',
              'port': 3128,
            },
        ],
      },
  ],
};

void main() {
  test(
    'proxy injection merges Anycast destinations and retains local exits',
    () {
      final directory = PhotonDirectory.fromJson(anycastDirectoryFixture());
      expect(directory.endpoints, hasLength(9));
      expect(directory.proxyEndpoints, hasLength(5));
      for (final template in <Map<String, dynamic>?>[
        null,
        {
          'rules': ['MATCH,Photon'],
        },
      ]) {
        final profile = photonProxyProfile(
          directory: directory,
          now: DateTime.now(),
          splitRoutes: [],
          adapter: directory.adapterName,
          backendPath: 'backend',
          template: template,
        );
        final proxies = template == null
            ? profile['proxies'] as List
            : (profile['proxy-providers'] as Map)['photon-services']['payload']
                  as List;
        final names = proxies.map((proxy) => proxy['name']).toList();
        expect(names, [
          'Anycast / global / [fd42:ffff::1]:3128',
          'Anycast / jp / [fd42:ff01::1]:3128',
          'node-1.catofes / local / [fd42:1::1]:3128',
          'node-2.catofes / local / [fd42:1::2]:3128',
          'node-3.catofes / local / [fd42:1::3]:3128',
        ]);
        expect(
          proxies.map((proxy) => proxy['interface-name']),
          everyElement('Photon Test'),
        );
        expect(
          (profile['tun'] as Map)['route-exclude-address'],
          containsAll([
            'fd42:ffff::1/128',
            'fd42:ff01::1/128',
            'fd42:1::1/128',
            'fd42:1::2/128',
            'fd42:1::3/128',
          ]),
        );
        for (final group in profile['proxy-groups'] as List) {
          if (template == null) {
            final members = group['proxies'] as List;
            expect(members.where((name) => name == names.first), hasLength(1));
          } else {
            expect(group['use'], ['photon-services']);
          }
        }
      }
    },
  );

  test('shared proxy profiles survive publisher changes and disappear only after the last valid publication', () {
    Map<String, dynamic> render(Map<String, dynamic> data) {
      final directory = PhotonDirectory.fromJson(data);
      return photonProxyProfile(
        directory: directory,
        now: DateTime.now(),
        splitRoutes: [],
        adapter: directory.adapterName,
        backendPath: 'backend',
        template: {
          'rules': ['MATCH,Photon'],
        },
      );
    }

    final data = anycastDirectoryFixture(local: false);
    final before = encodePhotonProfile(render(data));
    final services = data['services'] as List;
    data['services'] = services.reversed.toList();
    for (final service in services) {
      service['endpoints'] = (service['endpoints'] as List).reversed.toList();
    }
    expect(encodePhotonProfile(render(data)), before);
    services.first['status'] = 'withdrawn';
    services.first['endpoints'] = [];
    services[1]['status'] = 'unauthorized';
    services[1]['endpoints'] = [];
    expect(encodePhotonProfile(render(data)), before);
    services.last['status'] = 'untrusted';
    services.last['endpoints'] = [];
    expect(PhotonDirectory.fromJson(data).proxyEndpoints, isEmpty);
    expect(() => render(data), throwsStateError);
  });

  test(
    'Anycast merging retains different addresses and ports in the same region',
    () {
      final data = anycastDirectoryFixture(local: false);
      final services = data['services'] as List;
      services[1]['endpoints'][0]['port'] = 4128;
      services[2]['endpoints'][0]['address'] = 'fd42:ffff::2';
      final endpoints = PhotonDirectory.fromJson(data).proxyEndpoints;
      expect(endpoints, hasLength(4));
      expect(
        endpoints.where((endpoint) => endpoint.region == 'global'),
        hasLength(3),
      );
      expect(endpoints.map((endpoint) => endpoint.name).toSet(), hasLength(4));
    },
  );

  test(
    'a gateway IP or hostname change leaves the socket-routed profile stable',
    () {
      final now = DateTime.now();
      Map<String, dynamic> profile(String gateway, String host) {
        final directory = PhotonDirectory.fromJson({
          ...directoryFixture(now: now),
          'underlay_routing': true,
          'overlay_prefixes': ['fd42::/16'],
          'bypass_prefixes': [gateway, 'fd42::/16'],
          'bypass_domains': [host],
        });
        return photonProxyProfile(
          directory: directory,
          now: now,
          splitRoutes: [],
          adapter: directory.adapterName,
          backendPath: 'backend',
        );
      }

      final before = profile('192.0.2.1/32', 'gateway.example');
      final after = profile('2001:db8::2/128', 'replacement.example');
      expect(after, before);
      expect(
        (after['tun'] as Map)['route-exclude-address'],
        contains('fd42::/16'),
      );
      expect(encodePhotonProfile(after), isNot(contains('2001:db8::2')));
      expect((after['dns'] as Map)['fake-ip-filter'], isEmpty);
    },
  );

  test('a user policy keeps its rules and can use all Photon endpoints', () {
    final directory = PhotonDirectory.fromJson(directoryFixture());
    final template = Map<String, dynamic>.from(
      loadYaml('''
proxy-groups:
  - {name: Nodes, type: select, proxies: [Photon, DIRECT]}
rules:
  - RULE-SET,google,Nodes
  - MATCH,DIRECT
rule-providers:
  google:
    type: inline
    behavior: domain
    payload: ['+.google.example']
''') as Map,
    );
    final profile = photonProxyProfile(
      directory: directory,
      now: DateTime.now(),
      splitRoutes: [],
      adapter: directory.adapterName,
      backendPath: 'backend',
      template: template,
    );
    expect(
      (profile['rules'] as List).skipWhile(
        (rule) => rule != 'RULE-SET,google,Nodes',
      ),
      template['rules'],
    );
    expect(profile['rule-providers'], template['rule-providers']);
    final providers = profile['proxy-providers'] as Map;
    expect(providers['photon-services']['payload'], hasLength(2));
    final offline = blockedPhotonProfile(profile);
    expect(offline['rules'], profile['rules']);
    expect(
      (offline['proxy-groups'] as List).first,
      (template['proxy-groups'] as List).first,
    );
    expect((offline['proxy-groups'] as List)[1]['proxies'], ['REJECT']);
    expect((offline['proxy-providers'] as Map)['photon-services']['payload'], [
      {'name': 'Photon Offline', 'type': 'reject'},
    ]);
    expect(encodePhotonProfile(profile), contains('RULE-SET,google,Nodes'));
    expect(template.containsKey('proxy-providers'), isFalse);
  });

  test('all authorized SOCKS5 endpoints form stable manual, auto and balance groups', () {
    final directory = PhotonDirectory.fromJson(directoryFixture());
    Map<String, dynamic> build(PhotonDirectory directory) => photonProxyProfile(
      directory: directory,
      now: DateTime.now(),
      splitRoutes: ['fd42::/16'],
      adapter: directory.adapterName,
      backendPath: r'C:\Photon\photon-windows.exe',
    );
    final shuffled = directoryFixture();
    final entry = (shuffled['services'] as List).first as Map;
    entry['endpoints'] = (entry['endpoints'] as List).reversed.toList();
    final profile = build(directory);
    expect(profile['proxies'], hasLength(2));
    expect(
      encodePhotonProfile(profile),
      encodePhotonProfile(build(PhotonDirectory.fromJson(shuffled))),
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
  });

  test('expired snapshots, invalid endpoint identities and empty directories cannot generate a profile', () {
    final directory = PhotonDirectory.fromJson(
      directoryFixture(
        now: DateTime.now().subtract(const Duration(seconds: 10)),
      ),
    );
    expect(
      () => photonProxyProfile(
        directory: directory,
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
    final empty = PhotonDirectory.fromJson(directoryFixture(withdrawn: true));
    expect(
      () => photonProxyProfile(
        directory: empty,
        now: DateTime.now(),
        splitRoutes: [],
        adapter: empty.adapterName,
        backendPath: 'backend',
      ),
      throwsStateError,
    );
  });

  test('config path persists and refresh publishes the current authorized directory', () async {
    final prefs = MemoryPhotonPreferences();
    final backend = FakeBackend()..serviceSample = directoryFixture();
    var controller = PhotonController(
      createBackend: () => backend,
      preferences: prefs,
    );
    await controller.pickConfig(() async => '/test/config.yaml');
    await controller.start(allowed: true);
    expect(controller.directory?.endpoints, hasLength(2));
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
    expect(controller.directory?.endpoints, hasLength(2));
    restarted.serviceSample = directoryFixture(withdrawn: true);
    await controller.refresh();
    expect(controller.directory?.endpoints, isEmpty);
    restarted.serviceSample = directoryFixture(root: 'b');
    await controller.refresh();
    expect(controller.directory?.endpoints, hasLength(2));
    expect(controller.directory?.rootFingerprint, 'b' * 64);
    await controller.close();
    controller.dispose();
  });

  test('directory expiry invalidates the proxy owner while leaving Photon connected', () async {
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
  });

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
}
