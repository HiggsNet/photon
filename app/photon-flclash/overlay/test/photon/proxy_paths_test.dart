import 'package:fl_clash/photon/backend.dart';
import 'package:fl_clash/photon/controller.dart';
import 'package:fl_clash/photon/proxy_bridge.dart';
import 'package:fl_clash/photon/proxy_paths_view.dart';
import 'package:fl_clash/photon/services.dart';
import 'package:fl_clash/providers/app.dart';
import 'package:fl_clash/widgets/widgets.dart' show TextFormField;
import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../helpers/test_app.dart';
import 'controller_test.dart' show FakeBackend;
import 'services_test.dart' show directoryFixture;

class _PathBackend extends FakeBackend implements PhotonPathBackend {
  final requests = <Map<String, dynamic>>[];
  Map<String, dynamic>? path;
  Map<String, dynamic>? probe;

  @override
  Future<Map<String, dynamic>> proxyV2(Map<String, dynamic> request) async {
    requests.add(request);
    switch (request['action']) {
      case 'create':
      case 'update':
        path = {
          'name': request['name'],
          'address': '127.0.0.1',
          'port': 10801,
          'hops': request['hops'],
        };
      case 'delete':
        path = null;
      case 'probe':
        probe = {
          'name': request['name'],
          'result': {'ok': true, 'elapsed_ms': 52},
        };
    }
    return {
      'routes': [?path],
      'directory': {'exits': [], 'relays': []},
      'probe': ?probe,
    };
  }
}

void main() {
  testWidgets('path page creates, includes and probes a saved path', (
    tester,
  ) async {
    SharedPreferences.setMockInitialValues({});
    final backend = _PathBackend();
    final controller = PhotonController(createBackend: () => backend)
      ..selectConfig('/test/photon.yaml');
    final bridge = PhotonProxyBridge(controller: controller);
    await controller.start(allowed: true);
    try {
      await tester.pumpWidget(
        TestApp(
          locale: const Locale('en'),
          overrides: [safeModeProvider.overrideWith((_) => false)],
          child: PhotonProxyPathsView(controller: controller, bridge: bridge),
        ),
      );
      await tester.pumpAndSettle();
      await tester.tap(find.text('New path'));
      await tester.pumpAndSettle();
      await tester.enterText(find.byType(TextFormField).at(0), 'home');
      await tester.enterText(
        find.byType(TextFormField).at(1),
        'gateway.catofes./exit',
      );
      await tester.tap(find.text('Save'));
      await tester.pumpAndSettle();
      expect(
        backend.requests.any(
          (entry) => entry['action'] == 'create' && entry['name'] == 'home',
        ),
        isTrue,
      );
      expect(find.text('127.0.0.1:10801'), findsOneWidget);
      await tester.tap(find.text('Include in Photon profile'));
      await tester.pumpAndSettle();
      expect((await bridge.includedPaths()), {'home'});
      await tester.tap(find.text('Test'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Connectivity'));
      await tester.pumpAndSettle();
      expect(find.text('52 ms'), findsOneWidget);
    } finally {
      await tester.pumpWidget(const SizedBox());
      await controller.close();
      controller.dispose();
    }
  });

  test(
    'appended paths use stable loopback ports and are blocked when removed',
    () {
      final template = <String, dynamic>{
        'proxies': [
          {
            'name': 'Manual',
            'type': 'socks5',
            'server': '127.0.0.1',
            'port': 3080,
          },
        ],
        'rules': ['MATCH,Photon Paths'],
      };
      Map<String, dynamic> fixture({required bool include}) => {
        ...directoryFixture(withdrawn: true),
        'proxy_v2_routes': [
          if (include)
            {
              'name': 'home',
              'address': '127.0.0.1',
              'port': 10801,
              'hops': ['gateway@h2l4'],
            },
        ],
      };
      final live = PhotonDirectory.fromJson(fixture(include: true));
      final profile = photonProxyProfile(
        directory: live,
        now: DateTime.now(),
        splitRoutes: [],
        adapter: live.adapterName,
        backendPath: 'photon-windows.exe',
        template: template,
        includedPaths: {'home'},
      );
      final proxies = (profile['proxies'] as List).whereType<Map>();
      final path = proxies.singleWhere(
        (proxy) => proxy['name'] == 'Photon Path / home',
      );
      expect(path['server'], '127.0.0.1');
      expect(path['port'], 10801);
      expect(path['udp'], true);
      expect(path, isNot(contains('interface-name')));
      expect(unauthorizedPhotonProxies(profile, live), isEmpty);
      final removed = PhotonDirectory.fromJson(fixture(include: false));
      final blocked = unauthorizedPhotonProxies(profile, removed);
      expect(blocked, {'Photon Path / home'});
      final restricted = restrictPhotonProxies(profile, blocked);
      expect(
        (restricted['proxies'] as List).first,
        (template['proxies'] as List).first,
      );
      expect((restricted['proxies'] as List).last, {
        'name': 'Photon Path / home',
        'type': 'reject',
      });
      expect(blockedPhotonProfile(profile)['proxies'], restricted['proxies']);
    },
  );
}
