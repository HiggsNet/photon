import 'package:fl_clash/photon/backend.dart';
import 'package:fl_clash/photon/controller.dart';
import 'package:fl_clash/photon/proxy_bridge.dart';
import 'package:fl_clash/photon/proxy_paths_view.dart';
import 'package:fl_clash/photon/services.dart';
import 'package:fl_clash/providers/app.dart';
import 'package:fl_clash/widgets/widgets.dart' show IconButton, TextFormField;
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
  List<Map<String, dynamic>> relays = [];
  List<Map<String, dynamic>> exits = [];

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
      'directory': {'exits': exits, 'relays': relays},
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
          overrides: [
            safeModeProvider.overrideWith((_) => false),
            isMobileViewProvider.overrideWith((_) => false),
          ],
          child: PhotonProxyPathsView(controller: controller, bridge: bridge),
        ),
      );
      await tester.pumpAndSettle();
      expect(find.text('Apply Photon profile'), findsNothing);
      await tester.tap(find.text('New path'));
      await tester.pumpAndSettle();
      expect(
        tester.getSize(find.byType(TextFormField).first).width,
        greaterThan(380),
      );
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

  testWidgets('relay actions stay together and edit the matching relay', (
    tester,
  ) async {
    SharedPreferences.setMockInitialValues({});
    final backend = _PathBackend()
      ..relays = [
        {
          'zone': 'directory-relay.example.',
          'endpoint': 'relay',
          'links': ['h26'],
        },
        {'zone': 'z-pek.catofes.', 'endpoint': 'relay'},
        {'zone': 'n-hkg.example.', 'endpoint': 'relay'},
      ]
      ..exits = [
        {'zone': 'a-lax.example.', 'endpoint': 'backup'},
        {'zone': 'gateway.catofes.', 'endpoint': 'exit'},
      ];
    final controller = PhotonController(createBackend: () => backend)
      ..selectConfig('/test/photon.yaml');
    final bridge = PhotonProxyBridge(controller: controller);
    await controller.start(allowed: true);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetDevicePixelRatio);
    addTearDown(tester.view.resetPhysicalSize);

    Finder button(String tooltip) => find.byWidgetPredicate(
      (widget) => widget is IconButton && widget.tooltip == tooltip,
    );

    try {
      tester.view.physicalSize = const Size(428, 850);
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
      await tester.tap(find.text('Add relay'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Add relay'));
      await tester.pumpAndSettle();

      final fields = find.byType(TextFormField);
      final up = button('Move up');
      final down = button('Move down');
      final remove = button('Remove relay');
      for (final (width, inline) in [(428.0, true), (320.0, false)]) {
        tester.view.physicalSize = Size(width, 850);
        await tester.pumpAndSettle();
        final fieldCenter = tester.getCenter(fields.at(1));
        final upCenter = tester.getCenter(up.first);
        final downCenter = tester.getCenter(down.first);
        final removeCenter = tester.getCenter(remove.first);
        final addCenter = tester.getCenter(find.text('Add relay'));
        expect(addCenter.dy, lessThan(fieldCenter.dy));
        expect(addCenter.dx, greaterThan(fieldCenter.dx));
        expect(upCenter.dy, downCenter.dy);
        expect(downCenter.dy, removeCenter.dy);
        expect(removeCenter.dx, greaterThan(downCenter.dx));
        expect(
          upCenter.dy,
          inline ? fieldCenter.dy : greaterThan(fieldCenter.dy),
        );
        expect(tester.takeException(), isNull);
      }

      expect(tester.widget<IconButton>(up.first).onPressed, isNull);
      expect(tester.widget<IconButton>(down.last).onPressed, isNull);
      await tester.enterText(fields.at(0), 'home');
      await tester.enterText(fields.at(2), 'manual-relay');
      await tester.pumpAndSettle();
      final chooseNode = button('Choose node').first;
      await tester.ensureVisible(chooseNode);
      await tester.pumpAndSettle();
      await tester.tap(chooseNode);
      await tester.pumpAndSettle();
      final relayOptions = [
        find.text('z-pek.catofes.'),
        find.text('n-hkg.example.'),
        find.text('directory-relay.example.'),
      ];
      for (final option in relayOptions) {
        expect(tester.widget<Text>(option).textAlign, TextAlign.right);
      }
      expect(
        tester.getTopLeft(relayOptions[0]).dy,
        lessThan(tester.getTopLeft(relayOptions[1]).dy),
      );
      expect(
        tester.getTopLeft(relayOptions[1]).dy,
        lessThan(tester.getTopLeft(relayOptions[2]).dy),
      );
      await tester.tap(relayOptions.last);
      await tester.pumpAndSettle();
      await tester.tap(down.first);
      await tester.pumpAndSettle();
      expect(
        tester.widget<TextFormField>(fields.at(1)).controller?.text,
        'manual-relay',
      );
      await tester.tap(up.last);
      await tester.pumpAndSettle();
      expect(
        tester.widget<TextFormField>(fields.at(1)).controller?.text,
        'directory-relay.example.',
      );
      await tester.tap(remove.last);
      await tester.pumpAndSettle();
      final chooseExit = button('Choose node').last;
      await tester.ensureVisible(chooseExit);
      await tester.tap(chooseExit);
      await tester.pumpAndSettle();
      final primaryExit = find.text('gateway.catofes.');
      final backupExit = find.text('a-lax.example./backup');
      expect(tester.widget<Text>(primaryExit).textAlign, TextAlign.right);
      expect(
        tester.getTopLeft(primaryExit).dy,
        lessThan(tester.getTopLeft(backupExit).dy),
      );
      await tester.tap(primaryExit);
      await tester.pumpAndSettle();
      tester.view.physicalSize = const Size(428, 850);
      await tester.pumpAndSettle();
      await tester.tap(find.byTooltip('Save'));
      await tester.pumpAndSettle();
      expect(
        backend.requests.lastWhere(
          (request) => request['action'] == 'create',
        )['hops'],
        ['directory-relay.example.@h26', 'gateway.catofes./exit@h2l4'],
      );
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
        ...directoryFixture(),
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
      final groups = (profile['proxy-groups'] as List).cast<Map>();
      expect(
        groups.singleWhere(
          (group) => group['name'] == 'Photon Paths',
        )['proxies'],
        ['Photon Path / home'],
      );
      expect(
        (profile['proxy-providers'] as Map)['photon-services']['payload'],
        contains(containsPair('type', 'socks5')),
      );
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
