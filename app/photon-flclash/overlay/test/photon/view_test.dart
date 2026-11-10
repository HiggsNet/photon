import 'package:fl_clash/photon/controller.dart';
import 'package:fl_clash/photon/setup.dart';
import 'package:fl_clash/photon/setup_view.dart';
import 'package:fl_clash/photon/view.dart';
import 'package:fl_clash/providers/app.dart';
import 'package:fl_clash/widgets/widgets.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';

import '../helpers/test_app.dart';
import 'controller_test.dart' show FakeBackend;
import 'services_test.dart' show directoryFixture;

void main() {
  late PhotonController controller;
  late FakeBackend backend;

  void photonTest(
    String description,
    Future<void> Function(WidgetTester) body,
  ) {
    testWidgets(description, (tester) async {
      backend = FakeBackend();
      controller = PhotonController(createBackend: () => backend)
        ..selectConfig('/test/config.yaml');
      try {
        await body(tester);
      } finally {
        await tester.pumpWidget(const SizedBox());
        await controller.close();
        controller.dispose();
      }
    });
  }

  Widget view({bool safe = false}) => TestApp(
    locale: const Locale('en'),
    overrides: [safeModeProvider.overrideWith((_) => safe)],
    child: PhotonView(controller: controller, isWindows: true),
  );

  testWidgets('new Photon users can start with settings or use existing YAML', (
    tester,
  ) async {
    controller = PhotonController(createBackend: FakeBackend.new);
    await tester.pumpWidget(view());
    await tester.pumpAndSettle();
    final settings = tester.widget<FilledButton>(
      find.widgetWithText(FilledButton, 'Photon settings'),
    );
    expect(settings.onPressed, isNotNull);
    expect(find.text('Use existing Photon YAML'), findsOneWidget);
    expect(find.text('Start'), findsNothing);
    await tester.pumpWidget(const SizedBox());
    await controller.close();
    controller.dispose();
  });

  testWidgets('settings can be corrected after a rejected save', (
    tester,
  ) async {
    final form = <String, dynamic>{
      'new_config': true,
      'managed_zone': '',
      'root_public_key': '',
      'split_routes': '',
      'allowed_gateways': '*',
      'state_path': '/app/photon/photon.db',
      'overlay_id': 'ipsec-main',
      'gossip_listen': '0.0.0.0:33434',
      'adapter_name': 'Photon Windows',
      'mtu': '1400',
      'log_level': 'info',
      'initial_backoff': '1s',
      'max_backoff': '1m',
    };
    final attempts = <Map<String, dynamic>>[];
    bool? saved;
    await tester.pumpWidget(
      TestApp(
        locale: const Locale('en'),
        wrapInProviderScope: true,
        child: Builder(
          builder: (context) => Scaffold(
            title: 'Photon',
            body: Center(
              child: FilledButton(
                onPressed: () async {
                  saved = await showPhotonSettingsForm(
                    context,
                    config: '/app/photon/photon.yaml',
                    form: form,
                    onSave: (edited) async {
                      attempts.add(edited);
                      if (edited['managed_zone'] == '') {
                        throw const PhotonSetupException(
                          'Node zone is required',
                        );
                      }
                    },
                  );
                },
                child: const Text('Edit'),
              ),
            ),
          ),
        ),
      ),
    );
    await tester.tap(find.text('Edit'));
    await tester.pumpAndSettle();
    expect(find.text('Bootstrap nodes'), findsOneWidget);
    expect(find.text('Identity database path'), findsNothing);
    await tester.tap(find.byTooltip('Save'));
    await tester.pumpAndSettle();
    expect(find.text('Node zone is required'), findsOneWidget);
    expect(saved, isNull);
    final zone = find.byKey(const ValueKey('managed_zone'));
    await tester.ensureVisible(zone);
    await tester.enterText(zone, 'client.example.');
    final routes = find.byKey(const ValueKey('split_routes'));
    await tester.scrollUntilVisible(
      routes,
      100,
      scrollable: find.byType(Scrollable).first,
    );
    await tester.enterText(routes, 'fd42::/16\nfd43::/16');
    final advanced = find.text('Advanced configuration');
    await tester.scrollUntilVisible(
      advanced,
      100,
      scrollable: find.byType(Scrollable).first,
    );
    await tester.tap(advanced);
    await tester.pumpAndSettle();
    final mtu = find.byKey(const ValueKey('mtu'));
    await tester.scrollUntilVisible(
      mtu,
      100,
      scrollable: find.byType(Scrollable).first,
    );
    await tester.enterText(mtu, '1420');
    await tester.tap(find.byTooltip('Save'));
    await tester.pumpAndSettle();
    expect(saved, isTrue);
    expect(attempts, hasLength(2));
    expect(attempts.last, containsPair('managed_zone', 'client.example.'));
    expect(attempts.last, containsPair('split_routes', 'fd42::/16\nfd43::/16'));
    expect(attempts.last, containsPair('mtu', '1420'));
    expect(attempts.last, containsPair('state_path', '/app/photon/photon.db'));
    expect(attempts.last, containsPair('bootstrap_hints', [{}]));
    expect(form['managed_zone'], isEmpty);
  });

  photonTest('starts, displays status and addresses, then stops', (
    tester,
  ) async {
    await tester.pumpWidget(view());
    expect(
      tester.widget<Text>(find.byKey(const ValueKey('photon-status'))).data,
      'Disconnected',
    );
    await tester.tap(find.text('Start'));
    await tester.pumpAndSettle();
    expect(
      tester.widget<Text>(find.byKey(const ValueKey('photon-status'))).data,
      'Tunnel ready',
    );
    expect(find.text('Stop'), findsOneWidget);
    expect(
      tester
          .widget<TextButton>(
            find.widgetWithText(TextButton, 'Photon settings'),
          )
          .onPressed,
      isNull,
    );
    await tester.tap(find.text('Stop'));
    await tester.pumpAndSettle();
    expect(
      tester.widget<Text>(find.byKey(const ValueKey('photon-status'))).data,
      'Disconnected',
    );
    expect(controller.observation, isNull);
    expect(
      tester
          .widget<TextButton>(
            find.widgetWithText(TextButton, 'Photon settings'),
          )
          .onPressed,
      isNotNull,
    );
  });

  photonTest('leaving the page preserves the backend until app exit', (
    tester,
  ) async {
    await tester.pumpWidget(view());
    await tester.tap(find.text('Start'));
    await tester.pumpAndSettle();
    await tester.pumpWidget(const SizedBox());
    expect(backend.hasProcess, isTrue);
    await controller.close();
    expect(backend.hasProcess, isFalse);
  });

  photonTest('safe mode cannot start Photon', (tester) async {
    await tester.pumpWidget(view(safe: true));
    await tester.tap(find.text('Start'));
    await tester.pumpAndSettle();
    expect(backend.calls, isEmpty);
  });

  photonTest('failed start shows the error and removes old connection state', (
    tester,
  ) async {
    backend.statusError = StateError('IPC lost');
    await tester.pumpWidget(view());
    await tester.tap(find.text('Start'));
    await tester.pumpAndSettle();
    expect(find.textContaining('IPC lost'), findsOneWidget);
    expect(
      tester.widget<Text>(find.byKey(const ValueKey('photon-status'))).data,
      'Disconnected',
    );
    expect(controller.observation, isNull);
    expect(backend.hasProcess, isFalse);
  });

  photonTest(
    'the tunnel table separates readiness from IKE and keeps details accessible',
    (tester) async {
      tester.view.physicalSize = const Size(1400, 1100);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      backend.sample = {
        'running': true,
        'tunnel_ready': true,
        'admission': {
          'pending': false,
          'managed_zone': 'windows-test.catofes.',
        },
        'wintun': {
          'addresses': ['fd42::1/128'],
          'split_routes': ['fd42::/16'],
        },
        'connections': [
          {
            'peer': 'gateway.catofes.',
            'outer_family': 'ipv4',
            'tunnel_ready': true,
            'babel_live': true,
            'ipv4_route_ready': false,
            'ipv6_route_ready': true,
            'ike': {
              'live': true,
              'child_live': true,
              'phase': 'established',
              'attempt_remote_endpoint': '192.0.2.1:4500',
            },
          },
          {
            'peer': 'gateway.catofes.',
            'outer_family': 'ipv6',
            'tunnel_ready': true,
          },
          {
            'peer': 'second.catofes.',
            'tunnel_ready': false,
            'babel_live': false,
            'ike': {
              'live': false,
              'child_live': false,
              'phase': 'init',
              'attempt_remote_endpoint': '[2001:db8::2]:500',
              'last_failure': {
                'event': 'network_rebind',
                'message': 'outer_path_changed',
              },
            },
          },
        ],
        'peers': [
          {
            'peer_id': 'gossip.catofes.',
            'sync_status': 'synced',
            'last_sync_unix': 1735689600,
            'active_pull_last_event': 'scan_timer',
          },
          {
            'peer_id': 'other-gossip.catofes.',
            'sync_status': 'retry_pending',
            'last_failure': {
              'code': 'timeout',
              'message': 'round timer timed out',
              'at_unix': 1735689700,
            },
          },
        ],
        'babel': {
          'live': true,
          'routes': [
            {
              'prefix': 'fd42:1::/64',
              'peer': 'gateway.catofes.',
              'metric': 42,
              'source_prefix': '::/0',
            },
          ],
        },
      };
      await tester.pumpWidget(view());
      await tester.tap(find.text('Start'));
      await tester.pumpAndSettle();
      expect(find.text('fd42::1/128'), findsOneWidget);
      await tester.tap(find.text('Tunnels').first);
      await tester.pumpAndSettle();
      expect(find.text('gateway.catofes.'), findsNWidgets(2));
      expect(
        find.byKey(const ValueKey<Object>(('gateway.catofes.', 'IPv6'))),
        findsOneWidget,
      );
      expect(find.text('192.0.2.1:4500'), findsOneWidget);
      expect(find.text('IKE'), findsOneWidget);
      expect(find.text('ESP'), findsOneWidget);
      expect(find.text('Babel'), findsOneWidget);
      expect(find.text('Outer'), findsOneWidget);
      expect(find.byTooltip('Route ready'), findsOneWidget);
      expect(find.byTooltip('No usable route'), findsOneWidget);
      expect(find.text('Initializing'), findsOneWidget);
      expect(find.text('Not ready'), findsOneWidget);
      expect(
        tester.getCenter(find.text('second.catofes.')).dy,
        lessThan(tester.getCenter(find.text('gateway.catofes.').first).dy),
      );
      await tester.enterText(find.byType(TextField), '2001:db8::2');
      await tester.pumpAndSettle();
      expect(find.text('gateway.catofes.'), findsNothing);
      expect(find.text('second.catofes.'), findsOneWidget);
      tester.view.physicalSize = const Size(640, 900);
      await tester.pumpAndSettle();
      expect(find.text('[2001:db8::2]:500'), findsNothing);
      await tester.tap(find.text('second.catofes.'));
      await tester.pumpAndSettle();
      expect(find.text('[2001:db8::2]:500'), findsOneWidget);
      final reason = find.text('Outer network path changed');
      expect(reason, findsOneWidget);
      Navigator.of(tester.element(reason)).pop();
      tester.view.physicalSize = const Size(1400, 1100);
      await tester.pumpAndSettle();
      await tester.tap(find.text('Gossip peers').first);
      await tester.pumpAndSettle();
      expect(find.text('gossip.catofes.'), findsOneWidget);
      expect(find.text('synced'), findsOneWidget);
      expect(find.text('retry_pending'), findsOneWidget);
      expect(find.text('scan_timer'), findsNothing);
      expect(find.text('round timer timed out'), findsNothing);
      await tester.tap(find.text('other-gossip.catofes.'));
      await tester.pumpAndSettle();
      final syncTimeout = find.text('round timer timed out');
      expect(syncTimeout, findsOneWidget);
      Navigator.of(tester.element(syncTimeout)).pop();
      await tester.pumpAndSettle();
      await tester.tap(find.text('Routes').first);
      await tester.pumpAndSettle();
      expect(find.text('fd42:1::/64'), findsOneWidget);
      expect(find.text('42'), findsOneWidget);
      await tester.enterText(find.byType(TextField), 'no-match');
      await tester.pumpAndSettle();
      expect(find.text('fd42:1::/64'), findsNothing);
      expect(find.text('No records to display'), findsOneWidget);
      await tester.tap(find.text('Diagnostics').first);
      await tester.pumpAndSettle();
      expect(find.text('Copy diagnostics'), findsOneWidget);
      expect(tester.takeException(), isNull);
    },
  );
  photonTest('proxy services group all authorized endpoints by publisher', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(1400, 1100);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    backend.serviceSample = directoryFixture();
    await tester.pumpWidget(view());
    await tester.tap(find.text('Start'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Proxy services').first);
    await tester.pumpAndSettle();
    expect(find.text('Endpoints'), findsOneWidget);
    expect(find.text('Switch to Photon profile'), findsOneWidget);
    expect(find.text('Import YAML template'), findsOneWidget);
    expect(find.text('Edit YAML template'), findsOneWidget);
    expect(find.byType(Checkbox), findsNothing);
    expect(find.text('owner.catofes.'), findsOneWidget);
    expect(find.text('cn · jp'), findsOneWidget);
    expect(find.text('2'), findsOneWidget);
    expect(find.textContaining('fd42:1::2'), findsNothing);
    expect(tester.takeException(), isNull);
  });
}
