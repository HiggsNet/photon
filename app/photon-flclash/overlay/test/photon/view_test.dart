import 'dart:io';

import 'package:fl_clash/photon/controller.dart';
import 'package:fl_clash/photon/setup.dart';
import 'package:fl_clash/photon/setup_view.dart';
import 'package:fl_clash/photon/view.dart';
import 'package:fl_clash/providers/app.dart';
import 'package:fl_clash/ui/icons/icons.dart';
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

  photonTest('template editing and reset are offered without a tunnel', (
    tester,
  ) async {
    final directory = Directory.systemTemp.createTempSync('photon-template-');
    addTearDown(() => directory.deleteSync(recursive: true));
    final file = File('${directory.path}/photon.proxy.yaml');
    file.writeAsStringSync('rules: [');
    controller.selectConfig('${directory.path}/photon.yaml');

    await tester.pumpWidget(view());
    await tester.pumpAndSettle();
    await tester.tap(find.text('Proxy services').first);
    await tester.pumpAndSettle();
    await tester.runAsync(() => file.exists());
    await tester.pumpAndSettle();
    expect(find.text('photon.proxy.yaml'), findsOneWidget);
    expect(
      tester
          .widget<FilledButton>(
            find.widgetWithText(FilledButton, 'Apply Photon profile'),
          )
          .onPressed,
      isNull,
    );

    await tester.tap(find.widgetWithText(TextButton, 'Edit'));
    await tester.pumpAndSettle();
    expect(find.text('Edit YAML template', findRichText: true), findsOneWidget);
    expect(find.text('Built-in rules', findRichText: true), findsOneWidget);
    expect(backend.calls, isEmpty);
  });

  testWidgets('new Photon users can start with settings or use existing YAML', (
    tester,
  ) async {
    controller = PhotonController(createBackend: FakeBackend.new);
    await tester.pumpWidget(view());
    await tester.pumpAndSettle();
    expect(find.text('Connect'), findsOneWidget);
    expect(
      tester
          .widget<TextButton>(find.widgetWithText(TextButton, 'Connect'))
          .onPressed,
      isNull,
    );
    expect(find.text('Import Photon YAML'), findsNothing);
    await tester.tap(find.text('Settings'));
    await tester.pumpAndSettle();
    expect(find.text('Reference external Photon YAML'), findsOneWidget);
    expect(find.text('Import Photon YAML'), findsOneWidget);
    expect(find.text('Create Photon configuration'), findsOneWidget);
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
    expect(find.text('Identity database path'), findsNothing);
    await tester.tap(find.byTooltip('Save'));
    await tester.pumpAndSettle();
    expect(find.text('Node zone is required'), findsOneWidget);
    expect(saved, isNull);
    final zone = find.byKey(const ValueKey('managed_zone'));
    await tester.scrollUntilVisible(
      zone,
      100,
      scrollable: find.byType(Scrollable).first,
    );
    await tester.enterText(zone, 'client.example.');
    await tester.scrollUntilVisible(
      find.text('Local node identity'),
      100,
      scrollable: find.byType(Scrollable).first,
    );
    expect(
      find.textContaining('Photon generates this node’s key locally'),
      findsOneWidget,
    );
    await tester.scrollUntilVisible(
      find.text('Bootstrap nodes'),
      100,
      scrollable: find.byType(Scrollable).first,
    );
    final routes = find.byKey(const ValueKey('split_routes'));
    await tester.scrollUntilVisible(
      routes,
      100,
      scrollable: find.byType(Scrollable).first,
    );
    await tester.enterText(routes, 'fd42::/16\nfd43::/16');
    final mobike = find.byKey(const ValueKey('mobike'));
    await tester.scrollUntilVisible(
      mobike,
      100,
      scrollable: find.byType(Scrollable).first,
    );
    expect(tester.widget<Switch>(mobike).value, isFalse);
    await tester.tap(mobike);
    await tester.pumpAndSettle();
    expect(tester.widget<Switch>(mobike).value, isTrue);
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
    expect(attempts.last, containsPair('mobike', true));
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
      tester
          .widget<Tooltip>(find.byKey(const ValueKey('photon-status')))
          .message,
      'Disconnected',
    );
    await tester.tap(find.text('Connect'));
    await tester.pumpAndSettle();
    expect(
      tester
          .widget<Tooltip>(find.byKey(const ValueKey('photon-status')))
          .message,
      'Tunnel ready',
    );
    expect(find.text('Disconnect'), findsOneWidget);
    expect(find.text('Photon settings'), findsNothing);
    expect(find.text('/test/config.yaml'), findsNothing);
    expect(find.text('Reconnect Photon'), findsNothing);
    final count = find.byKey(const ValueKey('photon-tunnel-count'));
    expect(
      tester.getCenter(count).dy,
      closeTo(tester.getCenter(find.text('Connect')).dy, 1),
    );
    expect(
      tester.getCenter(count).dy,
      closeTo(tester.getCenter(find.text('Disconnect')).dy, 1),
    );
    expect(
      tester
          .getSize(find.byKey(const ValueKey('photon-connection-bar')))
          .height,
      lessThan(100),
    );
    expect(
      tester
          .widget<TextButton>(find.widgetWithText(TextButton, 'Connect'))
          .onPressed,
      isNull,
    );
    await tester.tap(find.text('Settings'));
    await tester.pumpAndSettle();
    expect(
      tester
          .widget<TextButton>(find.widgetWithText(TextButton, 'Edit'))
          .onPressed,
      isNull,
    );
    await tester.tap(find.text('Disconnect'));
    await tester.pumpAndSettle();
    expect(
      tester
          .widget<Tooltip>(find.byKey(const ValueKey('photon-status')))
          .message,
      'Disconnected',
    );
    expect(controller.observation, isNull);
    expect(
      tester
          .widget<TextButton>(find.widgetWithText(TextButton, 'Edit'))
          .onPressed,
      isNotNull,
    );
  });

  photonTest('leaving the page preserves the backend until app exit', (
    tester,
  ) async {
    await tester.pumpWidget(view());
    await tester.tap(find.text('Connect'));
    await tester.pumpAndSettle();
    await tester.pumpWidget(const SizedBox());
    expect(backend.hasProcess, isTrue);
    await controller.close();
    expect(backend.hasProcess, isFalse);
  });

  photonTest('safe mode cannot start Photon', (tester) async {
    await tester.pumpWidget(view(safe: true));
    await tester.tap(find.text('Connect'));
    await tester.pumpAndSettle();
    expect(backend.calls, isEmpty);
  });

  photonTest('failed start shows the error and removes old connection state', (
    tester,
  ) async {
    backend.statusError = StateError('IPC lost');
    await tester.pumpWidget(view());
    await tester.tap(find.text('Connect'));
    await tester.pumpAndSettle();
    expect(find.textContaining('IPC lost'), findsOneWidget);
    expect(
      tester
          .widget<Tooltip>(find.byKey(const ValueKey('photon-status')))
          .message,
      'Disconnected',
    );
    expect(controller.observation, isNull);
    expect(backend.hasProcess, isFalse);
  });

  photonTest(
    'established tunnels hide failures while diagnostics retain them',
    (tester) async {
      final failure = <String, dynamic>{
        'message': 'tunnel: IKE retransmission budget exhausted',
        'at': '2026-11-16T07:18:40Z',
        'historical': true,
      };
      final ike = <String, dynamic>{
        'live': true,
        'child_live': true,
        'phase': 'established',
        'attempt_remote_endpoint': '192.0.2.1:4500',
        'last_failure': failure,
      };
      final connection = <String, dynamic>{
        'peer': 'gateway.catofes.',
        'outer_family': 'ipv4',
        'tunnel_ready': true,
        'babel_live': true,
        'ike': ike,
      };
      backend.sample = {
        'running': true,
        'tunnel_ready': true,
        'connections': [connection],
      };
      await controller.start(allowed: true);
      await tester.pumpWidget(view());
      await tester.pumpAndSettle();
      await tester.tap(find.text('Tunnels').first);
      await tester.pumpAndSettle();

      for (final ready in [true, false]) {
        connection['tunnel_ready'] = ready;
        await controller.refresh();
        await tester.pumpAndSettle();
        await tester.tap(find.text('gateway.catofes.'));
        await tester.pumpAndSettle();
        expect(find.text('Last failure'), findsNothing);
        expect(find.text(failure['message'] as String), findsNothing);
        Navigator.of(tester.element(find.text('192.0.2.1:4500'))).pop();
        await tester.pumpAndSettle();
      }

      ike['live'] = false;
      ike['child_live'] = false;
      ike['phase'] = 'idle';
      failure['historical'] = false;
      await controller.refresh();
      await tester.pumpAndSettle();
      await tester.tap(find.text('gateway.catofes.'));
      await tester.pumpAndSettle();
      expect(find.text(failure['message'] as String), findsOneWidget);
      Navigator.of(tester.element(find.text('192.0.2.1:4500'))).pop();
      await tester.pumpAndSettle();

      ike['live'] = true;
      ike['child_live'] = true;
      ike['phase'] = 'established';
      failure['historical'] = true;
      await controller.refresh();
      await tester.pumpAndSettle();
      await tester.tap(find.text('Diagnostics').first);
      await tester.pumpAndSettle();
      await tester.tap(find.text('Advanced details'));
      await tester.pumpAndSettle();
      expect(
        find.textContaining('tunnel: IKE retransmission budget exhausted'),
        findsOneWidget,
      );
      expect(ike['last_failure'], same(failure));
    },
  );

  photonTest(
    'the tunnel table groups outer families and keeps their details accessible',
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
            'babel_live': true,
            'ipv4_route_ready': false,
            'ipv6_route_ready': true,
            'ike': {
              'live': true,
              'child_live': true,
              'phase': 'established',
              'attempt_remote_endpoint': '[2001:db8::1]:4500',
            },
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
          {'peer_id': 'revoked-sync.catofes.', 'sync_status': 'revoked'},
          {
            'peer_id': 'revoked-auth.catofes.',
            'authorization': 'revoked',
            'sync_status': 'waiting',
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
      await tester.tap(find.text('Connect'));
      await tester.pumpAndSettle();
      expect(find.text('fd42::1/128'), findsOneWidget);
      await tester.tap(find.text('Tunnels').first);
      await tester.pumpAndSettle();
      expect(find.text('gateway.catofes.'), findsOneWidget);
      expect(
        tester.getTopRight(find.text('gateway.catofes.')).dx,
        closeTo(tester.getTopRight(find.text('Gateway')).dx, 0.01),
      );
      expect(
        find.byKey(const ValueKey<Object>('gateway.catofes.')),
        findsOneWidget,
      );
      expect(find.textContaining('192.0.2.1:4500'), findsOneWidget);
      expect(find.byTooltip('IPv4 · Tunnel ready'), findsOneWidget);
      expect(find.byTooltip('IPv6 · Tunnel ready'), findsOneWidget);
      expect(find.text('IKE'), findsOneWidget);
      expect(find.text('ESP'), findsOneWidget);
      expect(find.text('Babel'), findsOneWidget);
      expect(find.text('Outer 4/6'), findsOneWidget);
      expect(find.byTooltip('Inner IPv6 route · Route ready'), findsOneWidget);
      expect(
        find.byTooltip('Inner IPv4 route · No usable route'),
        findsOneWidget,
      );
      expect(find.text('Initializing'), findsOneWidget);
      expect(find.text('Not ready'), findsOneWidget);
      expect(
        tester.getCenter(find.text('second.catofes.')).dy,
        lessThan(tester.getCenter(find.text('gateway.catofes.').first).dy),
      );
      final connections = backend.sample['connections'] as List;
      connections[1]['tunnel_ready'] = false;
      await controller.refresh();
      await tester.pumpAndSettle();
      expect(find.byTooltip('IPv4 · Tunnel ready'), findsOneWidget);
      expect(find.byTooltip('IPv6 · Tunnel ready'), findsNothing);
      expect(find.byTooltip('IPv6 · Tunnel not ready'), findsNWidgets(2));
      await tester.enterText(find.byType(TextField), '192.0.2.1');
      await tester.pumpAndSettle();
      expect(find.text('gateway.catofes.'), findsOneWidget);
      expect(find.byTooltip('IPv6 · Tunnel not ready'), findsOneWidget);
      await tester.tap(find.text('gateway.catofes.'));
      await tester.pumpAndSettle();
      expect(find.text('Outer tunnel · IPv4'), findsOneWidget);
      expect(find.text('Outer tunnel · IPv6'), findsOneWidget);
      expect(find.text('IPv4 · IKE'), findsNothing);
      expect(find.text('Inner IPv4 route'), findsNWidgets(2));
      expect(find.text('Inner IPv6 route'), findsNWidgets(2));
      expect(find.text('192.0.2.1:4500'), findsOneWidget);
      final ipv6Remote = find.text('[2001:db8::1]:4500');
      expect(ipv6Remote, findsOneWidget);
      Navigator.of(tester.element(ipv6Remote)).pop();
      await tester.pumpAndSettle();
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
      expect(
        tester.getTopRight(find.text('gossip.catofes.')).dx,
        closeTo(tester.getTopRight(find.text('Node')).dx, 0.01),
      );
      expect(find.text('synced'), findsOneWidget);
      expect(find.text('retry_pending'), findsOneWidget);
      expect(find.text('revoked-sync.catofes.'), findsNothing);
      expect(find.text('revoked-auth.catofes.'), findsNothing);
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
  photonTest('route rows group next hops and preserve source conditions', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(1400, 1100);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    backend.sample = {
      'running': true,
      'tunnel_ready': true,
      'routes_truncated': true,
      'babel': {
        'routes': [
          {
            'prefix': 'fd42:1::/64',
            'source_prefix': '::/0',
            'peer': 'gateway-b.catofes.',
            'next_hop': 'fe80::2',
            'outer_family': 'ipv4',
            'metric': 200,
          },
          {
            'prefix': 'fd42:1::/64',
            'source_prefix': '::/0',
            'peer': 'gateway-a.catofes.',
            'next_hop': 'fe80::3',
            'outer_family': 'ipv6',
            'metric': 100,
          },
          {
            'prefix': 'fd42:1::/64',
            'source_prefix': 'fd00::/64',
            'peer': 'gateway-c.catofes.',
            'next_hop': 'fe80::4',
            'outer_family': 'ipv4',
            'metric': 50,
          },
        ],
      },
    };
    await tester.pumpWidget(view());
    await tester.tap(find.text('Connect'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Routes').first);
    await tester.pumpAndSettle();
    expect(find.text('fd42:1::/64'), findsNWidgets(2));
    expect(find.text('Next hop'), findsOneWidget);
    expect(find.text('Paths'), findsOneWidget);
    expect(find.text('gateway-a.catofes.'), findsOneWidget);
    expect(find.text('gateway-c.catofes.'), findsOneWidget);
    expect(find.text('gateway-b.catofes.'), findsNothing);
    expect(find.text('This sample is incomplete.'), findsOneWidget);
    expect(find.text('Delay'), findsNothing);
    expect(
      find.textContaining('Babel cost is a routing weight'),
      findsOneWidget,
    );
    await tester.enterText(find.byType(TextField), 'fe80::2');
    await tester.pumpAndSettle();
    expect(find.text('fd42:1::/64'), findsOneWidget);
    expect(find.text('gateway-a.catofes.'), findsOneWidget);
    expect(find.text('2'), findsOneWidget);
    await tester.tap(find.text('fd42:1::/64'));
    await tester.pumpAndSettle();
    const routeKey = ValueKey<Object>((prefix: 'fd42:1::/64', source: '::/0'));
    final expansion = find.byKey(
      const ValueKey(('route-paths', (prefix: 'fd42:1::/64', source: '::/0'))),
    );
    expect(expansion, findsOneWidget);
    expect(find.byType(Scaffold), findsOneWidget);
    expect(
      tester.getTopLeft(expansion).dy,
      greaterThanOrEqualTo(tester.getBottomLeft(find.byKey(routeKey)).dy),
    );
    final rows = find.descendant(
      of: expansion,
      matching: find.byType(TableCells),
    );
    expect(rows, findsNWidgets(3));
    expect(find.text('gateway-a.catofes.'), findsNWidgets(2));
    expect(find.text('gateway-b.catofes.'), findsOneWidget);
    expect(find.text('fe80::2'), findsNWidgets(2));
    expect(find.text('fe80::3'), findsOneWidget);
    expect(find.text('200'), findsOneWidget);
    final routes = (backend.sample['babel'] as Map)['routes'] as List;
    (routes[0] as Map)['metric'] = 90;
    await controller.refresh();
    await tester.pumpAndSettle();
    expect(expansion, findsOneWidget);
    expect(
      (tester.widget<TableCells>(rows.at(1)).cells.last as Text).data,
      '90',
    );
    expect(
      (tester.widget<TableCells>(rows.at(2)).cells.last as Text).data,
      '100',
    );
    tester.view.physicalSize = const Size(640, 900);
    await tester.pumpAndSettle();
    await Scrollable.ensureVisible(
      tester.element(find.byKey(routeKey)),
      alignment: 0.5,
    );
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(routeKey));
    await tester.pumpAndSettle();
    expect(expansion, findsNothing);
    expect(find.byType(Scaffold), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  photonTest('proxy services group all authorized endpoints by publisher', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(1400, 1100);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final publishers = {
      'b-aws-hnd.catofes.': ['local', 'hk', 'global', 'sg', 'us', 'custom'],
      'z-aws-hnd.catofes.': ['local', 'global'],
      'a-aws-pek.catofes.': ['local', 'cn'],
      'short.other.': ['local', 'hk'],
      'q-aws-hnd.catofes.': ['jp'],
    };
    var endpointId = 0;
    backend.serviceSample = {
      ...directoryFixture(),
      'services': [
        for (final publisher in publishers.entries)
          {
            'id': '${publisher.key}/services/socks5',
            'owner': publisher.key,
            'status': 'active',
            'endpoints': [
              for (final region in publisher.value)
                {
                  'id': (++endpointId).toRadixString(16).padLeft(32, '0'),
                  'region': region,
                  'address': 'fd42:1::${endpointId.toRadixString(16)}',
                  'port': 1080,
                },
            ],
          },
      ],
    };
    await tester.pumpWidget(view());
    await tester.tap(find.text('Connect'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Proxy services').first);
    await tester.pumpAndSettle();
    expect(find.text('Endpoints'), findsNothing);
    expect(find.text('Local'), findsOneWidget);
    expect(find.text('Hong Kong'), findsOneWidget);
    expect(find.text('Mainland China'), findsOneWidget);
    expect(find.text('Japan'), findsOneWidget);
    expect(find.text('Singapore'), findsOneWidget);
    expect(find.text('United States'), findsOneWidget);
    expect(find.text('custom'), findsOneWidget);
    expect(find.text('Global'), findsOneWidget);
    expect(find.text('Apply Photon profile'), findsOneWidget);
    expect(find.text('Import YAML template'), findsNothing);
    expect(find.text('Edit YAML template'), findsNothing);
    expect(
      find.textContaining('Checks indicate supported exit types'),
      findsNothing,
    );
    await tester.runAsync(() => File('/test/config.proxy.yaml').exists());
    await tester.pumpAndSettle();
    expect(
      tester
          .widget<TextButton>(find.widgetWithText(TextButton, 'Edit'))
          .onPressed,
      isNotNull,
    );
    await tester.tap(find.widgetWithText(TextButton, 'Edit'));
    await tester.pumpAndSettle();
    expect(find.byType(PopupMenu), findsOneWidget);
    expect(
      find.text('Import YAML template', findRichText: true),
      findsOneWidget,
    );
    expect(find.text('Edit YAML template', findRichText: true), findsOneWidget);
    await tester.tap(find.byKey(const ValueKey('photon-tunnel-count')));
    await tester.pumpAndSettle();
    final help = find.byTooltip('How templates work');
    expect(help, findsOneWidget);
    expect(find.byType(Checkbox), findsNothing);
    const ordered = [
      'short.other.',
      'a-aws-pek.catofes.',
      'z-aws-hnd.catofes.',
      'q-aws-hnd.catofes.',
      'b-aws-hnd.catofes.',
    ];
    for (var i = 0; i < ordered.length; i++) {
      final name = find.text(ordered[i]);
      expect(name, findsOneWidget);
      expect(
        tester.getTopRight(name).dx,
        closeTo(tester.getTopRight(find.text('Node')).dx, 0.01),
      );
      if (i > 0) {
        expect(
          tester.getCenter(name).dy,
          greaterThan(tester.getCenter(find.text(ordered[i - 1])).dy),
        );
      }
      final row = find.ancestor(of: name, matching: find.byType(TableCells));
      final cells = tester.widget<TableCells>(row).cells;
      expect(cells, hasLength(9));
      for (final (index, region) in [
        'local',
        'cn',
        'custom',
        'hk',
        'jp',
        'sg',
        'us',
        'global',
      ].indexed) {
        final marker = cells[index + 1] as Tooltip;
        expect(
          marker.child is GlyphIcon,
          publishers[ordered[i]]!.contains(region),
        );
      }
    }
    await tester.enterText(find.byType(TextField), 'Singapore');
    await tester.pumpAndSettle();
    expect(find.text('b-aws-hnd.catofes.'), findsOneWidget);
    for (final node in ordered.take(ordered.length - 1)) {
      expect(find.text(node), findsNothing);
    }
    await tester.enterText(find.byType(TextField), '');
    await tester.pumpAndSettle();
    expect(find.textContaining('fd42:1::2'), findsNothing);
    await tester.tap(help);
    await tester.pumpAndSettle();
    expect(find.text('Generated by Photon'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });
}
