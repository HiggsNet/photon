import 'package:fl_clash/photon/controller.dart';
import 'package:fl_clash/photon/view.dart';
import 'package:fl_clash/providers/app.dart';
import 'package:fl_clash/widgets/widgets.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';

import '../helpers/test_app.dart';
import 'controller_test.dart' show FakeBackend;

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
      'Connected',
    );
    expect(find.text('Stop'), findsOneWidget);
    await tester.tap(find.text('Stop'));
    await tester.pumpAndSettle();
    expect(
      tester.widget<Text>(find.byKey(const ValueKey('photon-status'))).data,
      'Disconnected',
    );
    expect(controller.observation, isNull);
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
    'live tunnel, gossip and route pages expose useful details and filter rows',
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
            'tunnel_ready': true,
            'babel_live': true,
            'ike': {
              'live': true,
              'child_live': true,
              'phase': 'established',
              'attempt_remote_endpoint': '192.0.2.1:4500',
            },
          },
        ],
        'peers': [
          {
            'peer': 'gossip.catofes.',
            'pull_state': 'synced',
            'pull_attempts': 3,
            'pull_successes': 3,
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
      expect(find.text('gateway.catofes.'), findsOneWidget);
      expect(find.text('192.0.2.1:4500'), findsOneWidget);
      await tester.tap(find.text('Peers').first);
      await tester.pumpAndSettle();
      expect(find.text('gossip.catofes.'), findsOneWidget);
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
}
