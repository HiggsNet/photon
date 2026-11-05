import 'package:fl_clash/photon/controller.dart';
import 'package:fl_clash/photon/view.dart';
import 'package:fl_clash/providers/app.dart';
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
    expect(find.text('Disconnected'), findsOneWidget);
    await tester.tap(find.text('Start'));
    await tester.pumpAndSettle();
    expect(find.text('Connected'), findsOneWidget);
    expect(find.text('Stop'), findsOneWidget);
    await tester.tap(find.text('Stop'));
    await tester.pumpAndSettle();
    expect(find.text('Disconnected'), findsOneWidget);
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
    expect(find.text('Disconnected'), findsOneWidget);
    expect(find.text('Connected'), findsNothing);
    expect(backend.hasProcess, isFalse);
  });
}
