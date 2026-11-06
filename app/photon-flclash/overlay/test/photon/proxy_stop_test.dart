import 'dart:async';

import 'package:fl_clash/core/controller.dart';
import 'package:fl_clash/core/interface.dart';
import 'package:fl_clash/core/method.dart';
import 'package:fl_clash/models/models.dart';
import 'package:fl_clash/photon/controller.dart';
import 'package:fl_clash/photon/proxy_bridge.dart';
import 'package:fl_clash/providers/providers.dart';
import 'package:fl_clash/state.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mocktail/mocktail.dart';
import 'package:riverpod/riverpod.dart';

import '../helpers/test_profiles.dart';

class _Core extends Mock implements CoreHandlerInterface {}

class _Setup extends SetupAction {
  @override
  void applyProfileDebounce({bool silence = false, bool force = false}) {}

  @override
  void resetCoreTraffic() {}
}

void main() {
  late _Core core;
  late ProviderContainer container;
  late Profile unrelated;

  setUp(() async {
    core = _Core();
    unrelated = Profile.normal(label: 'Independent');
    final photon = Profile.normal(label: 'Photon')
        .copyWith(url: photonProfileSource);
    container = ProviderContainer(
      overrides: [
        appVisibleProvider.overrideWithBuild((_, _) => false),
        initProvider.overrideWithBuild((_, _) => true),
        currentProfileIdProvider.overrideWithBuild((_, _) => unrelated.id),
        networkSettingProvider.overrideWithBuild(
          (_, _) => const NetworkProps(systemProxy: true),
        ),
        profilesProvider.overrideWith(() => TestProfiles([unrelated, photon])),
        setupActionProvider.overrideWith(_Setup.new),
        coreHandlerProvider.overrideWithValue(CoreController.scoped(core)),
      ],
    );
    addTearDown(container.dispose);
    globalState.container = container;
    PhotonProxyBridge().attach();
    addTearDown(() {
      photonController.onServicesChanged = null;
      photonController.onServicesInvalidated = null;
    });
    when(core.startListener).thenAnswer((_) async {});
    when(core.closeConnections).thenAnswer((_) async {});
    await container.read(setupActionProvider.notifier).setRunning(true);
    expect(container.read(proxyStateProvider).isStart, isTrue);
    container.read(currentProfileIdProvider.notifier).value = photon.id;
  });

  test(
    'connection-close timeout leaves the listener and system proxy off',
    () async {
      when(core.stopListener).thenAnswer((_) async {});
      final timeout = TimeoutException('connection.closeAll');
      when(core.closeConnections).thenAnswer((_) async => throw timeout);

      await expectLater(
        photonController.onServicesInvalidated!(true),
        throwsA(same(timeout)),
      );
      verifyInOrder([core.stopListener, core.closeConnections]);
      expect(container.read(proxyStateProvider).isStart, isFalse);
      expect(container.read(runningVpnOptionsProvider), isNull);
    },
  );

  test('disconnected Core does not restore the system proxy on stop', () async {
    const disconnect = CoreMethodException(
      code: 'transport_disconnected',
      message: 'Core closed its connection',
    );
    when(core.stopListener).thenAnswer((_) async => throw disconnect);

    await expectLater(
      photonController.onServicesInvalidated!(true),
      throwsA(same(disconnect)),
    );
    expect(container.read(proxyStateProvider).isStart, isFalse);
    expect(container.read(runningVpnOptionsProvider), isNull);
  });

  test('keeps connections owned by a newly selected profile', () async {
    final entered = Completer<void>();
    final stopped = Completer<void>();
    when(core.stopListener).thenAnswer((_) {
      entered.complete();
      return stopped.future;
    });
    final stop = photonController.onServicesInvalidated!(true);
    await entered.future;
    container.read(currentProfileIdProvider.notifier).value = unrelated.id;
    stopped.complete();
    await stop;

    verifyNever(core.closeConnections);
  });
}
