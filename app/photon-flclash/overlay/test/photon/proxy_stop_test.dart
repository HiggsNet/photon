import 'package:fl_clash/models/models.dart';
import 'package:fl_clash/photon/controller.dart';
import 'package:fl_clash/photon/proxy_bridge.dart';
import 'package:fl_clash/photon/services.dart';
import 'package:fl_clash/providers/providers.dart';
import 'package:fl_clash/state.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:riverpod/riverpod.dart';

import '../helpers/test_profiles.dart';

class _Setup extends SetupAction {
  int applies = 0;

  @override
  Future<bool> applyProfile({
    bool silence = false,
    bool force = false,
    Future<void> Function()? preloadInvoke,
  }) async {
    applies++;
    return false;
  }
}

void main() {
  test('offline profile keeps Photon bypasses and rejects proxy traffic', () {
    final profile = blockedPhotonProfile({
      'proxies': [
        {'name': 'Photon endpoint'},
      ],
      'proxy-groups': [
        {'name': 'Photon'},
      ],
      'mode': 'direct',
      'dns': {
        'fake-ip-filter': ['bootstrap.example'],
      },
      'tun': {
        'route-exclude-address': ['192.0.2.1/32'],
      },
      'rules': [
        'IP-CIDR,192.0.2.1/32,DIRECT,no-resolve',
        'IP-CIDR6,2001:db8::/64,Photon,no-resolve',
        'PROCESS-PATH-REGEX,photon,DIRECT',
        'MATCH,DIRECT',
      ],
    });
    expect(profile, {
      'ipv6': true,
      'dns': {
        'fake-ip-filter': ['bootstrap.example'],
      },
      'tun': {
        'route-exclude-address': ['192.0.2.1/32'],
      },
      'rules': [
        'IP-CIDR,192.0.2.1/32,DIRECT,no-resolve',
        'PROCESS-PATH-REGEX,photon,DIRECT',
        'MATCH,REJECT',
      ],
    });
  });

  test('Photon stop leaves both independent proxy intents alone', () async {
    final photon = Profile.normal(
      label: 'Photon',
    ).copyWith(url: photonProfileSource);
    final independent = Profile.normal(label: 'Independent');
    final setup = _Setup();
    final container = ProviderContainer(
      overrides: [
        currentProfileIdProvider.overrideWithBuild((_, _) => independent.id),
        profilesProvider.overrideWith(
          () => TestProfiles([photon, independent]),
        ),
        setupActionProvider.overrideWith(() => setup),
      ],
    );
    addTearDown(container.dispose);
    globalState.container = container;
    PhotonProxyBridge().attach();
    addTearDown(() {
      photonController.onServicesChanged = null;
      photonController.onServicesInvalidated = null;
    });

    container.read(runTimeProvider.notifier).value = 1;
    await photonController.onServicesInvalidated!();
    expect(setup.applies, 0);
    expect(container.read(isStartProvider), isTrue);

    container.read(currentProfileIdProvider.notifier).value = photon.id;
    await expectLater(
      photonController.onServicesInvalidated!(),
      throwsStateError,
    );
    expect(setup.applies, 1);
    expect(container.read(isStartProvider), isTrue);
  });
}
