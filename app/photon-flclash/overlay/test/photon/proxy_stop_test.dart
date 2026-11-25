import 'dart:io';

import 'package:fl_clash/common/common.dart';
import 'package:fl_clash/core/controller.dart';
import 'package:fl_clash/core/interface.dart';
import 'package:fl_clash/core/method.dart';
import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/l10n/l10n.dart';
import 'package:fl_clash/models/models.dart';
import 'package:fl_clash/photon/controller.dart';
import 'package:fl_clash/photon/proxy_bridge.dart';
import 'package:fl_clash/photon/services.dart';
import 'package:fl_clash/providers/providers.dart';
import 'package:fl_clash/state.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mocktail/mocktail.dart';
import 'package:package_info_plus/package_info_plus.dart';
import 'package:riverpod/riverpod.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../helpers/app_paths.dart';
import '../helpers/test_profiles.dart';

class _Core extends Mock implements CoreHandlerInterface {}

class _Proxies extends ProxiesAction {
  @override
  Future<void> updateGroups() async {}
}

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
  TestWidgetsFlutterBinding.ensureInitialized();

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
    final photon = Profile.normal(label: 'Photon')
        .copyWith(url: photonProfileSource);
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

  test(
    'a rejected offline template recovers and deletion skips the cached rules',
    () async {
      final root = await Directory.systemTemp.createTemp('photon-proxy-stop-');
      addTearDown(() => root.delete(recursive: true));
      await useAppPaths(root);
      await AppLocalizations.load(const Locale('en'));
      globalState.packageInfo = PackageInfo(
        appName: 'FlClash',
        packageName: 'com.follow.clash',
        version: '0.0.0',
        buildNumber: '0',
      );
      SharedPreferences.setMockInitialValues({
        'photon.v1.config_path': 'photon.yaml',
      });
      final template = photonProxyTemplateFile('${root.path}/photon.yaml');
      await template.writeAsString('rules: [MATCH,Missing]');
      final profile = Profile.normal(label: 'Photon')
          .copyWith(url: photonProfileSource);
      final cached = await profile.file;
      await cached.parent.create(recursive: true);
      await cached.writeAsString(
        encodePhotonProfile({
          'proxy-providers': {
            'photon-services': {'type': 'inline'},
          },
          'proxy-groups': [
            {
              'name': 'Photon',
              'type': 'select',
              'proxies': ['DIRECT'],
            },
          ],
          'rules': ['MATCH,Missing'],
          'x-photon-protection': {
            'route-exclude-address': ['fd42::/16'],
            'rules': ['IP-CIDR6,fd42::/16,DIRECT,no-resolve'],
            'bypass-domains': <String>[],
          },
        }),
      );
      final core = _Core();
      registerFallbackValue(
        const SetupParams(
          selectedMap: {},
          options: CoreOptions(testUrl: ''),
        ),
      );
      when(() => core.getExternalProviders()).thenAnswer((_) async => []);
      final pushes = <String>[];
      when(() => core.setupConfig(any())).thenAnswer((_) async {
        final config = await File(await appPath.configFilePath).readAsString();
        pushes.add(config);
        if (config.contains('MATCH,Missing')) {
          throw const CoreMethodException(
            code: 'config_rejected',
            message: 'Missing policy',
          );
        }
      });
      final container = ProviderContainer(
        overrides: [
          currentProfileIdProvider.overrideWithBuild((_, _) => profile.id),
          profilesProvider.overrideWith(() => TestProfiles([profile])),
          coreHandlerProvider.overrideWithValue(CoreController.scoped(core)),
          proxiesActionProvider.overrideWith(_Proxies.new),
          setupStateProvider.overrideWith(
            (_, id) => SetupState(
              profileId: id,
              profileLastUpdateDate: null,
              profileType: ProfileType.file,
              extendType: ExtendType.standard,
              rules: const [],
              proxyGroups: const [],
              addedRules: const [],
              script: null,
              overrides: const ProfileOverrides(),
            ),
          ),
        ],
      );
      addTearDown(container.dispose);
      globalState.container = container;
      final setup = container.read(setupActionProvider.notifier);

      expect(await setup.applyProfile(force: true, silence: true), isTrue);
      expect(pushes, hasLength(2));
      expect(pushes.first, contains('MATCH,Missing'));
      final recovered = pushes.last;
      expect(recovered, contains('IP-CIDR6,fd42::/16,DIRECT,no-resolve'));
      expect(recovered, contains('MATCH,REJECT'));
      expect(recovered, isNot(contains('photon-services')));
      expect(await template.exists(), isTrue);

      await template.delete();
      pushes.clear();
      expect(await setup.applyProfile(force: true, silence: true), isTrue);
      expect(pushes, [recovered]);
    },
  );
}
