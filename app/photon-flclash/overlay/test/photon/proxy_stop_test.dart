import 'dart:io';
import 'dart:async';
import 'dart:convert';

import 'package:fl_clash/common/common.dart';
import 'package:fl_clash/core/controller.dart';
import 'package:fl_clash/core/interface.dart';
import 'package:fl_clash/core/method.dart';
import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/l10n/l10n.dart';
import 'package:fl_clash/models/models.dart';
import 'package:fl_clash/photon/controller.dart';
import 'package:fl_clash/photon/profile.dart';
import 'package:fl_clash/photon/proxy_bridge.dart';
import 'package:fl_clash/photon/proxy_selection.dart';
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
import 'controller_test.dart' show FakeBackend;

class _Core extends Mock implements CoreHandlerInterface {}

class _Proxies extends ProxiesAction {
  @override
  Future<void> updateGroups() async {}
}

class _Setup extends SetupAction {
  int applies = 0;
  Future<bool> Function()? apply;

  @override
  Future<bool> applyProfile({
    bool silence = false,
    bool force = false,
    Future<void> Function()? preloadInvoke,
  }) async {
    applies++;
    return await apply?.call() ?? false;
  }
}

Map<String, dynamic> _directory(List<int> nodes) {
  final now = DateTime.now().toUtc();
  return {
    'instance_id': 'test',
    'root_fingerprint': 'a' * 64,
    'managed_zone': 'test.example.',
    'revision': 1,
    'observed_at': now.toIso8601String(),
    'valid_until': now.add(const Duration(seconds: 5)).toIso8601String(),
    'adapter_name': 'Photon Test',
    'services': [
      for (final node in nodes)
        {
          'id': 'node-$node',
          'owner': 'node-$node.example.',
          'status': 'active',
          'diagnostic': '',
          'endpoints': [
            {
              'id': node.toRadixString(16).padLeft(32, '0'),
              'region': 'local',
              'address': '192.0.2.$node',
              'port': 3128,
            },
          ],
        },
    ],
  };
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
    final root = await Directory.systemTemp.createTemp('photon-proxy-stop-');
    addTearDown(() => root.delete(recursive: true));
    await useAppPaths(root);
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
    final selection = container.listen(currentProfileIdProvider, (_, _) {});
    addTearDown(selection.close);
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
      throwsA(isA<StateError>()),
    );
    expect(setup.applies, 1);
    expect(container.read(isStartProvider), isTrue);
  });

  test('only manual apply replaces the saved proxy configuration', () async {
    final root = await Directory.systemTemp.createTemp('photon-proxy-apply-');
    addTearDown(() => root.delete(recursive: true));
    await useAppPaths(root);
    SharedPreferences.setMockInitialValues({});
    final profile = Profile.normal(label: 'Photon')
        .copyWith(url: photonProfileSource);
    final file = await profile.file;
    await file.parent.create(recursive: true);
    final backend = FakeBackend()..serviceSample = _directory([1, 2]);
    final controller = PhotonController(createBackend: () => backend)
      ..selectConfig('${root.path}/photon.yaml');
    addTearDown(() async {
      await controller.close();
      controller.dispose();
    });
    final bridge = PhotonProxyBridge(controller: controller)..attach();
    final original = photonProxyProfile(
      directory: PhotonDirectory.fromJson(backend.serviceSample!),
      now: DateTime.now(),
      splitRoutes: [],
      adapter: 'Photon Test',
      backendPath: '${root.path}/photon-windows.exe',
    );
    final saved = encodePhotonProfile(original);
    await file.writeAsString(saved);
    final running = <Map<String, dynamic>>[];
    var failNextApply = false;
    final setup = _Setup()
      ..apply = () async {
        if (failNextApply) {
          failNextApply = false;
          return false;
        }
        running.add(
          bridge.authorizeProfile(await readPhotonProfile(profile.id)),
        );
        return true;
      };
    final core = _Core();
    final originalProxies = (original['proxies'] as List).cast<Map>();
    final a = originalProxies.first['name'] as String;
    final b = originalProxies.last['name'] as String;
    TrackerInfo connection(String name) => TrackerInfo(
      id: name,
      start: DateTime.now(),
      metadata: const Metadata(),
      chains: [name, 'Photon'],
      rule: 'MATCH',
      rulePayload: '',
    );
    when(() => core.validateConfig(any())).thenAnswer((_) async => null);
    when(() => core.getConnections())
        .thenAnswer((_) async => [connection(a), connection(b)]);
    when(() => core.closeConnection(any())).thenAnswer((_) async {});
    when(() => core.closeConnections()).thenAnswer((_) async {});
    final container = ProviderContainer(
      overrides: [
        currentProfileIdProvider.overrideWithBuild((_, _) => profile.id),
        profilesProvider.overrideWith(() => TestProfiles([profile])),
        setupActionProvider.overrideWith(() => setup),
        coreHandlerProvider.overrideWithValue(CoreController.scoped(core)),
      ],
    );
    addTearDown(container.dispose);
    globalState.container = container;
    await controller.start(allowed: true);
    expect(setup.applies, 1);

    await bridge.saveSelection(
      PhotonProxySelection(excludedNodes: {'node-1.example.'}),
    );
    expect(setup.applies, 1);
    expect(await file.readAsString(), saved);

    backend.sample['tunnel_ready'] = false;
    backend.serviceSample = _directory([1, 2, 3]);
    await controller.refresh();
    backend.statusError = TimeoutException('status timed out');
    await controller.refresh();
    expect(setup.applies, 1);
    expect(await file.readAsString(), saved);
    verifyNever(() => core.closeConnections());

    backend.statusError = null;
    backend.sample['tunnel_ready'] = true;
    backend.serviceSample = _directory([2, 3]);
    await controller.refresh();
    expect(setup.applies, 2);
    expect(await file.readAsString(), saved);
    expect(running.last['proxies'], [
      {'name': a, 'type': 'reject'},
      originalProxies.last,
    ]);
    verify(() => core.closeConnection(a)).called(1);
    verifyNever(() => core.closeConnection(b));
    verifyNever(() => core.closeConnections());

    failNextApply = true;
    await expectLater(bridge.apply(), throwsA(isA<StateError>()));
    expect(await file.readAsString(), saved);
    expect(running.last['proxies'], [
      {'name': a, 'type': 'reject'},
      originalProxies.last,
    ]);
    verifyNever(() => core.closeConnections());

    backend.serviceSample = _directory([2, 3]);
    await controller.refresh();
    await bridge.apply();
    final applied = await file.readAsString();
    expect(
      (jsonDecode(applied)['proxies'] as List).map((proxy) => proxy['server']),
      ['192.0.2.2', '192.0.2.3'],
    );
    verify(() => core.closeConnections()).called(1);
    final applyCount = setup.applies;
    backend.serviceSample = _directory([1, 2, 3]);
    await controller.refresh();
    expect(setup.applies, applyCount);
    expect(await file.readAsString(), applied);
  });

  test(
    'a rejected offline template recovers without applying draft deletion',
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
      expect(pushes, hasLength(2));
      expect(pushes.last, recovered);
    },
  );
}
