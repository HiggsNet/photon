import 'dart:convert';
import 'dart:io';

import 'package:fl_clash/common/common.dart';
import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/main.dart' as application;
import 'package:fl_clash/photon/controller.dart';
import 'package:fl_clash/photon/proxy_bridge.dart';
import 'package:fl_clash/photon/view.dart';
import 'package:fl_clash/providers/providers.dart';
import 'package:fl_clash/state.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

const _config = String.fromEnvironment('PHOTON_TEST_CONFIG');
const _evidence = String.fromEnvironment('PHOTON_TEST_EVIDENCE');

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets(
    'existing Windows identity, detailed UI, three proxy exits and dual TUN',
    (tester) async {
      if (!Platform.isWindows || _config.isEmpty || _evidence.isEmpty) {
        fail(
          'Run only on the authorized Windows VM with PHOTON_TEST_CONFIG and PHOTON_TEST_EVIDENCE',
        );
      }
      final output = Directory(_evidence);
      await output.create(recursive: true);
      final results = <String, dynamic>{};
      final originalConfig = await File(_config).readAsBytes();
      application.main([]);

      Future<void> waitFor(
        bool Function() check,
        String description, {
        int seconds = 60,
      }) async {
        final deadline = DateTime.now().add(Duration(seconds: seconds));
        while (!check()) {
          if (DateTime.now().isAfter(deadline)) fail('Timed out: $description');
          await tester.pump(const Duration(milliseconds: 100));
          await Future<void>.delayed(const Duration(milliseconds: 100));
        }
        await tester.pump();
      }

      await waitFor(
        () {
          try {
            return globalState.container.read(initProvider);
          } catch (_) {
            return false;
          }
        },
        'application initialization',
        seconds: 120,
      );
      final container = globalState.container;
      final labels = currentAppLocalizations;
      final originalTun = container.read(patchClashConfigProvider).tun;
      final originalProxy = container.read(networkSettingProvider).systemProxy;
      try {
        await photonController.initialize();
        await photonController.pickConfig(() async => _config);
        container
            .read(currentPageLabelProvider.notifier)
            .toPage(PageLabel.photon);
        await waitFor(
          () => find.byType(PhotonView).evaluate().isNotEmpty,
          'Photon page',
        );
        await tester.tap(find.text(labels.start).first);
        await waitFor(
          () => photonController.observation?['tunnel_ready'] == true,
          'existing identity admission and tunnel',
        );
        results['connected'] = photonController.observation;
        final tabs = [
          labels.photonTunnel,
          labels.peers,
          labels.photonRoutes,
          labels.photonDiagnostics,
          labels.photonServices,
        ];
        for (final label in tabs) {
          await tester.tap(find.text(label).first);
          await tester.pump(const Duration(milliseconds: 400));
          expect(find.byType(PhotonView), findsOneWidget);
        }
        final directory = photonController.directory!;
        final wanted = {
          'bgp-vultr-lax.catofes.',
          'chair-misaka-sin.catofes.',
          'neutron-linode-hnd.catofes.',
        };
        final endpoints = directory.endpoints
            .where(
              (endpoint) =>
                  endpoint.region == 'local' && wanted.contains(endpoint.owner),
            )
            .toList();
        expect(endpoints, hasLength(3));
        final scrollable = find
            .descendant(
              of: find.byType(PhotonView),
              matching: find.byType(Scrollable),
            )
            .first;
        for (final endpoint in endpoints) {
          if (photonController.selected.contains(endpoint.id)) continue;
          await tester.scrollUntilVisible(
            find.byKey(ValueKey(endpoint.id)),
            400,
            scrollable: scrollable,
            maxScrolls: 30,
          );
          await tester.tap(find.byKey(ValueKey(endpoint.id)));
          await tester.pump(const Duration(milliseconds: 300));
        }
        expect(
          photonController.selected.containsAll(
            endpoints.map((endpoint) => endpoint.id),
          ),
          isTrue,
        );
        await tester.scrollUntilVisible(
          find.text(labels.photonApply),
          -400,
          scrollable: scrollable,
          maxScrolls: 30,
        );
        await tester.tap(find.text(labels.photonApply));
        await waitFor(
          () =>
              photonProxyBridge.ready &&
              container.read(currentProfileProvider)?.url ==
                  photonProfileSource &&
              container.read(isStartProvider),
          'proxy profile activation',
          seconds: 90,
        );
        final port = container.read(patchClashConfigProvider).mixedPort;
        final traces = <Map<String, dynamic>>[];
        for (final endpoint in endpoints) {
          await container
              .read(proxiesActionProvider.notifier)
              .changeProxy(groupName: 'Photon', proxyName: endpoint.name);
          final result = await Process.run('curl.exe', [
            '--silent',
            '--show-error',
            '--max-time',
            '20',
            '--proxy',
            'http://127.0.0.1:$port',
            'https://www.cloudflare.com/cdn-cgi/trace',
          ]);
          traces.add({
            'owner': endpoint.owner,
            'exit_code': result.exitCode,
            'trace': result.stdout,
            'error': result.stderr,
          });
          expect(
            result.exitCode,
            0,
            reason: '${endpoint.owner}: ${result.stderr}',
          );
          expect(result.stdout as String, contains('ip='));
        }
        results['proxy_traces'] = traces;
        container
            .read(patchClashConfigProvider.notifier)
            .update((state) => state.copyWith.tun(enable: true));
        expect(
          await container
              .read(setupActionProvider.notifier)
              .applyProfile(force: true),
          isTrue,
        );
        await Future<void>.delayed(const Duration(seconds: 5));
        final network = await Process.run('powershell.exe', [
          '-NoProfile',
          '-NonInteractive',
          '-Command',
          r'Get-NetAdapter -IncludeHidden | Where-Object {$_.Name -eq "Photon Windows Test" -or $_.Name -eq "FlClash"} | Select-Object Name,Status,InterfaceIndex | ConvertTo-Json',
        ]);
        results['dual_tun_adapters'] = network.stdout;
        final direct = await Process.run('curl.exe', [
          '--silent',
          '--show-error',
          '--max-time',
          '20',
          '--noproxy',
          '*',
          'https://www.cloudflare.com/cdn-cgi/trace',
        ]);
        results['tun_trace'] = {
          'exit_code': direct.exitCode,
          'trace': direct.stdout,
          'error': direct.stderr,
        };
        expect(direct.exitCode, 0, reason: '${direct.stderr}');
        final ping = await Process.run('ping.exe', [
          '-6',
          '-n',
          '3',
          '-l',
          '1232',
          '-w',
          '2000',
          '2a0d:2905:1:1::1',
        ]);
        results['inner_ipv6_ping'] = {
          'exit_code': ping.exitCode,
          'output': ping.stdout,
        };
        expect(ping.exitCode, 0);
        expect(photonController.observation?['tunnel_ready'], isTrue);
        await File(
          '${output.path}/result.json',
        ).writeAsString(const JsonEncoder.withIndent('  ').convert(results));
      } finally {
        container
            .read(patchClashConfigProvider.notifier)
            .update((state) => state.copyWith(tun: originalTun));
        await photonController.stop();
        container
            .read(networkSettingProvider.notifier)
            .update((state) => state.copyWith(systemProxy: originalProxy));
        await container.read(setupActionProvider.notifier).setRunning(false);
        expect(await File(_config).readAsBytes(), originalConfig);
        await File(
          '${output.path}/partial-result.json',
        ).writeAsString(const JsonEncoder.withIndent('  ').convert(results));
        await container.read(coreHandlerProvider).close();
      }
    },
    timeout: const Timeout(Duration(minutes: 10)),
  );
}
