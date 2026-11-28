import 'dart:convert';
import 'dart:io';

import 'package:fl_clash/common/common.dart';
import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/features/form/form.dart' show FormPage;
import 'package:fl_clash/main.dart' as application;
import 'package:fl_clash/photon/controller.dart';
import 'package:fl_clash/photon/proxy_bridge.dart';
import 'package:fl_clash/photon/services.dart';
import 'package:fl_clash/photon/services_view.dart';
import 'package:fl_clash/photon/template_view.dart';
import 'package:fl_clash/photon/view.dart';
import 'package:fl_clash/providers/providers.dart';
import 'package:fl_clash/state.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:prism_ui/prism_ui.dart' show TextFormField;

import 'socks_probe.dart';

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
      Future<void> phase(String value) async {
        await File('${output.path}/phase.txt').writeAsString(value);
        // Leave the real desktop visible for an independent VM console capture.
        await Future<void>.delayed(const Duration(seconds: 3));
      }

      final originalConfig = await File(_config).readAsBytes();
      final testErrorHandler = FlutterError.onError;
      application.main([]);
      FlutterError.onError = testErrorHandler;

      Future<void> waitFor(
        bool Function() check,
        String description, {
        int seconds = 60,
      }) async {
        final deadline = DateTime.now().add(Duration(seconds: seconds));
        while (!check()) {
          if (DateTime.now().isAfter(deadline)) {
            fail('Timed out: $description; Photon: ${photonController.error}');
          }
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
      final originalLogs = container.read(appSettingProvider).openLogs;
      container
          .read(appSettingProvider.notifier)
          .update((state) => state.copyWith(openLogs: true));
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
        final settings = File('${output.path}/settings-copy.yaml');
        await settings.writeAsBytes(originalConfig);
        await photonController.pickConfig(() async => settings.path);
        await tester.pump();
        final photonPage = find.byType(PhotonView);
        await tester.tap(
          find.descendant(of: photonPage, matching: find.text(labels.settings)),
        );
        final editSettings = find.descendant(
          of: photonPage,
          matching: find.text(labels.edit),
        );
        await waitFor(() => editSettings.evaluate().isNotEmpty, 'Settings tab');
        await tester.tap(editSettings);
        await waitFor(
          () => find.byType(FormPage).evaluate().isNotEmpty,
          'settings form',
        );
        await tester.pump(const Duration(milliseconds: 400));
        await phase('settings-open');
        final logLevel = find.descendant(
          of: find.byKey(const ValueKey('log_level')),
          matching: find.byType(TextFormField),
        );
        await tester.scrollUntilVisible(
          logLevel,
          240,
          scrollable: find
              .descendant(
                of: find.byType(FormPage),
                matching: find.byType(Scrollable),
              )
              .first,
        );
        final previous = tester.widget<TextFormField>(logLevel).initialValue;
        final level = previous == 'debug' ? 'info' : 'debug';
        await tester.enterText(logLevel, level);
        await tester.tap(find.text(labels.save).hitTestable());
        await waitFor(
          () =>
              find.byType(FormPage).evaluate().isEmpty &&
              !photonController.busy,
          'settings saved',
        );
        expect(await settings.readAsString(), contains('level: $level'));
        expect(await File(_config).readAsBytes(), originalConfig);
        results['settings_form_saved'] = true;
        await phase('settings-saved');
        await photonController.pickConfig(() async => _config);
        await tester.pump();
        await tester.tap(find.text(labels.photonConnect));
        await waitFor(
          () => photonController.observation?['tunnel_ready'] == true,
          'existing identity admission and tunnel',
        );
        results['connected'] = photonController.observation;
        await phase('connected');
        final tabs = [
          labels.photonTunnel,
          labels.photonGossipPeers,
          labels.photonRoutes,
          labels.photonDiagnostics,
        ];
        for (final label in tabs) {
          await tester.tap(find.text(label).first);
          await tester.pump(const Duration(milliseconds: 400));
          expect(find.byType(PhotonView), findsOneWidget);
          await phase('tab-$label');
        }
        final page = container.read(currentPageLabelProvider.notifier);
        page.toPage(PageLabel.photonTemplate);
        await waitFor(
          () => find.byType(PhotonTemplateView).evaluate().isNotEmpty,
          'Template page',
        );
        expect(find.text(labels.photonEditTemplate), findsOneWidget);
        await phase('page-template');
        page.toPage(PageLabel.photonServices);
        await waitFor(
          () => find.byType(PhotonServicesView).evaluate().isNotEmpty,
          'Services page',
        );
        await phase('page-services');
        final directory = photonController.directory!;
        final selection = await photonProxyBridge.loadSelection();
        final available = directory.proxyEndpoints
            .where(
              (endpoint) => selection.allows(
                type: endpoint.type,
                region: endpoint.region,
                owner: endpoint.owner,
              ),
            )
            .toList();
        final wanted = {
          'bgp-vultr-lax.catofes.',
          'chair-misaka-sin.catofes.',
          'neutron-linode-hnd.catofes.',
        };
        final endpoints = available
            .where(
              (endpoint) =>
                  endpoint.type == 'socks5' &&
                  endpoint.region == 'local' &&
                  wanted.contains(endpoint.owner),
            )
            .toList();
        expect(endpoints, hasLength(3));
        final scrollable = find
            .descendant(
              of: find.byType(PhotonServicesView),
              matching: find.byType(Scrollable),
            )
            .first;
        await tester.scrollUntilVisible(
          find.text(labels.photonApply),
          -400,
          scrollable: scrollable,
          maxScrolls: 30,
        );
        final setup = container.read(setupActionProvider.notifier);
        await setup.setRunning(false);
        await tester.tap(find.text(labels.photonApply));
        await waitFor(
          () =>
              photonProxyBridge.ready &&
              container.read(currentProfileProvider)?.url ==
                  photonProfileSource &&
              !photonController.busy,
          'proxy profile activation',
          seconds: 90,
        );
        expect(container.read(isStartProvider), isFalse);
        expect(
          container.read(networkSettingProvider).systemProxy,
          originalProxy,
        );
        container
            .read(networkSettingProvider.notifier)
            .update((state) => state.copyWith(systemProxy: true));
        expect(await setup.setRunning(true), isTrue);
        final generated = await container
            .read(coreHandlerProvider)
            .readConfig(container.read(currentProfileIdProvider)!);
        final proxies = (generated['proxies'] as List).cast<Map>();
        (Object?, Object?, Object?) destination(Map proxy) =>
            (proxy['type'], proxy['server'], proxy['port']);
        String proxyName(PhotonEndpoint endpoint) =>
            proxies.singleWhere(
                  (proxy) =>
                      destination(proxy) ==
                      (endpoint.type, endpoint.address, endpoint.port),
                )['name']
                as String;
        expect(
          proxies.map(destination),
          unorderedEquals(
            available.map(
              (endpoint) => (endpoint.type, endpoint.address, endpoint.port),
            ),
          ),
        );
        await phase('all-authorized-proxies');
        final port = container.read(patchClashConfigProvider).mixedPort;
        final traces = <Map<String, dynamic>>[];
        for (final endpoint in endpoints) {
          await container
              .read(proxiesActionProvider.notifier)
              .changeProxy(groupName: 'Photon', proxyName: proxyName(endpoint));
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
          try {
            traces.last['udp_dns'] = await probeSocksUDP(port);
          } catch (error) {
            traces.last['udp_error'] = '$error';
          }
        }
        results['proxy_traces'] = traces;
        expect(
          traces.where((trace) => trace.containsKey('udp_dns')),
          isNotEmpty,
          reason: 'At least one selected exit must relay a real UDP DNS query',
        );
        final groupTraces = <Map<String, dynamic>>[];
        for (final group in ['Photon Auto', 'Photon Balance']) {
          await container
              .read(proxiesActionProvider.notifier)
              .changeProxy(groupName: 'Photon', proxyName: group);
          final probe = await Process.run('curl.exe', [
            '--silent',
            '--show-error',
            '--max-time',
            '20',
            '--proxy',
            'http://127.0.0.1:$port',
            'https://www.cloudflare.com/cdn-cgi/trace',
          ]);
          groupTraces.add({
            'group': group,
            'exit_code': probe.exitCode,
            'trace': probe.stdout,
            'error': probe.stderr,
          });
          expect(probe.exitCode, 0, reason: '$group: ${probe.stderr}');
        }
        results['group_traces'] = groupTraces;
        await container
            .read(proxiesActionProvider.notifier)
            .changeProxy(
              groupName: 'Photon',
              proxyName: proxyName(endpoints.first),
            );
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
        await waitFor(
          () =>
              photonController.observation?['tunnel_ready'] == true &&
              photonProxyBridge.ready,
          'tunnel remains ready after proxy TUN activation',
        );
        final network = await Process.run('powershell.exe', [
          '-NoProfile',
          '-NonInteractive',
          '-Command',
          r'Get-NetAdapter -IncludeHidden | Where-Object {$_.Name -eq "Photon Windows Test" -or $_.Name -eq "FlClash"} | Select-Object Name,Status,InterfaceIndex | ConvertTo-Json',
        ]);
        results['dual_tun_adapters'] = network.stdout;
        results['after_tun_observation'] = photonController.observation;
        await phase('dual-tun');
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
        final routing = await Process.run('powershell.exe', [
          '-NoProfile',
          '-NonInteractive',
          '-Command',
          r"@('1.1.1.1','123.57.143.66','2a0d:2905:1:a::20') | ForEach-Object { Find-NetRoute -RemoteIPAddress $_ } | Select-Object IPAddress,DestinationPrefix,NextHop,InterfaceIndex,InterfaceAlias,RouteMetric | ConvertTo-Json",
        ]);
        results['routes'] = routing.stdout;
        final proxyAfterTun = await Process.run('curl.exe', [
          '--silent',
          '--show-error',
          '--max-time',
          '20',
          '--proxy',
          'http://127.0.0.1:$port',
          'https://www.cloudflare.com/cdn-cgi/trace',
        ]);
        results['proxy_after_tun'] = {
          'exit_code': proxyAfterTun.exitCode,
          'trace': proxyAfterTun.stdout,
          'error': proxyAfterTun.stderr,
        };
        if (direct.exitCode != 0) {
          final alternatives = <Map<String, dynamic>>[];
          for (final stack in [
            TunStack.gvisor,
            TunStack.system,
            TunStack.mixed,
          ]) {
            container
                .read(patchClashConfigProvider.notifier)
                .update((state) => state.copyWith.tun(stack: stack));
            await container
                .read(setupActionProvider.notifier)
                .applyProfile(force: true);
            await Future<void>.delayed(const Duration(seconds: 3));
            final probe = await Process.run('curl.exe', [
              '--silent',
              '--show-error',
              '--max-time',
              '15',
              '--noproxy',
              '*',
              'https://www.cloudflare.com/cdn-cgi/trace',
            ]);
            alternatives.add({
              'stack': stack.name,
              'exit_code': probe.exitCode,
              'trace': probe.stdout,
              'error': probe.stderr,
            });
          }
          results['tun_stack_diagnostics'] = alternatives;
        }
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
        results['core_logs'] = container
            .read(logsProvider)
            .list
            .map((log) => log.toJson())
            .toList();
        results['connections'] =
            (await container.read(coreHandlerProvider).getConnections())
                .map((connection) => connection.toJson())
                .toList();
        expect(direct.exitCode, 0, reason: '${direct.stderr}');
        expect(ping.exitCode, 0);
        expect(photonController.observation?['tunnel_ready'], isTrue);
        await setup.setRunning(false);
        expect(photonController.observation?['tunnel_ready'], isTrue);
        expect(await setup.setRunning(true), isTrue);
        await photonController.stop();
        expect(photonController.hasLease, isFalse);
        expect(container.read(isStartProvider), isTrue);
        expect(await setup.setRunning(false), isTrue);
        expect(await setup.setRunning(true), isTrue);
        expect(photonController.hasLease, isFalse);
        final offline = await Process.run('curl.exe', [
          '--silent',
          '--show-error',
          '--max-time',
          '10',
          '--proxy',
          'http://127.0.0.1:$port',
          'https://www.cloudflare.com/cdn-cgi/trace',
        ]);
        expect(offline.exitCode, isNot(0));
        results['independent_switches'] = true;
        await photonController.start(allowed: true);
        await waitFor(
          () => photonController.observation?['tunnel_ready'] == true,
          'Photon reconnect',
        );
        await waitFor(
          () => photonProxyBridge.ready && container.read(isStartProvider),
          'proxy recovery after Photon reconnect',
        );
        final recovered = await Process.run('curl.exe', [
          '--silent',
          '--show-error',
          '--max-time',
          '20',
          '--noproxy',
          '*',
          'https://www.cloudflare.com/cdn-cgi/trace',
        ]);
        results['reconnected_tun'] = {
          'exit_code': recovered.exitCode,
          'trace': recovered.stdout,
          'error': recovered.stderr,
        };
        final directSocks = await Process.run('curl.exe', [
          '--silent',
          '--show-error',
          '--max-time',
          '20',
          '--proxy',
          'socks5h://${endpoints.first.authority}',
          'https://www.cloudflare.com/cdn-cgi/trace',
        ]);
        results['reconnect_direct_socks'] = {
          'exit_code': directSocks.exitCode,
          'trace': directSocks.stdout,
          'error': directSocks.stderr,
        };
        results['reconnect_observation'] = photonController.observation;
        results['reconnect_core_logs'] = container
            .read(logsProvider)
            .list
            .map((log) => log.toJson())
            .toList();
        expect(recovered.exitCode, 0, reason: '${recovered.stderr}');
        await File('${output.path}/result.json')
            .writeAsString(const JsonEncoder.withIndent('  ').convert(results));
      } finally {
        final form = find.byType(FormPage);
        if (form.evaluate().isNotEmpty) {
          Navigator.of(tester.element(form)).pop();
          await waitFor(() => !photonController.busy, 'settings closed');
        }
        results['controller_error'] = photonController.error?.toString();
        await photonController.stop();
        results['stop_error'] = photonController.error?.toString();
        await photonController.pickConfig(() async => _config);
        container
            .read(patchClashConfigProvider.notifier)
            .update((state) => state.copyWith(tun: originalTun));
        container
            .read(networkSettingProvider.notifier)
            .update((state) => state.copyWith(systemProxy: originalProxy));
        await container.read(setupActionProvider.notifier).setRunning(false);
        container
            .read(appSettingProvider.notifier)
            .update((state) => state.copyWith(openLogs: originalLogs));
        await Future<void>.delayed(const Duration(seconds: 3));
        await tester.pump();
        await preferences.saveConfig(container.read(configProvider));
        expect(await File(_config).readAsBytes(), originalConfig);
        await File('${output.path}/partial-result.json')
            .writeAsString(const JsonEncoder.withIndent('  ').convert(results));
        await container.read(coreHandlerProvider).close();
      }
    },
    timeout: const Timeout(Duration(minutes: 10)),
  );
}
