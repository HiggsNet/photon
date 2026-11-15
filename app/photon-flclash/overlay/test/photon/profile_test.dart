import 'dart:convert';

import 'package:fl_clash/common/common.dart';
import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/models/models.dart';
import 'package:fl_clash/photon/profile.dart';
import 'package:fl_clash/photon/services.dart';
import 'package:flutter_test/flutter_test.dart';

import 'services_test.dart' show directoryFixture;

Map<String, dynamic> _profile({
  bool underlay = true,
  Map<String, dynamic>? dns,
}) {
  final now = DateTime.now();
  final directory = PhotonDirectory.fromJson({
    ...directoryFixture(now: now),
    'underlay_routing': underlay,
    'overlay_prefixes': ['fd42::/16'],
  });
  return photonProxyProfile(
    directory: directory,
    now: now,
    splitRoutes: [],
    adapter: directory.adapterName,
    backendPath: r'C:\Photon\photon-windows.exe',
    template: {
      'dns':
          dns ??
          {
            'nameserver': ['https://template.example/dns-query'],
            'respect-rules': true,
            'fake-ip-filter': ['+.example'],
            'nameserver-policy': {'+.example': 'system'},
          },
      'tun': {
        'enable': true,
        'device': 'Template TUN',
        'mtu': 1400,
        'strict-route': true,
        'dns-mode': 'native',
        'route-exclude-address': ['198.51.100.0/24'],
      },
      'rules': ['MATCH,Photon'],
    },
  );
}

void main() {
  test('template DNS/TUN survive rendering without mutating user policy', () {
    final profile = _profile();
    expect(profile['dns'], containsPair('respect-rules', true));
    expect((profile['dns'] as Map)['nameserver'], [
      'https://template.example/dns-query',
    ]);
    expect((profile['dns'] as Map)['fake-ip-filter'], ['+.example']);
    expect((profile['dns'] as Map)['nameserver-policy'], {
      '+.example': 'system',
    });
    expect((profile['tun'] as Map)['mtu'], 1400);
    expect((profile['tun'] as Map)['dns-mode'], 'native');
    expect(
      (profile['tun'] as Map)['route-exclude-address'],
      containsAll([
        '198.51.100.0/24',
        'fd42::/16',
        'fd42:1::20/128',
        'fd42:1::21/128',
      ]),
    );
    final before = jsonEncode(profile);
    expect(protectPhotonProxyProfile(profile), profile);
    expect(jsonEncode(profile), before);
  });

  for (final blocked in [false, true]) {
    test(
      'FlClash overrides precede Photon safeguards (blocked=$blocked)',
      () async {
        final generated = _profile();
        final source = blocked ? blockedPhotonProfile(generated) : generated;
        final result = await makePhotonProfileTask(
          MakeRealProfileState(
            profilesPath: '/tmp/photon-template-tests',
            profileId: 1,
            rawConfig: source,
            realPatchConfig: const PatchClashConfig(
              tun: Tun(
                enable: false,
                device: 'App TUN',
                stack: TunStack.system,
              ),
            ),
            overrides: const ProfileOverrides(
              dns: Dns(nameserver: ['https://override.example/dns-query']),
              dnsOverrideKeys: {DnsOverrideKey.nameserver},
              tun: ProfileTun(
                mtu: 1300,
                routeExcludeAddress: ['203.0.113.0/24', 'fd42::/16'],
              ),
              tunOverrideKeys: {
                TunOverrideKey.mtu,
                TunOverrideKey.routeExcludeAddress,
              },
            ),
            appendSystemDns: false,
            proxyGroups: const [],
            rules: const [],
            addedRules: [Rule.parse('IP-CIDR6,fd42::/16,REJECT,no-resolve')],
            defaultUA: 'Photon-Test',
          ),
        );
        final config = Map<String, dynamic>.from(
          loadPlainYaml(result.yaml) as Map,
        );
        final tun = config['tun'] as Map;
        expect(tun['enable'], isFalse);
        expect(tun['device'], 'App TUN');
        expect(tun['stack'], 'system');
        expect(tun['mtu'], 1300);
        expect(tun['strict-route'], isTrue);
        expect(tun['dns-mode'], 'native');
        expect(tun['route-exclude-address'], [
          '203.0.113.0/24',
          'fd42::/16',
          'fd42:1::20/128',
          'fd42:1::21/128',
        ]);
        final dns = config['dns'] as Map;
        expect(dns['nameserver'], ['https://override.example/dns-query']);
        expect(dns['respect-rules'], isTrue);
        expect(dns['nameserver-policy'], {'+.example': 'system'});
        final rules = config['rules'] as List;
        expect(
          rules.indexOf('IP-CIDR6,fd42::/16,DIRECT,no-resolve'),
          lessThan(rules.indexOf('IP-CIDR6,fd42::/16,REJECT,no-resolve')),
        );
        expect(
          rules.where((rule) => rule == 'IP-CIDR6,fd42::/16,DIRECT,no-resolve'),
          hasLength(1),
        );
        final payload =
            (config['proxy-providers'] as Map)['photon-services']['payload']
                as List;
        if (blocked) {
          expect(payload, [
            {'name': 'Photon Offline', 'type': 'reject'},
          ]);
        } else {
          expect(payload, hasLength(2));
          expect(
            payload.map((proxy) => proxy['interface-name']),
            everyElement('Photon Test'),
          );
        }
        expect(config.containsKey('x-photon-protection'), isFalse);
        expect(result.md5, result.yaml.toMd5());
        expect(result.counts, configCountsOf(config));
      },
    );
  }

  for (final mode in ['blacklist', 'whitelist', 'rule']) {
    test('legacy gateway DNS survives overrides in $mode mode', () {
      final source = _profile(underlay: false);
      final filter = mode == 'rule'
          ? ['MATCH,fake-ip']
          : ['+.example', '*.lan'];
      final finalConfig = protectPhotonProxyProfile({
        ...source,
        'dns': {
          'fake-ip-filter-mode': mode,
          'fake-ip-filter': filter,
          'nameserver-policy': {
            'gateway.example': 'system',
            '+.example': 'system',
          },
        },
      }, source: source);
      final dns = finalConfig['dns'] as Map;
      expect(
        (dns['nameserver-policy'] as Map)['gateway.example'],
        everyElement(endsWith('#DIRECT')),
      );
      expect((dns['nameserver-policy'] as Map)['+.example'], 'system');
      if (mode == 'blacklist') {
        expect(dns['fake-ip-filter'], [
          '+.example',
          '*.lan',
          'gateway.example',
        ]);
      } else {
        expect(dns['fake-ip-filter-mode'], 'rule');
        expect(
          (dns['fake-ip-filter'] as List).first,
          'DOMAIN,gateway.example,real-ip',
        );
        if (mode == 'whitelist') {
          expect((dns['fake-ip-filter'] as List).last, 'MATCH,real-ip');
          final regexRule = (dns['fake-ip-filter'] as List)[1] as String;
          final regex = RegExp(
            regexRule.substring(
              'DOMAIN-REGEX,'.length,
              regexRule.lastIndexOf(','),
            ),
          );
          expect(regex.hasMatch('example'), isTrue);
          expect(regex.hasMatch('one.two.example'), isTrue);
          expect(regex.hasMatch('otherexample'), isFalse);
        }
      }
      expect(protectPhotonProxyProfile(finalConfig), finalConfig);
    });
  }

  test('already stored profiles retain safeguards without new metadata', () {
    final old = _profile(underlay: false)..remove('x-photon-protection');
    final config = protectPhotonProxyProfile(
      {
        ...old,
        'tun': {'enable': true, 'route-exclude-address': <String>[]},
        'rules': ['MATCH,REJECT'],
      },
      source: old,
      stripMetadata: true,
    );
    expect(
      (config['tun'] as Map)['route-exclude-address'],
      old['tun']['route-exclude-address'],
    );
    expect((config['tun'] as Map)['enable'], isTrue);
    expect((config['rules'] as List).last, 'MATCH,REJECT');
  });

  test('template rejects DNS/TUN sections of the wrong type', () {
    for (final key in ['dns', 'tun']) {
      expect(
        () => validatePhotonProxyTemplate({
          'rules': ['MATCH,Photon'],
          key: [],
        }),
        throwsFormatException,
      );
    }
  });
}
