import 'dart:convert';
import 'dart:io';

const _photonProvider = 'photon-services';
const _photonGroups = ['Photon', 'Photon Auto', 'Photon Balance'];

final class PhotonDirectory {
  PhotonDirectory._({
    required this.instanceID,
    required this.rootFingerprint,
    required this.managedZone,
    required this.revision,
    required this.observedAt,
    required this.validUntil,
    required this.services,
    required this.adapterName,
    required this.bypassPrefixes,
    required this.bypassDomains,
  });

  factory PhotonDirectory.fromJson(Map<String, dynamic> data) {
    final observed = DateTime.parse(_string(data, 'observed_at')).toUtc();
    final until = DateTime.parse(_string(data, 'valid_until')).toUtc();
    final root = _string(data, 'root_fingerprint');
    final revision = data['revision'];
    final raw = data['services'];
    if (!RegExp(r'^[0-9a-f]{64}$').hasMatch(root) ||
        revision is! int ||
        revision < 0 ||
        raw is! List ||
        until.isBefore(observed) ||
        until.difference(observed) > const Duration(seconds: 5)) {
      throw const FormatException('Invalid Photon service snapshot');
    }
    final entries = raw
        .map(
          (value) =>
              PhotonService.fromJson(Map<String, dynamic>.from(value as Map)),
        )
        .toList();
    final ids = <String>{};
    for (final entry in entries) {
      for (final endpoint in entry.endpoints) {
        if (!ids.add(endpoint.id)) {
          throw const FormatException('Duplicate service endpoint identity');
        }
      }
    }
    return PhotonDirectory._(
      instanceID: _string(data, 'instance_id'),
      rootFingerprint: root,
      managedZone: _string(data, 'managed_zone'),
      revision: revision,
      observedAt: observed,
      validUntil: until,
      services: List.unmodifiable(entries),
      adapterName: data['adapter_name'] as String? ?? '',
      bypassPrefixes: List<String>.from(data['bypass_prefixes'] as List? ?? []),
      bypassDomains: List<String>.from(data['bypass_domains'] as List? ?? []),
    );
  }

  final String instanceID;
  final String rootFingerprint;
  final String managedZone;
  final int revision;
  final DateTime observedAt;
  final DateTime validUntil;
  final List<PhotonService> services;
  final String adapterName;
  final List<String> bypassPrefixes;
  final List<String> bypassDomains;

  bool fresh(DateTime now) =>
      now.toUtc().isBefore(validUntil) &&
      !observedAt.isAfter(now.toUtc().add(const Duration(seconds: 5)));
  Iterable<PhotonEndpoint> get endpoints => services
      .where((entry) => entry.status == 'active')
      .expand((entry) => entry.endpoints);
}

final class PhotonService {
  PhotonService({
    required this.id,
    required this.owner,
    required this.status,
    required this.diagnostic,
    required this.endpoints,
  });

  factory PhotonService.fromJson(Map<String, dynamic> data) {
    final owner = _string(data, 'owner');
    final status = _string(data, 'status');
    final raw = data['endpoints'];
    if (!const {
          'active',
          'withdrawn',
          'unauthorized',
          'untrusted',
          'invalid',
        }.contains(status) ||
        raw is! List) {
      throw const FormatException('Invalid Photon service entry');
    }
    final endpoints = raw
        .map(
          (value) => PhotonEndpoint.fromJson(
            owner,
            Map<String, dynamic>.from(value as Map),
          ),
        )
        .toList();
    if ((status == 'active') != endpoints.isNotEmpty) {
      throw const FormatException('Invalid Photon endpoint availability');
    }
    return PhotonService(
      id: _string(data, 'id'),
      owner: owner,
      status: status,
      diagnostic: data['diagnostic'] as String? ?? '',
      endpoints: List.unmodifiable(endpoints),
    );
  }

  final String id;
  final String owner;
  final String status;
  final String diagnostic;
  final List<PhotonEndpoint> endpoints;
}

final class PhotonEndpoint {
  PhotonEndpoint({
    required this.id,
    required this.owner,
    required this.region,
    required this.address,
    required this.port,
  });

  factory PhotonEndpoint.fromJson(String owner, Map<String, dynamic> data) {
    final id = _string(data, 'id');
    final address = _string(data, 'address');
    final port = data['port'];
    if (!RegExp(r'^[0-9a-f]{32}$').hasMatch(id) ||
        InternetAddress.tryParse(address) == null ||
        port is! int ||
        port < 1 ||
        port > 65535) {
      throw const FormatException('Invalid Photon proxy endpoint');
    }
    return PhotonEndpoint(
      id: id,
      owner: owner,
      region: _string(data, 'region'),
      address: address,
      port: port,
    );
  }

  final String id;
  final String owner;
  final String region;
  final String address;
  final int port;

  String get name =>
      '${owner.replaceFirst(RegExp(r'\.$'), '')} / $region / $authority';
  String get authority =>
      address.contains(':') ? '[$address]:$port' : '$address:$port';
}

String _string(Map<String, dynamic> data, String key) {
  final value = data[key];
  if (value is! String || value.isEmpty || value.length > 1024) {
    throw FormatException('Invalid Photon $key');
  }
  return value;
}

Map<String, dynamic> photonProxyProfile({
  required PhotonDirectory directory,
  required DateTime now,
  required List<String> splitRoutes,
  required String adapter,
  required String backendPath,
  Map<String, dynamic>? template,
}) {
  if (!directory.fresh(now)) {
    throw StateError('Photon service information expired');
  }
  final endpoints = directory.endpoints.toList()
    ..sort((a, b) => a.id.compareTo(b.id));
  if (endpoints.isEmpty || adapter.isEmpty) {
    throw StateError('No authorized Photon proxy endpoints are available');
  }
  final exclusions = <String>{
    ...directory.bypassPrefixes,
    ...splitRoutes,
    for (final endpoint in endpoints)
      '${endpoint.address}/${endpoint.address.contains(':') ? 128 : 32}',
  };
  final names = endpoints.map((endpoint) => endpoint.name).toList();
  final orderedExclusions = exclusions.toList()..sort();
  final rules = <String>[
    for (final prefix in orderedExclusions)
      '${prefix.contains(':') ? 'IP-CIDR6' : 'IP-CIDR'},$prefix,DIRECT,no-resolve',
    'PROCESS-PATH-REGEX,${RegExp.escape(backendPath).replaceAll(',', r'\x2c')},DIRECT',
  ];
  final proxies = [
    for (final endpoint in endpoints)
      {
        'name': endpoint.name,
        'type': 'socks5',
        'server': endpoint.address,
        'port': endpoint.port,
        'udp': true,
        'interface-name': adapter,
      },
  ];
  final templateProxies = template?['proxies'] as List? ?? const [];
  final templateGroups = template?['proxy-groups'] as List? ?? const [];
  final templateProviders = template?['proxy-providers'] as Map? ?? const {};
  final templateRules = template?['rules'] as List?;
  if (template != null) {
    if (templateRules == null || templateRules.isEmpty) {
      throw const FormatException('The Photon proxy template needs rules');
    }
    if (templateProviders.containsKey(_photonProvider) ||
        [
          ...templateProxies,
          ...templateGroups,
        ].any((item) => _photonGroups.contains((item as Map)['name']))) {
      throw const FormatException(
        'The Photon proxy template uses a reserved name',
      );
    }
  }
  final groupEndpoints = template == null
      ? {'proxies': names}
      : {
          'use': [_photonProvider],
          'empty-fallback': 'REJECT',
        };
  return {
    'ipv6': true,
    'mode': 'rule',
    'allow-lan': false,
    'dns': {
      'enable': true,
      'ipv6': true,
      'enhanced-mode': 'fake-ip',
      'fake-ip-filter-mode': 'blacklist',
      'fake-ip-filter': directory.bypassDomains,
      'default-nameserver': ['223.5.5.5', '1.1.1.1'],
      'nameserver': [
        'https://doh.pub/dns-query',
        'https://dns.alidns.com/dns-query',
      ],
      'nameserver-policy': {
        for (final domain in directory.bypassDomains)
          domain: [
            'https://223.5.5.5/dns-query#DIRECT',
            'https://1.1.1.1/dns-query#DIRECT',
          ],
      },
    },
    'tun': {
      'enable': false,
      'auto-route': true,
      'auto-detect-interface': true,
      'route-exclude-address': orderedExclusions,
    },
    'proxies': template == null ? proxies : templateProxies,
    if (template != null)
      'proxy-providers': {
        ...templateProviders,
        _photonProvider: {
          'type': 'inline',
          'payload': proxies,
          'health-check': {
            'enable': true,
            'url': 'https://www.gstatic.com/generate_204',
            'interval': 300,
          },
        },
      },
    if (template?['rule-providers'] case final Map providers)
      'rule-providers': providers,
    if (template?['sub-rules'] case final Map subRules) 'sub-rules': subRules,
    'proxy-groups': [
      ...templateGroups,
      {
        'name': 'Photon',
        'type': 'select',
        ...groupEndpoints,
        'proxies': [
          'Photon Auto',
          'Photon Balance',
          if (template == null) ...names,
        ],
      },
      {
        'name': 'Photon Auto',
        'type': 'url-test',
        ...groupEndpoints,
        'url': 'https://www.gstatic.com/generate_204',
        'interval': 300,
        'tolerance': 80,
      },
      {
        'name': 'Photon Balance',
        'type': 'load-balance',
        'strategy': 'consistent-hashing',
        ...groupEndpoints,
        'url': 'https://www.gstatic.com/generate_204',
        'interval': 300,
      },
    ],
    'rules': [
      ...rules,
      ...(templateRules ?? ['MATCH,Photon']),
    ],
  };
}

String encodePhotonProfile(Map<String, dynamic> profile) =>
    const JsonEncoder.withIndent('  ').convert(profile);

Map<String, dynamic> blockedPhotonProfile(Map<String, dynamic> profile) {
  final providers = profile['proxy-providers'];
  if (providers is Map && providers.containsKey(_photonProvider)) {
    return {
      ...profile,
      'proxy-providers': {
        ...providers,
        _photonProvider: {
          'type': 'inline',
          'payload': [
            {'name': 'Photon Offline', 'type': 'reject'},
          ],
        },
      },
      'proxy-groups': [
        for (final group in profile['proxy-groups'] as List)
          if (_photonGroups.contains((group as Map)['name']))
            {
              'name': group['name'],
              'type': 'select',
              'proxies': ['REJECT'],
            }
          else
            group,
      ],
    };
  }
  return {
    'ipv6': true,
    'dns': ?profile['dns'],
    'tun': ?profile['tun'],
    'rules': [
      for (final rule in profile['rules'] as List? ?? const [])
        if (rule is String &&
            ((rule.startsWith('IP-CIDR,') || rule.startsWith('IP-CIDR6,')) &&
                    rule.endsWith(',DIRECT,no-resolve') ||
                rule.startsWith('PROCESS-PATH-REGEX,') &&
                    rule.endsWith(',DIRECT')))
          rule,
      'MATCH,REJECT',
    ],
  };
}
