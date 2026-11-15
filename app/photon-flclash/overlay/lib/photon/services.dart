import 'dart:convert';
import 'dart:io';

const _photonProvider = 'photon-services';
const _photonGroups = ['Photon', 'Photon Auto', 'Photon Balance'];
const _photonProtection = 'x-photon-protection';

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
    required this.underlayRouting,
    required this.overlayPrefixes,
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
      underlayRouting: data['underlay_routing'] == true,
      overlayPrefixes: List<String>.from(
        data['overlay_prefixes'] as List? ?? [],
      ),
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
  final bool underlayRouting;
  final List<String> overlayPrefixes;
  final List<String> bypassPrefixes;
  final List<String> bypassDomains;

  bool fresh(DateTime now) =>
      now.toUtc().isBefore(validUntil) &&
      !observedAt.isAfter(now.toUtc().add(const Duration(seconds: 5)));
  Iterable<PhotonEndpoint> get endpoints => services
      .where((entry) => entry.status == 'active')
      .expand((entry) => entry.endpoints);

  /// A signed publication identifies an owner; an Anycast proxy identifies a
  /// destination. Keep the publications for diagnostics, but inject each shared
  /// destination only once, with a name that survives publisher changes.
  List<PhotonEndpoint> get proxyEndpoints {
    final available = endpoints.toList()
      ..sort((a, b) {
        final name = a.name.compareTo(b.name);
        return name != 0 ? name : a.id.compareTo(b.id);
      });
    final seen = <String>{};
    return [
      for (final endpoint in available)
        if (seen.add(
          endpoint.region == 'local'
              ? '${endpoint.owner}\u0000${endpoint.authority}'
              : endpoint.authority,
        ))
          endpoint,
    ];
  }
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
      '${region == 'local' ? owner.replaceFirst(RegExp(r'\.$'), '') : 'Anycast'} / $region / $authority';
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

void validatePhotonProxyTemplate(Map<String, dynamic> template) {
  final rules = template['rules'];
  if (rules is! List ||
      rules.isEmpty ||
      rules.any((rule) => rule is! String || rule.trim().isEmpty)) {
    throw const FormatException('The Photon proxy template needs rules');
  }
  for (final section in ['proxies', 'proxy-groups']) {
    final items = template[section];
    if (items == null) continue;
    if (items is! List ||
        items.any((item) => item is! Map || item['name'] is! String)) {
      throw FormatException('Invalid Photon proxy template section: $section');
    }
    if (items.any((item) => _photonGroups.contains((item as Map)['name']))) {
      throw const FormatException(
        'The Photon proxy template uses a reserved name',
      );
    }
  }
  for (final section in [
    'proxy-providers',
    'rule-providers',
    'sub-rules',
    'dns',
    'tun',
  ]) {
    final value = template[section];
    if (value != null && value is! Map) {
      throw FormatException('Invalid Photon proxy template section: $section');
    }
  }
  if ((template['proxy-providers'] as Map?)?.containsKey(_photonProvider) ==
      true) {
    throw const FormatException(
      'The Photon proxy template uses a reserved name',
    );
  }
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
  final endpoints = directory.proxyEndpoints;
  if (endpoints.isEmpty || adapter.isEmpty) {
    throw StateError('No authorized Photon proxy endpoints are available');
  }
  final exclusions = <String>{
    ...directory.underlayRouting
        ? directory.overlayPrefixes
        : directory.bypassPrefixes,
    ...splitRoutes,
    for (final endpoint in endpoints)
      '${endpoint.address}/${endpoint.address.contains(':') ? 128 : 32}',
  };
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
  return _renderPhotonProxyProfile(
    proxies: proxies,
    exclusions: orderedExclusions,
    bypassDomains: directory.underlayRouting
        ? const []
        : directory.bypassDomains,
    bypassRules: rules,
    template: template,
  );
}

/// Used only by Mihomo's validator when no signed service directory is live.
Map<String, dynamic> photonProxyTemplatePreview(
  Map<String, dynamic> template,
) => _renderPhotonProxyProfile(
  proxies: const [
    {'name': 'Photon Offline', 'type': 'reject'},
  ],
  exclusions: const [],
  bypassDomains: const [],
  bypassRules: const [],
  template: template,
);

Map<String, dynamic> _renderPhotonProxyProfile({
  required List<Map<String, dynamic>> proxies,
  required List<String> exclusions,
  required List<String> bypassDomains,
  required List<String> bypassRules,
  required Map<String, dynamic>? template,
}) {
  final names = proxies.map((proxy) => proxy['name']).toList();
  if (template != null) validatePhotonProxyTemplate(template);
  final templateProxies = template?['proxies'] as List? ?? const [];
  final templateGroups = template?['proxy-groups'] as List? ?? const [];
  final templateProviders = template?['proxy-providers'] as Map? ?? const {};
  final templateRules = template?['rules'] as List?;
  final groupEndpoints = template == null
      ? {'proxies': names}
      : {
          'use': [_photonProvider],
          'empty-fallback': 'REJECT',
        };
  final protection = {
    'route-exclude-address': exclusions,
    'rules': bypassRules,
    'bypass-domains': bypassDomains,
  };
  return protectPhotonProxyProfile({
    'ipv6': true,
    'mode': 'rule',
    'allow-lan': false,
    'dns': {
      'enable': true,
      'ipv6': true,
      'enhanced-mode': 'fake-ip',
      'fake-ip-filter-mode': 'blacklist',
      'fake-ip-filter': <String>[],
      'default-nameserver': ['223.5.5.5', '1.1.1.1'],
      'nameserver': [
        'https://doh.pub/dns-query',
        'https://dns.alidns.com/dns-query',
      ],
      ...?template?['dns'] as Map?,
    },
    'tun': {
      'enable': false,
      'auto-route': true,
      'auto-detect-interface': true,
      'route-exclude-address': exclusions,
      ...?template?['tun'] as Map?,
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
      ...bypassRules,
      ...(templateRules ?? ['MATCH,Photon']),
    ],
    // Persist only the required safeguards, separately from user policy. They
    // must survive a restart/offline profile and be restored after app overrides.
    _photonProtection: protection,
  });
}

/// Runs again after FlClash's overrides, without changing app-owned TUN fields.
/// [source] is the generated profile before those overrides were applied.
Map<String, dynamic> protectPhotonProxyProfile(
  Map<String, dynamic> profile, {
  Map<String, dynamic>? source,
  bool stripMetadata = false,
}) {
  source ??= profile;
  final protection = source[_photonProtection] as Map?;
  // Compatibility with already generated profiles from older clients. Those
  // clients did not accept template DNS/TUN sections, so these are safeguards.
  final routes =
      protection?['route-exclude-address'] as List? ??
      (source['tun'] as Map?)?['route-exclude-address'] as List? ??
      const [];
  final requiredRules =
      protection?['rules'] as List? ??
      [
        for (final rule in source['rules'] as List? ?? const [])
          if (rule is String &&
              ((rule.startsWith('IP-CIDR,') || rule.startsWith('IP-CIDR6,')) &&
                      rule.endsWith(',DIRECT,no-resolve') ||
                  rule.startsWith('PROCESS-PATH-REGEX,') &&
                      rule.endsWith(',DIRECT')))
            rule,
      ];
  final domains =
      protection?['bypass-domains'] as List? ??
      (source['dns'] as Map?)?['fake-ip-filter'] as List? ??
      const [];
  final tun = profile['tun'] as Map? ?? const {};
  final dns = <String, dynamic>{...?profile['dns'] as Map?};
  if (domains.isNotEmpty) {
    final filter = dns['fake-ip-filter'] as List? ?? const [];
    switch (dns['fake-ip-filter-mode'] ?? 'blacklist') {
      case 'rule':
        dns['fake-ip-filter'] = {
          for (final domain in domains) 'DOMAIN,$domain,real-ip',
          ...filter,
        }.toList();
      case 'whitelist':
        // A whitelist has the opposite meaning. Keep its matching semantics
        // while giving legacy gateway domains an explicit real-IP exception.
        dns['fake-ip-filter-mode'] = 'rule';
        dns['fake-ip-filter'] = [
          for (final domain in domains) 'DOMAIN,$domain,real-ip',
          for (final pattern in filter.cast<String>())
            ..._whitelistFakeIPRules(pattern),
          'MATCH,real-ip',
        ];
      default:
        dns['fake-ip-filter'] = {...filter, ...domains}.toList();
    }
    dns['nameserver-policy'] = {
      ...?dns['nameserver-policy'] as Map?,
      for (final domain in domains)
        domain: [
          'https://223.5.5.5/dns-query#DIRECT',
          'https://1.1.1.1/dns-query#DIRECT',
        ],
    };
  }
  return {
    for (final entry in profile.entries)
      if (!stripMetadata || entry.key != _photonProtection)
        entry.key: entry.value,
    'dns': dns,
    'tun': {
      ...tun,
      'route-exclude-address': {
        ...?tun['route-exclude-address'] as List?,
        ...routes,
      }.toList(),
    },
    'rules': [
      ...requiredRules,
      for (final rule in profile['rules'] as List? ?? const [])
        if (!requiredRules.contains(rule)) rule,
    ],
  };
}

Iterable<String> _whitelistFakeIPRules(String pattern) sync* {
  for (final prefix in ['geosite:', 'rule-set:']) {
    if (pattern.toLowerCase().startsWith(prefix)) {
      for (final name in pattern.substring(prefix.length).split(',')) {
        yield '${prefix == 'geosite:' ? 'GEOSITE' : 'RULE-SET'},${name.trim()},fake-ip';
      }
      return;
    }
  }
  final suffix = pattern.startsWith('+.') || pattern.startsWith('.');
  final domain = suffix ? pattern.substring(pattern.indexOf('.') + 1) : pattern;
  final labels = domain
      .split('.')
      .map((label) => label == '*' ? r'[^.]+' : RegExp.escape(label))
      .join(r'\.');
  final subdomains = suffix
      ? pattern.startsWith('+.')
            ? r'([^.]+\.)*'
            : r'([^.]+\.)+'
      : '';
  yield 'DOMAIN-REGEX,^$subdomains$labels\$,fake-ip';
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
    _photonProtection: ?profile[_photonProtection],
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
