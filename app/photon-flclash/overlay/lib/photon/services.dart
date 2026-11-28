import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:fl_clash/common/string.dart' show StringExtension;

import 'proxy_selection.dart';
import 'proxy_paths.dart';

const photonServiceProvider = 'photon-services';
const _pathGroup = 'Photon Paths';
const photonProxyGroups = [
  'Photon',
  'Photon Auto',
  'Photon Balance',
  _pathGroup,
];
const _photonProtection = 'x-photon-protection';

typedef PhotonProxyCardTitles = Map<({String? provider, String name}), String>;

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
    required this.proxyPaths,
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
      proxyPaths: List.unmodifiable([
        for (final route in data['proxy_v2_routes'] as List? ?? const [])
          PhotonProxyPath.fromJson(route as Map),
      ]),
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
  final List<PhotonProxyPath> proxyPaths;

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
      ..removeWhere((e) => e.type == 'http' && e.authRequired)
      ..sort((a, b) {
        final order = a._proxyOrder.compareTo(b._proxyOrder);
        return order != 0 ? order : a.id.compareTo(b.id);
      });
    final seen = <String>{};
    return [
      for (final endpoint in available)
        if (seen.add(endpoint._destinationKey)) endpoint,
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
    this.type = 'socks5',
    this.serverName = '',
    this.fingerprint = '',
    this.authRequired = false,
  });

  factory PhotonEndpoint.fromJson(String owner, Map<String, dynamic> data) {
    final id = _string(data, 'id');
    final address = _string(data, 'address');
    final port = data['port'];
    final type = data['type'] as String? ?? 'socks5';
    final serverName = data['server_name'] as String? ?? '';
    final fingerprint = data['fingerprint'] as String? ?? '';
    if (!RegExp(r'^[0-9a-f]{32}$').hasMatch(id) ||
        InternetAddress.tryParse(address) == null ||
        port is! int ||
        port < 1 ||
        port > 65535) {
      throw const FormatException('Invalid Photon proxy endpoint');
    }
    if (!const {'socks5', 'trusttunnel', 'http'}.contains(type) ||
        (type == 'trusttunnel' &&
            (data['region'] != 'local' ||
                !RegExp(r'^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$')
                    .hasMatch(serverName) ||
                !RegExp(r'^[0-9a-f]{64}$').hasMatch(fingerprint)))) {
      throw const FormatException('Invalid Photon proxy transport');
    }
    return PhotonEndpoint(
      id: id,
      owner: owner,
      region: _string(data, 'region'),
      address: address,
      port: port,
      type: type,
      serverName: serverName,
      fingerprint: fingerprint,
      authRequired: data['auth_required'] as bool? ?? false,
    );
  }

  final String id;
  final String owner;
  final String region;
  final String address;
  final int port;
  final String type;
  final String serverName;
  final String fingerprint;
  final bool authRequired;

  String get _proxyOrder =>
      '${region == 'local' ? '1$owner' : '0$region'}\u0000$type\u0000$authority';
  String get _destinationKey => region == 'local'
      ? '$type\u0000$owner\u0000$authority'
      : '$type\u0000$authority';

  String get _proxyLabel {
    if (region == 'global') return '🌐 global';
    if (region != 'local') {
      final flag = region.countryFlagEmoji;
      return flag == region ? region : '$flag $region';
    }
    final node = owner.split('.').first;
    if (node.isEmpty) return owner;
    final regionCode = switch (node.split('-').last.toLowerCase()) {
      'pek' || 'sha' => 'cn',
      'hkg' => 'hk',
      'hnd' || 'kix' => 'jp',
      'sin' => 'sg',
      'lax' || 'sfo' => 'us',
      _ => null,
    };
    return regionCode == null ? node : '${regionCode.countryFlagEmoji} $node';
  }

  String get authority =>
      address.contains(':') ? '[$address]:$port' : '$address:$port';
}

Map<PhotonEndpoint, String> _proxyNames(
  List<PhotonEndpoint> endpoints,
  Map<String, dynamic>? template, {
  PhotonProxyCardTitles? cardTitles,
}) {
  final provider = template == null ? null : photonServiceProvider;
  final byLabel = <String, List<PhotonEndpoint>>{};
  for (final endpoint in endpoints) {
    (byLabel[endpoint._proxyLabel] ??= []).add(endpoint);
  }
  final used = {
    ...photonProxyGroups,
    'GLOBAL',
    'DIRECT',
    'REJECT',
    'REJECT-DROP',
    'COMPATIBLE',
    'PASS',
    'PASS-RULE',
    for (final section in ['proxies', 'proxy-groups'])
      for (final item in template?[section] as List? ?? const [])
        (item as Map)['name'] as String,
  };
  final names = <PhotonEndpoint, String>{};
  for (final MapEntry(key: label, value: matches) in byLabel.entries) {
    if (matches.length == 1 && used.add(label)) {
      names[matches.single] = label;
      continue;
    }
    final counts = <String, int>{};
    for (final endpoint in matches) {
      counts.update(endpoint.type, (count) => count + 1, ifAbsent: () => 1);
    }
    for (final endpoint in matches) {
      final protocol = switch (endpoint.type) {
        'trusttunnel' => 'TT',
        'http' => 'HTTP',
        _ => 'SOCKS5',
      };
      final qualified = counts.length > 1 ? '$label · $protocol' : label;
      if (qualified != label &&
          counts[endpoint.type] == 1 &&
          !byLabel.containsKey(qualified) &&
          used.add(qualified)) {
        names[endpoint] = qualified;
        cardTitles?[(provider: provider, name: qualified)] = label;
        continue;
      }
      // Derive the suffix from the destination so a shared Anycast proxy
      // keeps its name when its publisher changes.
      final token = sha256
          .convert(utf8.encode(endpoint._destinationKey))
          .toString()
          .substring(0, 6);
      var suffix = token;
      var name = '$qualified · $suffix';
      for (
        var index = 2;
        byLabel.containsKey(name) || !used.add(name);
        index++
      ) {
        suffix = '$token $index';
        name = '$qualified · $suffix';
      }
      names[endpoint] = name;
      if (qualified != label) {
        cardTitles?[(provider: provider, name: name)] = '$label · $suffix';
      }
    }
  }
  return names;
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
    final placed = <String>{};
    for (final item in items.cast<Map>()) {
      final name = item['name'] as String;
      if (!photonProxyGroups.contains(name)) continue;
      if (section != 'proxy-groups' || item.length != 1) {
        throw FormatException(
          'Generated group "$name" only accepts a name in proxy-groups',
        );
      }
      if (!placed.add(name)) {
        throw FormatException('Duplicate generated group "$name"');
      }
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
  if ((template['proxy-providers'] as Map?)?.containsKey(
        photonServiceProvider,
      ) ==
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
  PhotonProxySelection? selection,
  Set<String> includedPaths = const {},
  PhotonProxyCardTitles? cardTitles,
}) {
  if (!directory.fresh(now)) {
    throw StateError('Photon service information expired');
  }
  final available = directory.proxyEndpoints;
  final paths = directory.proxyPaths
      .where((route) => includedPaths.contains(route.name))
      .toList();
  final endpoints = available
      .where(
        (e) =>
            selection == null ||
            selection.allows(type: e.type, region: e.region, owner: e.owner),
      )
      .toList();
  if ((available.isEmpty || adapter.isEmpty) && directory.proxyPaths.isEmpty) {
    throw StateError('No authorized Photon proxy endpoints are available');
  }
  final exclusions = <String>{
    ...directory.underlayRouting
        ? directory.overlayPrefixes
        : directory.bypassPrefixes,
    ...splitRoutes,
    for (final endpoint in available)
      '${endpoint.address}/${endpoint.address.contains(':') ? 128 : 32}',
  };
  final orderedExclusions = exclusions.toList()..sort();
  final rules = <String>[
    for (final prefix in orderedExclusions)
      '${prefix.contains(':') ? 'IP-CIDR6' : 'IP-CIDR'},$prefix,DIRECT,no-resolve',
    'PROCESS-PATH-REGEX,${RegExp.escape(backendPath).replaceAll(',', r'\x2c')},DIRECT',
  ];
  if (template != null) validatePhotonProxyTemplate(template);
  final templateNames = {
    for (final section in ['proxies', 'proxy-groups'])
      for (final item in template?[section] as List? ?? const [])
        (item as Map)['name'],
  };
  if (paths.any((route) => templateNames.contains(route.proxyName))) {
    throw const FormatException(
      'A Photon path name conflicts with the proxy template',
    );
  }
  final names = _proxyNames(endpoints, template, cardTitles: cardTitles);
  final proxies = [
    if (endpoints.isEmpty)
      {'name': 'Photon No selected exits', 'type': 'reject'},
    for (final endpoint in endpoints)
      {
        'name': names[endpoint]!,
        'type': endpoint.type,
        'server': endpoint.address,
        'port': endpoint.port,
        'udp': endpoint.type != 'http',
        'interface-name': adapter,
        if (endpoint.type == 'trusttunnel') ...{
          'quic': true,
          'username': 'photon',
          'password': '',
          'sni': endpoint.serverName,
          'fingerprint': endpoint.fingerprint,
        },
      },
  ];
  return _renderPhotonProxyProfile(
    proxies: proxies,
    paths: [
      for (final route in paths)
        {
          'name': route.proxyName,
          'type': 'socks5',
          'server': route.address,
          'port': route.port,
          'udp': true,
        },
    ],
    exclusions: orderedExclusions,
    bypassDomains: directory.underlayRouting
        ? const []
        : directory.bypassDomains,
    bypassRules: rules,
    template: template,
  );
}

/// Used only by Mihomo's validator when no signed service directory is live.
Map<String, dynamic> photonProxyTemplatePreview(Map<String, dynamic> template) {
  validatePhotonProxyTemplate(template);
  return _renderPhotonProxyProfile(
    proxies: const [
      {'name': 'Photon Offline', 'type': 'reject'},
    ],
    exclusions: const [],
    bypassDomains: const [],
    bypassRules: const [],
    template: template,
  );
}

Map<String, dynamic> _renderPhotonProxyProfile({
  required List<Map<String, dynamic>> proxies,
  List<Map<String, dynamic>> paths = const [],
  required List<String> exclusions,
  required List<String> bypassDomains,
  required List<String> bypassRules,
  required Map<String, dynamic>? template,
}) {
  final names = proxies.map((proxy) => proxy['name']).toList();
  final templateProxies = template?['proxies'] as List? ?? const [];
  final templateGroups = template?['proxy-groups'] as List? ?? const [];
  final templateProviders = template?['proxy-providers'] as Map? ?? const {};
  final templateRules = template?['rules'] as List?;
  final showPaths = paths.isNotEmpty || template != null;
  final groupEndpoints = template == null
      ? {'proxies': names}
      : {
          'use': [photonServiceProvider],
          'empty-fallback': 'REJECT',
        };
  final generatedGroups = <String, Map<String, dynamic>>{
    'Photon': {
      'name': 'Photon',
      'type': 'select',
      ...groupEndpoints,
      'proxies': [
        'Photon Auto',
        'Photon Balance',
        if (paths.isNotEmpty) _pathGroup,
        if (template == null) ...names,
      ],
    },
    'Photon Auto': {
      'name': 'Photon Auto',
      'type': 'url-test',
      ...groupEndpoints,
      'url': 'https://www.gstatic.com/generate_204',
      'interval': 300,
      'tolerance': 80,
    },
    'Photon Balance': {
      'name': 'Photon Balance',
      'type': 'load-balance',
      'strategy': 'consistent-hashing',
      ...groupEndpoints,
      'url': 'https://www.gstatic.com/generate_204',
      'interval': 300,
    },
    if (showPaths)
      _pathGroup: {
        'name': _pathGroup,
        'type': 'select',
        'proxies': paths.isEmpty
            ? ['REJECT']
            : [for (final route in paths) route['name']],
      },
  };
  final groups = [
    for (final group in templateGroups)
      generatedGroups.remove(group['name']) ?? group,
  ];
  groups.addAll(generatedGroups.values);
  final protection = {
    'route-exclude-address': exclusions,
    'rules': bypassRules,
    'bypass-domains': bypassDomains,
    if (paths.isNotEmpty)
      'proxy-paths': [for (final path in paths) path['name']],
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
    'proxies': [...(template == null ? proxies : templateProxies), ...paths],
    if (template != null)
      'proxy-providers': {
        ...templateProviders,
        photonServiceProvider: {
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
    'proxy-groups': groups,
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

List<dynamic> _appliedProxyEntries(Map<String, dynamic> profile) {
  final providers = profile['proxy-providers'] as Map?;
  final photon = providers?[photonServiceProvider] as Map?;
  final proxies = profile['proxies'] as List? ?? const [];
  if (photon == null) return proxies;
  final paths = _appliedPathNames(profile);
  return [
    ...(photon['payload'] as List? ?? const []),
    for (final proxy in proxies)
      if (proxy is Map && paths.contains(proxy['name'])) proxy,
  ];
}

List _appliedPathNames(Map<String, dynamic> profile) =>
    (profile[_photonProtection] as Map?)?['proxy-paths'] as List? ?? const [];

Set<String> unauthorizedPhotonProxies(
  Map<String, dynamic> profile,
  PhotonDirectory? directory,
) {
  final allowed = {
    for (final endpoint
        in directory?.proxyEndpoints ?? const <PhotonEndpoint>[])
      (
        endpoint.type,
        endpoint.address,
        endpoint.port,
        endpoint.serverName,
        endpoint.fingerprint,
        directory!.adapterName,
      ),
  };
  final allowedPaths = {
    for (final route in directory?.proxyPaths ?? const <PhotonProxyPath>[])
      (route.proxyName, route.address, route.port),
  };
  final pathNames = _appliedPathNames(profile);
  return {
    for (final proxy in _appliedProxyEntries(profile).whereType<Map>())
      if (proxy['name'] is String &&
          proxy['type'] != 'reject' &&
          (pathNames.contains(proxy['name'])
              ? proxy['type'] != 'socks5' ||
                    !allowedPaths.contains((
                      proxy['name'],
                      proxy['server'],
                      proxy['port'],
                    ))
              : !allowed.contains((
                  proxy['type'],
                  proxy['server'],
                  proxy['port'],
                  proxy['sni'] ?? '',
                  proxy['fingerprint'] ?? '',
                  proxy['interface-name'],
                ))))
        proxy['name'] as String,
  };
}

Map<String, dynamic> restrictPhotonProxies(
  Map<String, dynamic> profile,
  Set<String> blocked,
) {
  if (blocked.isEmpty) return profile;
  List<dynamic> restrict(List proxies) => [
    for (final proxy in proxies)
      if (proxy is Map && blocked.contains(proxy['name']))
        {'name': proxy['name'], 'type': 'reject'}
      else
        proxy,
  ];
  final providers = profile['proxy-providers'] as Map?;
  final photon = providers?[photonServiceProvider] as Map?;
  final proxies = restrict(profile['proxies'] as List? ?? const []);
  if (photon == null) return {...profile, 'proxies': proxies};
  return {
    ...profile,
    'proxies': proxies,
    'proxy-providers': {
      ...providers!,
      photonServiceProvider: {
        ...photon,
        'payload': restrict(photon['payload'] as List? ?? const []),
      },
    },
  };
}

Map<String, dynamic> blockedPhotonProfile(
  Map<String, dynamic> profile, {
  bool keepTemplate = true,
}) {
  final providers = profile['proxy-providers'];
  final hasTemplate =
      providers is Map && providers.containsKey(photonServiceProvider);
  if (keepTemplate && hasTemplate) {
    final paths = _appliedPathNames(profile);
    return {
      ...profile,
      'proxies': [
        for (final proxy in profile['proxies'] as List? ?? const [])
          if (proxy is Map && paths.contains(proxy['name']))
            {'name': proxy['name'], 'type': 'reject'}
          else
            proxy,
      ],
      'proxy-providers': {
        ...providers,
        photonServiceProvider: {
          'type': 'inline',
          'payload': [
            {'name': 'Photon Offline', 'type': 'reject'},
          ],
        },
      },
      'proxy-groups': [
        for (final group in profile['proxy-groups'] as List)
          if (photonProxyGroups.contains((group as Map)['name']))
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
  final protection = profile[_photonProtection];
  if (!keepTemplate && hasTemplate && protection is Map) {
    return {
      'ipv6': true,
      _photonProtection: protection,
      'rules': ['MATCH,REJECT'],
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
