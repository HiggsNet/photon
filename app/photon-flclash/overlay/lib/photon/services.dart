import 'dart:convert';
import 'dart:io';

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

  String get scope => '$rootFingerprint/$managedZone';
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
  required Set<String> selected,
  required DateTime now,
  required List<String> splitRoutes,
  required String adapter,
  required String backendPath,
}) {
  if (!directory.fresh(now)) {
    throw StateError('Photon service information expired');
  }
  final endpoints =
      directory.endpoints
          .where((endpoint) => selected.contains(endpoint.id))
          .toList()
        ..sort((a, b) => a.id.compareTo(b.id));
  if (endpoints.isEmpty || adapter.isEmpty) {
    throw StateError('Select an authorized Photon proxy endpoint');
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
    'MATCH,Photon',
  ];
  return {
    'ipv6': true,
    'mode': 'rule',
    'allow-lan': false,
    'tun': {
      'enable': false,
      'auto-route': true,
      'auto-detect-interface': true,
      'route-exclude-address': orderedExclusions,
    },
    'proxies': [
      for (final endpoint in endpoints)
        {
          'name': endpoint.name,
          'type': 'socks5',
          'server': endpoint.address,
          'port': endpoint.port,
          'udp': true,
          'interface-name': adapter,
        },
    ],
    'proxy-groups': [
      {
        'name': 'Photon',
        'type': 'select',
        'proxies': ['Photon Auto', 'Photon Balance', ...names],
      },
      {
        'name': 'Photon Auto',
        'type': 'url-test',
        'proxies': names,
        'url': 'https://www.gstatic.com/generate_204',
        'interval': 300,
        'tolerance': 80,
      },
      {
        'name': 'Photon Balance',
        'type': 'load-balance',
        'strategy': 'consistent-hashing',
        'proxies': names,
        'url': 'https://www.gstatic.com/generate_204',
        'interval': 300,
      },
    ],
    'rules': rules,
  };
}

String encodePhotonProfile(Map<String, dynamic> profile) =>
    const JsonEncoder.withIndent('  ').convert(profile);
