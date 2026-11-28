import 'dart:io';

final class PhotonProxyPath {
  PhotonProxyPath.fromJson(Map data)
    : name = data['name'] as String,
      address = data['address'] as String,
      port = data['port'] as int,
      hops = List<String>.from(data['hops'] as List),
      udpPrefixes = List<String>.from(
        data['udp_prefixes'] as List? ?? const [],
      ) {
    if (name.trim().isEmpty ||
        InternetAddress.tryParse(address)?.isLoopback != true ||
        port < 1 ||
        port > 65535 ||
        hops.isEmpty) {
      throw const FormatException('Invalid local Photon proxy path');
    }
  }

  final String name;
  final String address;
  final int port;
  final List<String> hops;
  final List<String> udpPrefixes;

  String get proxyName => 'Photon Path / $name';
  String get listen =>
      address.contains(':') ? '[$address]:$port' : '$address:$port';
}

final class PhotonPathEndpoint {
  PhotonPathEndpoint.fromJson(Map data)
    : zone = data['zone'] as String,
      endpoint = data['endpoint'] as String,
      links = List<String>.from(data['links'] as List? ?? const []);

  final String zone;
  final String endpoint;
  final List<String> links;

  String get label =>
      '${zone.split('.').first}${endpoint == 'relay' || endpoint == 'exit' ? '' : '/$endpoint'}';
}

final class PhotonPathSnapshot {
  PhotonPathSnapshot.fromJson(Map data)
    : routes = [
        for (final route in data['routes'] as List)
          PhotonProxyPath.fromJson(route as Map),
      ],
      relays = _endpoints(data, 'relays'),
      exits = _endpoints(data, 'exits'),
      probe = data['probe'] as Map?;

  final List<PhotonProxyPath> routes;
  final List<PhotonPathEndpoint> relays;
  final List<PhotonPathEndpoint> exits;
  final Map? probe;

  static List<PhotonPathEndpoint> _endpoints(Map data, String role) => [
    for (final value in (data['directory'] as Map)[role] as List)
      PhotonPathEndpoint.fromJson(value as Map),
  ];
}
