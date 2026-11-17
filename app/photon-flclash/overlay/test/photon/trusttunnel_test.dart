import 'package:fl_clash/photon/services.dart';
import 'package:flutter_test/flutter_test.dart';

import 'services_test.dart' show directoryFixture;

void main() {
  test('HTTP directory nodes disable UDP and require explicit credentials when authenticated', () {
    final now = DateTime.now().toUtc();
    final raw = directoryFixture(now: now);
    final entry = (raw['services'] as List).first as Map;
    final endpoint = (entry['endpoints'] as List).first as Map;
    entry['endpoints'] = [endpoint];
    endpoint['type'] = 'http';
    final directory = PhotonDirectory.fromJson(raw);
    final config = photonProxyProfile(
      directory: directory,
      now: now,
      splitRoutes: ['fd42::/16'],
      adapter: 'Photon',
      backendPath: '/tmp/photon',
    );
    final proxy = (config['proxies'] as List).single as Map;
    expect(proxy['type'], 'http');
    expect(proxy['udp'], false);
    endpoint['auth_required'] = true;
    expect(PhotonDirectory.fromJson(raw).proxyEndpoints, isEmpty);
  });
  test('TrustTunnel is pinned, HTTP3 only and carries UDP', () {
    final now = DateTime.now().toUtc();
    final raw = directoryFixture(now: now);
    final services = raw['services'] as List;
    final entry = services.first as Map;
    entry['endpoints'] = [
      {
        'id': '3' * 32,
        'region': 'local',
        'address': 'fd42:1::22',
        'port': 4433,
        'type': 'trusttunnel',
        'server_name': 'trusttunnel.node.catofes',
        'fingerprint': 'ab' * 32,
      },
    ];
    final directory = PhotonDirectory.fromJson(raw);
    final config = photonProxyProfile(
      directory: directory,
      now: now,
      splitRoutes: ['fd42::/16'],
      adapter: 'Photon',
      backendPath: '/tmp/photon',
    );
    final proxy = (config['proxies'] as List).single as Map;
    expect(proxy['type'], 'trusttunnel');
    expect(proxy['quic'], true);
    expect(proxy['udp'], true);
    expect(proxy['fingerprint'], 'ab' * 32);
    expect(proxy['sni'], 'trusttunnel.node.catofes');
    expect(proxy.containsKey('skip-cert-verify'), false);
    final endpoint = (entry['endpoints'] as List).first as Map;
    endpoint['fingerprint'] = '';
    expect(() => PhotonDirectory.fromJson(raw), throwsFormatException);
  });
}
