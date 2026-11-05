import 'dart:async';
import 'dart:convert';
import 'dart:io';

// Also runs in the standalone Windows fixture without Flutter dependencies.
// ignore: avoid_relative_lib_imports
import '../lib/photon/backend.dart';

// Run this same adapter against the actual Windows backend before building UI.
Future<void> main(List<String> args) async {
  if (args.length != 2) {
    stderr.writeln(
      'Usage: dart tool/photon_smoke.dart <backend.exe> <config.yaml>',
    );
    exitCode = 2;
    return;
  }
  final backend = PhotonProcess(executable: args[0]);
  try {
    await backend.start(args[1]);
    final deadline = DateTime.now().add(const Duration(seconds: 60));
    while (true) {
      final status = await backend.status();
      stdout.writeln(
        jsonEncode({
          'running': status['running'],
          'tunnel_ready': status['tunnel_ready'],
          'revision': status['revision'],
          'wintun': status['wintun'],
          'connections': (status['connections'] as List?)?.length,
        }),
      );
      if (status['tunnel_ready'] == true) break;
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('Photon did not become tunnel ready');
      }
      await Future<void>.delayed(const Duration(seconds: 1));
    }
    final ping = await Process.run('ping.exe', [
      '-6',
      '-n',
      '3',
      '-w',
      '2000',
      '2a0d:2905:1:1::1',
    ]);
    stdout.write(ping.stdout);
    if (ping.exitCode != 0) throw StateError('IPv6 business ping failed');
  } finally {
    await backend.stop();
    stdout.writeln(jsonEncode({'owned_backend_released': !backend.hasProcess}));
  }
}
