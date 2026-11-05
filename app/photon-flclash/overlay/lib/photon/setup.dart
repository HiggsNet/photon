import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'backend.dart' show photonExecutable;

final class PhotonConfigSession {
  PhotonConfigSession._(this._process)
    : _replies = StreamIterator(
        _process.stdout.transform(utf8.decoder).transform(const LineSplitter()),
      ) {
    unawaited(_process.stderr.drain<void>());
  }

  final Process _process;
  final StreamIterator<String> _replies;
  late final Map<String, dynamic> form;

  static Future<PhotonConfigSession> open(
    String config, {
    required bool create,
    String? executable,
  }) async {
    final backend = executable ?? photonExecutable;
    final session = PhotonConfigSession._(
      await Process.start(backend, [
        'config',
        'edit',
        '--config',
        config,
        if (create) '--new',
      ], workingDirectory: File(backend).absolute.parent.path),
    );
    try {
      final reply = await session._read();
      session.form = Map<String, dynamic>.from(reply['form'] as Map);
      return session;
    } catch (_) {
      await session.close();
      rethrow;
    }
  }

  Future<Map<String, dynamic>> _read() async {
    if (!await _replies.moveNext().timeout(const Duration(seconds: 10))) {
      throw StateError('Photon configuration editor exited');
    }
    final reply = jsonDecode(_replies.current) as Map<String, dynamic>;
    if (reply['error'] case final String message) {
      throw PhotonSetupException(message);
    }
    return reply;
  }

  Future<void> save(Map<String, dynamic> edited) async {
    _process.stdin.writeln(jsonEncode(edited));
    await _process.stdin.flush().timeout(const Duration(seconds: 10));
    if ((await _read())['saved'] != true) {
      throw const FormatException('Invalid Photon configuration reply');
    }
  }

  Future<void> close() async {
    try {
      await _process.stdin.close().timeout(const Duration(seconds: 2));
    } on Exception {
      _process.kill();
    }
    await _replies.cancel();
    try {
      await _process.exitCode.timeout(const Duration(seconds: 3));
    } on TimeoutException {
      _process.kill();
      await _process.exitCode.timeout(const Duration(seconds: 3));
    }
  }
}

final class PhotonSetupException implements Exception {
  const PhotonSetupException(this.message);

  final String message;

  @override
  String toString() => message;
}

Future<void> importPhotonIdentity({
  required String config,
  required String bundle,
  required String key,
}) async {
  final backend = photonExecutable;
  final result = await Process.run(backend, [
    'state',
    'import',
    '--config',
    config,
    '--bundle',
    bundle,
    '--key',
    key,
  ], workingDirectory: File(backend).parent.path);
  if (result.exitCode != 0) {
    final message = (result.stderr as String).trim();
    throw PhotonSetupException(
      message.isEmpty ? 'Photon identity import failed' : message,
    );
  }
}
