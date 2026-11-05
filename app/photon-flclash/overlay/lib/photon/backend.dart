import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:path/path.dart' as path;
import 'package:yaml/yaml.dart';

String get photonExecutable => path.join(
  File(Platform.resolvedExecutable).parent.path,
  'photon-windows.exe',
);

abstract interface class PhotonBackend {
  bool get hasProcess;
  Future<int>? get exitCode;
  Future<void> start(String configPath);
  Future<Map<String, dynamic>> status();
  Future<Map<String, dynamic>> services();
  Future<void> stop();
}

final class PhotonProcess implements PhotonBackend {
  PhotonProcess({
    required this.executable,
    this.arguments = const [],
    this.timeout = const Duration(seconds: 10),
    this.startupTimeout = const Duration(seconds: 10),
    this.shutdownTimeout = const Duration(seconds: 10),
  });

  final String executable;
  final List<String> arguments;
  final Duration timeout;
  final Duration startupTimeout;
  final Duration shutdownTimeout;
  Process? _process;
  _FrameReader? _reader;
  StreamSubscription<List<int>>? _stderr;
  Future<void> _tail = Future.value();
  bool _broken = false;

  @override
  bool get hasProcess => _process != null;

  @override
  Future<int>? get exitCode => _process?.exitCode;

  @override
  Future<void> start(String configPath) async {
    if (hasProcess) throw StateError('Photon backend is already owned');
    final config = File(configPath).absolute;
    final bytes = await config.readAsBytes();
    if (bytes.length > 1 << 20) throw const FormatException('Config too large');
    final yaml = loadYaml(utf8.decode(bytes));
    final statePath = yaml is YamlMap && yaml['state'] is YamlMap
        ? yaml['state']['path']
        : null;
    if (statePath is! String || !path.isAbsolute(statePath)) {
      throw const FormatException('Photon state.path must be absolute');
    }
    final process = await Process.start(executable, [
      ...arguments,
      'run',
      '--stdio',
      '--config',
      config.path,
    ], workingDirectory: File(executable).absolute.parent.path);
    _process = process;
    _broken = false;
    _reader = _FrameReader(process.stdout);
    _stderr = process.stderr.listen((_) {});
    try {
      final ready = await _reader!.read().timeout(startupTimeout);
      final result = _result(ready, 'ready');
      final returnedPath = result['state_path'];
      if (result['pid'] != process.pid ||
          result['config_sha256'] != sha256.convert(bytes).toString() ||
          returnedPath is! String ||
          !_samePath(returnedPath, statePath)) {
        throw const FormatException('Photon startup identity mismatch');
      }
    } catch (_) {
      _broken = true;
      await stop();
      rethrow;
    }
  }

  static bool _samePath(String a, String b) {
    final left = path.normalize(a);
    final right = path.normalize(b);
    return Platform.isWindows
        ? left.toLowerCase() == right.toLowerCase()
        : left == right;
  }

  @override
  Future<Map<String, dynamic>> status() => _request('status');

  @override
  Future<Map<String, dynamic>> services() => _request('services');

  Future<Map<String, dynamic>> _request(String method) {
    final operation = _tail
        .then((_) async {
          final process = _process;
          if (process == null || _broken) {
            throw StateError('Photon backend is unavailable');
          }
          try {
            final bytes = utf8.encode(
              jsonEncode({'version': 1, 'method': method}),
            );
            final header = ByteData(4)..setUint32(0, bytes.length);
            process.stdin.add(header.buffer.asUint8List());
            process.stdin.add(bytes);
            await process.stdin.flush();
            final response = await _reader!.read();
            process.stdin.add(const [1]);
            await process.stdin.flush();
            return _result(response, method);
          } on PhotonControlException {
            rethrow;
          } catch (_) {
            _broken = true;
            rethrow;
          }
        })
        .timeout(
          timeout,
          onTimeout: () {
            _broken = true;
            throw TimeoutException('Photon control request timed out');
          },
        );
    _tail = operation.then<void>((_) {}, onError: (Object _, StackTrace _) {});
    return operation;
  }

  static Map<String, dynamic> _result(
    Map<String, dynamic> response,
    String method,
  ) {
    if (response['version'] != 1 || response['method'] != method) {
      throw const FormatException('Invalid Photon response');
    }
    final error = response['error'];
    final result = response['result'];
    if ((error == null) == (result == null)) {
      throw const FormatException('Invalid Photon response envelope');
    }
    if (error is Map && error['code'] is String && error['message'] is String) {
      throw PhotonControlException(error['code'], error['message']);
    }
    if (error != null || result is! Map<String, dynamic>) {
      throw const FormatException('Invalid Photon response result');
    }
    return result;
  }

  @override
  Future<void> stop() async {
    final process = _process;
    if (process == null) return;
    try {
      if (!_broken) await _request('stop');
    } catch (_) {
      // EOF on the private pipe also cancels the backend's owned run.
    } finally {
      unawaited(process.stdin.close().catchError((Object _) {}));
      await _reader?.close();
      await _stderr?.cancel();
    }
    try {
      await process.exitCode.timeout(shutdownTimeout);
    } on TimeoutException {
      process.kill();
      await process.exitCode.timeout(const Duration(seconds: 2));
    }
    _process = null;
    _reader = null;
    _stderr = null;
  }
}

final class PhotonControlException implements Exception {
  const PhotonControlException(this.code, this.message);

  final String code;
  final String message;

  @override
  String toString() => '$code: $message';
}

final class _FrameReader {
  _FrameReader(Stream<List<int>> stream) : _stream = StreamIterator(stream);

  final StreamIterator<List<int>> _stream;
  List<int> _chunk = const [];
  int _offset = 0;

  Future<Uint8List> _readBytes(int count) async {
    final bytes = Uint8List(count);
    var written = 0;
    while (written < count) {
      if (_offset == _chunk.length) {
        if (!await _stream.moveNext()) {
          throw const FormatException('Photon control stream ended');
        }
        _chunk = _stream.current;
        _offset = 0;
      }
      final remaining = count - written;
      final available = _chunk.length - _offset;
      final take = remaining < available ? remaining : available;
      bytes.setRange(written, written + take, _chunk, _offset);
      written += take;
      _offset += take;
    }
    return bytes;
  }

  Future<Map<String, dynamic>> read() async {
    final header = await _readBytes(4);
    final size = ByteData.sublistView(header).getUint32(0);
    if (size == 0 || size > 1 << 20) {
      throw const FormatException('Invalid Photon frame size');
    }
    final value = jsonDecode(utf8.decode(await _readBytes(size)));
    if (value is! Map<String, dynamic>) {
      throw const FormatException('Invalid Photon response object');
    }
    return value;
  }

  Future<void> close() => _stream.cancel();
}
