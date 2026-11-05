import 'dart:async';
import 'dart:io';

import 'package:fl_clash/common/constant.dart' show safeModeBuild;
import 'package:flutter/foundation.dart';
import 'package:path/path.dart' as path;

import 'backend.dart';

final class PhotonController extends ChangeNotifier {
  PhotonController({required PhotonBackend Function() createBackend})
    : _createBackend = createBackend;

  final PhotonBackend Function() _createBackend;
  PhotonBackend? _backend;
  Future<void> _tail = Future.value();
  Future<void>? _refresh;
  Future<void>? _closing;
  Timer? _timer;
  bool _closed = false;
  bool _busy = false;
  Map<String, dynamic>? _observation;
  Object? _error;
  String? _configPath;

  bool get busy => _busy;
  bool get hasLease => _backend != null;
  bool get closed => _closed;
  Map<String, dynamic>? get observation => _observation;
  Object? get error => _error;
  String? get configPath => _configPath;

  void selectConfig(String value) {
    if (_closed || busy || hasLease) return;
    _configPath = File(value).absolute.path;
    _error = null;
    notifyListeners();
  }

  Future<void> pickConfig(Future<String?> Function() pick) =>
      _enqueue(() async {
        if (_closed || hasLease) return;
        final selected = await pick();
        if (selected != null && !_closed) {
          _configPath = File(selected).absolute.path;
        }
      });

  Future<void> start({required bool allowed}) => _enqueue(() async {
    if (_closed || !allowed || hasLease) return;
    _error = null;
    final config = _configPath;
    if (config == null) return;
    final backend = _createBackend();
    _backend = backend;
    await backend.start(config);
    final exited = backend.exitCode;
    if (exited != null) {
      unawaited(
        exited.then((_) async {
          if (_backend != backend || _closed) return;
          await _enqueue(() async {
            if (_backend != backend) return;
            await _release();
            throw StateError('Photon backend exited');
          }, clearError: false);
        }),
      );
    }
    if (_closed) {
      await _release();
      return;
    }
    _observation = await backend.status();
    _timer = Timer.periodic(const Duration(seconds: 2), (_) {
      unawaited(refresh());
    });
  }, clearError: false);

  Future<void> refresh() {
    if (_closed || !hasLease || _busy) return Future.value();
    return _refresh ??= _enqueue(() async {
      final backend = _backend;
      if (backend != null) _observation = await backend.status();
    }).whenComplete(() => _refresh = null);
  }

  Future<void> stop() => _enqueue(_release, cleanupOnError: false);

  Future<void> restart({required bool allowed}) async {
    await stop();
    if (!hasLease && !_closed) await start(allowed: allowed);
  }

  Future<void> _release() async {
    _timer?.cancel();
    _timer = null;
    _observation = null;
    final backend = _backend;
    if (backend == null) return;
    await backend.stop();
    _backend = null;
  }

  Future<void> _enqueue(
    Future<void> Function() action, {
    bool clearError = true,
    bool cleanupOnError = true,
  }) {
    final operation = _tail.then((_) async {
      _busy = true;
      if (clearError) _error = null;
      notifyListeners();
      try {
        await action();
      } catch (error) {
        _error = error;
        if (cleanupOnError) {
          try {
            await _release();
          } catch (cleanupError) {
            _error = cleanupError;
          }
        }
      } finally {
        _busy = false;
        notifyListeners();
      }
    });
    _tail = operation;
    return operation;
  }

  Future<void> close() {
    _closed = true;
    _timer?.cancel();
    return _closing ??= _enqueue(_release, cleanupOnError: false).then((_) {
      if (hasLease) throw StateError('Photon backend exit is unconfirmed');
    });
  }
}

final photonController = PhotonController(
  createBackend: () {
    if (safeModeBuild || !Platform.isWindows) {
      throw StateError('Photon is disabled on this platform or in safe mode');
    }
    return PhotonProcess(
      executable: path.join(
        File(Platform.resolvedExecutable).parent.path,
        'photon-windows.exe',
      ),
    );
  },
);
