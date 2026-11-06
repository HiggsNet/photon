import 'dart:async';
import 'dart:io';

import 'package:fl_clash/common/constant.dart' show safeModeBuild;
import 'package:flutter/foundation.dart';

import 'backend.dart';
import 'preferences.dart';
import 'services.dart';

final class PhotonController extends ChangeNotifier {
  PhotonController({
    required PhotonBackend Function() createBackend,
    this.preferences,
  }) : _createBackend = createBackend;

  final PhotonBackend Function() _createBackend;
  final PhotonPreferences? preferences;
  Future<void> Function(PhotonDirectory, Set<String>)? onServicesChanged;
  Future<void> Function()? onServicesInvalidated;
  PhotonDirectory? _directory;
  String? _selectionScope;
  Set<String> _selected = {};
  Future<void>? _initializing;
  Timer? _expiry;
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
  PhotonDirectory? get directory => _directory;
  bool get directoryFresh => _directory?.fresh(DateTime.now()) ?? false;
  Set<String> get selected => Set.unmodifiable(_selected);

  Future<void> initialize() => _initializing ??= _enqueue(() async {
    _configPath ??= await preferences?.configPath();
  }, cleanupOnError: false);

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
          await preferences?.saveConfigPath(_configPath!);
        }
      }, cleanupOnError: false);

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
    await _refreshServices(backend);
    _timer = Timer.periodic(const Duration(seconds: 2), (_) {
      unawaited(refresh());
    });
  }, clearError: false);

  Future<void> refresh() {
    if (_closed || !hasLease || _busy) return Future.value();
    return _refresh ??= _enqueue(() async {
      final backend = _backend;
      if (backend != null) {
        _observation = await backend.status();
        await _refreshServices(backend);
      }
    }, showBusy: false).whenComplete(() => _refresh = null);
  }

  Future<void> stop() => _enqueue(_release, cleanupOnError: false);

  Future<void> restart({required bool allowed}) async {
    await stop();
    if (!hasLease && !_closed) await start(allowed: allowed);
  }

  Future<void> _refreshServices(
    PhotonBackend backend, {
    bool publish = true,
  }) async {
    try {
      final next = PhotonDirectory.fromJson(await backend.services());
      if (!next.fresh(DateTime.now())) {
        throw StateError('Photon service information expired');
      }
      if (_selectionScope != next.scope) {
        _selected = await preferences?.selection(next.scope) ?? {};
        _selectionScope = next.scope;
      }
      final active = next.endpoints.map((endpoint) => endpoint.id).toSet();
      final retained = _selected.intersection(active);
      if (!setEquals(retained, _selected)) {
        _selected = retained;
        await preferences?.saveSelection(next.scope, retained);
      }
      _directory = next;
      _expiry?.cancel();
      final remaining = next.validUntil.difference(DateTime.now());
      _expiry = Timer(remaining.isNegative ? Duration.zero : remaining, () {
        if (!directoryFresh) {
          unawaited(
            _enqueue(
              () async {
                if (identical(_directory, next) && !directoryFresh) {
                  await _invalidateServices();
                }
              },
              clearError: false,
              cleanupOnError: false,
            ),
          );
        }
      });
      if (publish) await onServicesChanged?.call(next, selected);
    } catch (error) {
      _error = error;
      await _invalidateServices();
    }
  }

  Future<void> toggleEndpoint(String id, bool enabled) => _enqueue(() async {
    final backend = _backend;
    if (!directoryFresh && backend != null) {
      await _refreshServices(backend, publish: false);
    }
    final current = _directory;
    if (current == null ||
        !directoryFresh ||
        !current.endpoints.any((endpoint) => endpoint.id == id)) {
      return;
    }
    final next = {..._selected};
    enabled ? next.add(id) : next.remove(id);
    await preferences?.saveSelection(current.scope, next);
    _selected = next;
    await onServicesChanged?.call(current, selected);
  }, cleanupOnError: false);

  Future<void> applyProxies(Future<void> Function() apply) =>
      _enqueue(apply, cleanupOnError: false);

  Future<void> _invalidateServices() async {
    _expiry?.cancel();
    _expiry = null;
    _directory = null;
    if (!_closed) await onServicesInvalidated?.call();
  }

  Future<void> _release() async {
    _timer?.cancel();
    _timer = null;
    _observation = null;
    Object? invalidationError;
    try {
      await _invalidateServices();
    } catch (error) {
      invalidationError = error;
    }
    final backend = _backend;
    if (backend == null) return;
    await backend.stop();
    _backend = null;
    if (invalidationError != null) {
      throw StateError('Proxy cleanup failed: $invalidationError');
    }
  }

  Future<void> _enqueue(
    Future<void> Function() action, {
    bool clearError = true,
    bool cleanupOnError = true,
    bool showBusy = true,
  }) {
    final operation = _tail.then((_) async {
      _busy = showBusy;
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
  preferences: StoredPhotonPreferences(),
  createBackend: () {
    if (safeModeBuild || !Platform.isWindows) {
      throw StateError('Photon is disabled on this platform or in safe mode');
    }
    return PhotonProcess(
      executable: photonExecutable,
      requestElevation: true,
      startupTimeout: const Duration(minutes: 2),
    );
  },
);
