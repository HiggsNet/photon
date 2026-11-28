import 'dart:async';

import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/l10n/l10n.dart';
import 'package:fl_clash/providers/app.dart';
import 'package:fl_clash/ui/icons/icons.dart';
import 'package:fl_clash/widgets/widgets.dart';
import 'package:flutter/services.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'controller.dart';
import 'proxy_bridge.dart';
import 'proxy_paths.dart';

String _text(BuildContext context, String zh, String en) =>
    Localizations.localeOf(context).languageCode == 'zh' ? zh : en;

class PhotonProxyPathsView extends ConsumerStatefulWidget {
  const PhotonProxyPathsView({super.key, this.controller, this.bridge});

  final PhotonController? controller;
  final PhotonProxyBridge? bridge;

  @override
  ConsumerState<PhotonProxyPathsView> createState() => _PhotonProxyPathsState();
}

class _PhotonProxyPathsState extends ConsumerState<PhotonProxyPathsView> {
  PhotonController get _owner => widget.controller ?? photonController;
  PhotonProxyBridge get _bridge => widget.bridge ?? photonProxyBridge;
  PhotonPathSnapshot? _snapshot;
  Set<String> _included = {};
  Timer? _timer;
  Object? _error;
  bool _busy = false;
  bool _loading = false;

  @override
  void initState() {
    super.initState();
    if (widget.controller == null) _bridge.attach();
    unawaited(_owner.initialize().then((_) => _refresh()));
    _timer = Timer.periodic(const Duration(seconds: 2), (_) => _refresh());
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  Future<void> _refresh() async {
    if (!mounted || _busy || _loading || ref.read(safeModeProvider)) return;
    if (!_owner.hasLease) {
      if (_snapshot != null || _error != null) {
        setState(() {
          _snapshot = null;
          _error = null;
        });
      }
      return;
    }
    _loading = true;
    try {
      final next = await _request(const {'action': 'list'});
      final included = await _bridge.includedPaths();
      if (mounted && !_busy && _owner.hasLease) {
        setState(() {
          if (_snapshot == null) _error = null;
          _snapshot = next;
          _included = included;
        });
      }
    } catch (error) {
      if (mounted && !_busy && _snapshot == null && _owner.hasLease) {
        setState(() => _error = error);
      }
    } finally {
      _loading = false;
    }
  }

  Future<PhotonPathSnapshot> _request(Map<String, dynamic> request) async =>
      PhotonPathSnapshot.fromJson(await _owner.proxyPaths(request));

  Future<void> _run(Future<void> Function() action) async {
    if (_busy || !mounted) return;
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await action();
    } catch (error) {
      if (mounted) setState(() => _error = error);
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _edit(
    PhotonPathSnapshot snapshot, [
    PhotonProxyPath? path,
  ]) async {
    await showFloatingDialog<void>(
      context: context,
      child: _PathEditor(
        snapshot: snapshot,
        path: path,
        onSave: (edit) async {
          final next = await _request(edit);
          if (mounted) setState(() => _snapshot = next);
          unawaited(_owner.refresh());
        },
      ),
    );
  }

  Future<void> _delete(PhotonProxyPath path) async {
    final yes = await showFloatingDialog<bool>(
      context: context,
      child: AlertDialog(
        title: _text(context, '删除路径', 'Delete path'),
        destructive: true,
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: Text(_text(context, '取消', 'Cancel')),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, true),
            child: Text(_text(context, '删除', 'Delete')),
          ),
        ],
        child: Text(path.name),
      ),
    );
    if (yes != true || !mounted) return;
    await _run(() async {
      final next = await _request({'action': 'delete', 'name': path.name});
      await _bridge.includePath(path.name, false);
      if (mounted) {
        setState(() {
          _snapshot = next;
          _included.remove(path.name);
        });
      }
      await _owner.refresh();
    });
  }

  Future<void> _probe(PhotonProxyPath path, String kind) async {
    final fields = kind == 'custom'
        ? await showFloatingDialog<Map<String, dynamic>>(
            context: context,
            child: const _ProbeTargetDialog(),
          )
        : {'kind': kind};
    if (fields == null || !mounted) return;
    await _run(() async {
      final next = await _request({
        'action': 'probe',
        'name': path.name,
        ...fields,
      });
      if (mounted) setState(() => _snapshot = next);
    });
  }

  @override
  Widget build(BuildContext context) {
    final safeMode = ref.watch(safeModeProvider);
    return Scaffold(
      title: AppLocalizations.of(context).photonProxyPaths,
      body: ListenableBuilder(
        listenable: _owner,
        builder: (context, _) {
          final snapshot = _owner.hasLease && !safeMode ? _snapshot : null;
          return SingleChildScrollView(
            key: const PageStorageKey('photon-proxy-paths'),
            padding: EdgeInsets.fromLTRB(
              20,
              context.sectionsTopPadding,
              20,
              24,
            ),
            child: Align(
              alignment: Alignment.topCenter,
              child: ConstrainedBox(
                constraints: const BoxConstraints(maxWidth: 880),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  spacing: 12,
                  children: [
                    if (safeMode)
                      Text(
                        _text(context, '安全模式下不可用', 'Unavailable in safe mode'),
                      )
                    else if (!_owner.hasLease)
                      Align(
                        alignment: Alignment.centerLeft,
                        child: FilledButton(
                          onPressed: _busy || _owner.busy
                              ? null
                              : () => _run(() async {
                                  if (_owner.configPath == null) {
                                    ref
                                        .read(currentPageLabelProvider.notifier)
                                        .toPage(PageLabel.photon);
                                    return;
                                  }
                                  await _owner.start(allowed: true);
                                }),
                          child: Text(
                            _text(context, '连接 Photon', 'Connect Photon'),
                          ),
                        ),
                      )
                    else if (snapshot == null)
                      Text(
                        _text(
                          context,
                          '正在等待代理客户端',
                          'Waiting for the proxy client',
                        ),
                      )
                    else ...[
                      Wrap(
                        spacing: 8,
                        runSpacing: 8,
                        children: [
                          FilledButton.icon(
                            onPressed: _busy ? null : () => _edit(snapshot),
                            icon: const GlyphIcon(AppGlyphs.add),
                            label: Text(_text(context, '新建路径', 'New path')),
                          ),
                          OutlinedButton(
                            onPressed: _busy
                                ? null
                                : () => _run(() async {
                                    await _owner.refresh();
                                    await _owner.applyProxies(_bridge.apply);
                                    if (_owner.error case final error?) {
                                      throw StateError('$error');
                                    }
                                  }),
                            child: Text(
                              _text(
                                context,
                                '应用 Photon 配置',
                                'Apply Photon profile',
                              ),
                            ),
                          ),
                        ],
                      ),
                      if (snapshot.routes.isEmpty)
                        Text(_text(context, '暂无已保存的路径', 'No saved paths')),
                      for (final path in snapshot.routes)
                        _routeCard(snapshot, path),
                    ],
                    if (!safeMode)
                      if ((_error ?? _owner.error) case final error?)
                        Text(
                          '$error',
                          style: TextStyle(color: context.colorScheme.error),
                        ),
                  ],
                ),
              ),
            ),
          );
        },
      ),
    );
  }

  Widget _routeCard(PhotonPathSnapshot snapshot, PhotonProxyPath path) {
    final probe = snapshot.probe;
    final result = probe != null && probe['name'] == path.name
        ? (probe['result'] as Map?)
        : null;
    final probing = probe?['name'] == path.name && result == null;
    final included = _included.contains(path.name);
    return Card(
      padding: const EdgeInsets.all(16),
      child: SizedBox(
        width: double.infinity,
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          spacing: 8,
          children: [
            Row(
              children: [
                Expanded(
                  child: Text(
                    path.name,
                    style: AppTextStyle.headline.of(context),
                  ),
                ),
                TextButton.icon(
                  onPressed: () =>
                      Clipboard.setData(ClipboardData(text: path.listen)),
                  icon: const GlyphIcon(AppGlyphs.copy, size: 16),
                  label: Text(path.listen),
                ),
              ],
            ),
            SelectableText(path.hops.join(' → ')),
            Wrap(
              spacing: 8,
              runSpacing: 6,
              crossAxisAlignment: WrapCrossAlignment.center,
              children: [
                TextButton.icon(
                  icon: GlyphIcon(included ? AppGlyphs.check : AppGlyphs.add),
                  label: Text(
                    _text(context, '加入 Photon 配置', 'Include in Photon profile'),
                  ),
                  onPressed: _busy
                      ? null
                      : () => _run(() async {
                          await _bridge.includePath(path.name, !included);
                          final selected = await _bridge.includedPaths();
                          if (mounted) setState(() => _included = selected);
                        }),
                ),
                TextButton(
                  onPressed: _busy ? null : () => _edit(snapshot, path),
                  child: Text(_text(context, '编辑', 'Edit')),
                ),
                _choiceMenu(
                  title: _text(context, '探测', 'Test'),
                  enabled:
                      !_busy && !(probe != null && probe['result'] == null),
                  onSelected: (kind) => _probe(path, kind),
                  choices: [
                    ('connectivity', _text(context, '连通性', 'Connectivity')),
                    ('dns', 'UDP DNS'),
                    ('download', _text(context, '下载速度', 'Download speed')),
                    ('custom', _text(context, '自定义目标', 'Custom target')),
                  ],
                ),
                IconButton(
                  tooltip: _text(context, '删除', 'Delete'),
                  onPressed: _busy ? null : () => _delete(path),
                  icon: const GlyphIcon(AppGlyphs.delete),
                ),
              ],
            ),
            if (probing) const LinearProgressIndicator(),
            if (result != null)
              Text(
                result['ok'] == true
                    ? [
                        '${result['elapsed_ms']} ms',
                        if (result['download_mbps'] case final num speed)
                          '${speed.toStringAsFixed(2)} Mbps',
                      ].join(' · ')
                    : '${result['error'] ?? _text(context, '探测失败', 'Test failed')}',
              ),
          ],
        ),
      ),
    );
  }
}

const _links = ['h24', 'h26', 'h2p', 'h2l4', 'h2l6'];

Widget _choiceMenu<T>({
  required String title,
  required List<(T, String)> choices,
  required ValueChanged<T> onSelected,
  bool enabled = true,
  Glyph? buttonGlyph,
  ButtonStyle? style,
}) => PopupAnchor(
  targetBuilder: (open) {
    final onPressed = enabled && choices.isNotEmpty ? open : null;
    return buttonGlyph != null
        ? IconButton(
            tooltip: title,
            onPressed: onPressed,
            icon: GlyphIcon(buttonGlyph),
          )
        : TextButton.icon(
            onPressed: onPressed,
            style: style,
            icon: const GlyphIcon(AppGlyphs.chevronDown, size: 14),
            label: Text(title),
          );
  },
  popupBuilder: (_) => PopupMenu(
    maxVisibleItems: 8,
    items: [
      for (final (value, label) in choices)
        PopupMenuItem(label: label, onPressed: () => onSelected(value)),
    ],
  ),
);

class _HopDraft {
  _HopDraft([String? hop])
    : node = TextEditingController(text: hop?.split('@').first ?? ''),
      link = hop?.split('@').last ?? 'h2l4';

  final TextEditingController node;
  String link;
  String get value => '${node.text.trim()}@$link';
}

class _PathEditor extends StatefulWidget {
  const _PathEditor({required this.snapshot, required this.onSave, this.path});

  final PhotonPathSnapshot snapshot;
  final PhotonProxyPath? path;
  final Future<void> Function(Map<String, dynamic>) onSave;

  @override
  State<_PathEditor> createState() => _PathEditorState();
}

class _PathEditorState extends State<_PathEditor> {
  final _form = GlobalKey<FormState>();
  late final _name = TextEditingController(text: widget.path?.name);
  late final _udp = TextEditingController(
    text: widget.path?.udpPrefixes.join(', '),
  );
  late final _relays = (widget.path?.hops ?? [])
      .take((widget.path?.hops.length ?? 1) - 1)
      .map(_HopDraft.new)
      .toList();
  late final _exit = _HopDraft(widget.path?.hops.lastOrNull);
  bool _saving = false;
  Object? _error;

  @override
  void dispose() {
    _name.dispose();
    _udp.dispose();
    for (final draft in [..._relays, _exit]) {
      draft.node.dispose();
    }
    super.dispose();
  }

  Future<void> _save() async {
    if (!_form.currentState!.validate()) return;
    setState(() {
      _saving = true;
      _error = null;
    });
    final request = <String, dynamic>{
      'action': widget.path == null ? 'create' : 'update',
      'name': _name.text.trim(),
      'hops': [
        for (final hop in [..._relays, _exit]) hop.value,
      ],
      'udp_prefixes': _udp.text
          .split(RegExp(r'[,\s]+'))
          .where((prefix) => prefix.isNotEmpty)
          .toList(),
    };
    try {
      await widget.onSave(request);
      if (mounted) Navigator.pop(context);
    } catch (error) {
      if (mounted) setState(() => _error = error);
    } finally {
      if (mounted) setState(() => _saving = false);
    }
  }

  Widget _hop(
    _HopDraft draft,
    List<PhotonPathEndpoint> choices,
    String label, {
    int? relayIndex,
  }) {
    final nodeField = TextFormField(
      controller: draft.node,
      validator: (value) => value == null || value.trim().isEmpty
          ? _text(context, '请选择或输入节点', 'Choose or enter a node')
          : null,
      decoration: InputDecoration(hintText: label),
    );
    final nodeControls = [
      Expanded(child: nodeField),
      if (choices.isNotEmpty)
        _choiceMenu(
          title: _text(context, '选节点', 'Choose node'),
          buttonGlyph: relayIndex == null ? null : AppGlyphs.connections,
          choices: [for (final endpoint in choices) (endpoint, endpoint.label)],
          onSelected: (endpoint) => setState(() {
            draft.node.text = endpoint.endpoint == 'relay'
                ? endpoint.zone
                : '${endpoint.zone}/${endpoint.endpoint}';
            if (!endpoint.links.contains(draft.link) &&
                endpoint.links.isNotEmpty) {
              draft.link = endpoint.links.first;
            }
          }),
        ),
    ];
    final linkMenu = _choiceMenu(
      title: draft.link,
      style: relayIndex == null
          ? null
          : const ButtonStyle(padding: EdgeInsets.symmetric(horizontal: 4)),
      choices: [
        for (final link in {..._links, draft.link}) (link, link),
      ],
      onSelected: (value) => setState(() => draft.link = value),
    );
    if (relayIndex == null) {
      return Row(
        key: ObjectKey(draft),
        spacing: 12,
        children: [...nodeControls, linkMenu],
      );
    }
    final actions = _relayActions(relayIndex);
    return LayoutBuilder(
      key: ObjectKey(draft),
      builder: (context, constraints) =>
          constraints.maxWidth >= 300 &&
              MediaQuery.textScalerOf(context).scale(16) <= 20
          ? Row(spacing: 4, children: [...nodeControls, linkMenu, actions])
          : Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Row(spacing: 4, children: nodeControls),
                Wrap(
                  alignment: WrapAlignment.end,
                  spacing: 4,
                  children: [linkMenu, actions],
                ),
              ],
            ),
    );
  }

  Widget _relayActions(int index) => Row(
    mainAxisSize: MainAxisSize.min,
    children: [
      IconButton(
        tooltip: _text(context, '上移', 'Move up'),
        onPressed: index == 0
            ? null
            : () => setState(
                () => _relays.insert(index - 1, _relays.removeAt(index)),
              ),
        icon: const GlyphIcon(AppGlyphs.arrowUp),
      ),
      IconButton(
        tooltip: _text(context, '下移', 'Move down'),
        onPressed: index == _relays.length - 1
            ? null
            : () => setState(
                () => _relays.insert(index + 1, _relays.removeAt(index)),
              ),
        icon: const GlyphIcon(AppGlyphs.arrowDown),
      ),
      IconButton(
        tooltip: _text(context, '移除中继', 'Remove relay'),
        onPressed: () => setState(() {
          // The text field disposes its listener on the next frame.
          final removed = _relays.removeAt(index);
          WidgetsBinding.instance.addPostFrameCallback(
            (_) => removed.node.dispose(),
          );
        }),
        icon: const GlyphIcon(AppGlyphs.remove),
      ),
    ],
  );

  @override
  Widget build(BuildContext context) => AlertDialog(
    title: widget.path == null
        ? _text(context, '新建路径', 'New path')
        : _text(context, '编辑路径', 'Edit path'),
    hasFields: true,
    actions: [
      TextButton(
        onPressed: () => Navigator.pop(context),
        child: Text(_text(context, '取消', 'Cancel')),
      ),
      FilledButton(
        onPressed: _saving ? null : _save,
        child: Text(_text(context, '保存', 'Save')),
      ),
    ],
    child: ConstrainedBox(
      constraints: BoxConstraints(
        maxWidth: 550,
        maxHeight: MediaQuery.sizeOf(context).height * 0.62,
      ),
      child: SingleChildScrollView(
        child: Form(
          key: _form,
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            spacing: 12,
            children: [
              TextFormField(
                controller: _name,
                readOnly: widget.path != null,
                decoration: InputDecoration(
                  hintText: _text(context, '路径名称', 'Path name'),
                ),
                validator: (value) => value == null || value.trim().isEmpty
                    ? _text(context, '请输入名称', 'Enter a name')
                    : null,
              ),
              for (final (i, draft) in _relays.indexed)
                _hop(
                  draft,
                  widget.snapshot.relays,
                  _text(context, '中继 ${i + 1}', 'Relay ${i + 1}'),
                  relayIndex: i,
                ),
              Align(
                alignment: Alignment.centerLeft,
                child: TextButton.icon(
                  onPressed: _relays.length >= 7
                      ? null
                      : () => setState(() => _relays.add(_HopDraft())),
                  icon: const GlyphIcon(AppGlyphs.add),
                  label: Text(_text(context, '添加中继', 'Add relay')),
                ),
              ),
              _hop(_exit, widget.snapshot.exits, _text(context, '出口', 'Exit')),
              TextField(
                controller: _udp,
                decoration: InputDecoration(
                  hintText: _text(
                    context,
                    'UDP 目标前缀（可留空）',
                    'UDP destination prefixes (optional)',
                  ),
                ),
              ),
              if (_error case final error?)
                Text(
                  '$error',
                  style: TextStyle(color: context.colorScheme.error),
                ),
            ],
          ),
        ),
      ),
    ),
  );
}

class _ProbeTargetDialog extends StatefulWidget {
  const _ProbeTargetDialog();

  @override
  State<_ProbeTargetDialog> createState() => _ProbeTargetState();
}

class _ProbeTargetState extends State<_ProbeTargetDialog> {
  final _target = TextEditingController();
  String _protocol = 'tcp';

  @override
  void dispose() {
    _target.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => AlertDialog(
    title: _text(context, '自定义探测', 'Custom test'),
    hasFields: true,
    actions: [
      TextButton(
        onPressed: () => Navigator.pop(context),
        child: Text(_text(context, '取消', 'Cancel')),
      ),
      FilledButton(
        onPressed: () {
          if (_target.text.trim().isNotEmpty) {
            Navigator.pop(context, {
              'protocol': _protocol,
              'target': _target.text.trim(),
            });
          }
        },
        child: Text(_text(context, '探测', 'Test')),
      ),
    ],
    child: Row(
      mainAxisSize: MainAxisSize.min,
      spacing: 12,
      children: [
        _choiceMenu(
          title: _protocol.toUpperCase(),
          choices: const [('tcp', 'TCP'), ('udp', 'UDP')],
          onSelected: (value) => setState(() => _protocol = value),
        ),
        SizedBox(
          width: 230,
          child: TextField(
            controller: _target,
            autofocus: true,
            decoration: const InputDecoration(hintText: 'Host:port'),
          ),
        ),
      ],
    ),
  );
}
