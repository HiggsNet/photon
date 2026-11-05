import 'package:file_picker/file_picker.dart';
import 'package:fl_clash/common/common.dart';
import 'package:fl_clash/features/form/form.dart';
import 'package:fl_clash/widgets/widgets.dart';
import 'package:flutter/widgets.dart';
import 'package:path/path.dart' as path;

import 'setup.dart';

Future<String?> choosePhotonConfig() async {
  final file = await picker.pickerFile();
  final uri = file?.uri;
  return uri != null && uri.scheme == 'file' ? uri.toFilePath() : null;
}

Future<String?> editPhotonSettings(
  BuildContext context, {
  String? config,
}) async {
  final create = config == null;
  if (create) {
    final title = context.appLocalizations.photonCreateConfig;
    final folder = await FilePicker.getDirectoryPath(
      dialogTitle: title,
      initialDirectory: await appPath.downloadDirPath,
    );
    if (folder == null) return null;
    config = path.join(folder, 'photon.yaml');
  }
  if (!context.mounted) return null;
  final session = await PhotonConfigSession.open(config, create: create);
  try {
    if (!context.mounted) return null;
    final saved = await showFormSheet<bool>(
      context: context,
      builder: (_) => _PhotonSettingsForm(session: session, config: config!),
    );
    return saved == true ? config : null;
  } finally {
    await session.close();
  }
}

Future<String?> showPhotonImport(BuildContext context, String config) async {
  final imported = await showFormSheet<bool>(
    context: context,
    builder: (_) => _PhotonImportForm(config: config),
  );
  return imported == true ? config : null;
}

class _PhotonSettingsForm extends StatefulWidget {
  const _PhotonSettingsForm({required this.session, required this.config});

  final PhotonConfigSession session;
  final String config;

  @override
  State<_PhotonSettingsForm> createState() => _PhotonSettingsFormState();
}

class _PhotonSettingsFormState extends State<_PhotonSettingsForm> {
  late final _form = Map<String, dynamic>.of(widget.session.form);
  late final _hints = [
    for (final hint in _form['bootstrap_hints'] as List? ?? const [])
      Map<String, dynamic>.from(hint as Map),
  ];
  bool _saving = false;
  String? _error;

  Future<void> _save() async {
    if (_saving) return;
    setState(() {
      _saving = true;
      _error = null;
    });
    try {
      await widget.session.save({..._form, 'bootstrap_hints': _hints});
      if (mounted) Navigator.pop(context, true);
    } catch (error) {
      if (mounted) setState(() => _error = error.toString());
    } finally {
      if (mounted) setState(() => _saving = false);
    }
  }

  Widget _field(String name, String label, {bool multiline = false}) => FormRow(
    title: label,
    trailing: multiline
        ? TextFormField(
            key: ValueKey(name),
            initialValue: _form[name] as String,
            autocorrect: false,
            maxLines: null,
            keyboardType: TextInputType.multiline,
            onChanged: (value) => _form[name] = value,
          )
        : FormRowTextField(
            key: ValueKey(name),
            initialValue: _form[name] as String,
            autocorrect: false,
            onChanged: (value) => _form[name] = value,
          ),
  );

  @override
  Widget build(BuildContext context) {
    final l = context.appLocalizations;
    final create = _form['new_config'] == true;
    return PopScope(
      canPop: !_saving,
      child: FormPage(
        title: create ? l.photonCreateConfig : l.photonSettings,
        onSave: _save,
        saving: _saving,
        error: _error,
        children: [
          Text(widget.config),
          generateSection(
            footer: create ? l.photonFirstRunHint : null,
            items: [
              _field('managed_zone', l.photonManagedZone),
              _field('root_public_key', l.photonRootKey),
              _field('split_routes', l.photonRoutes, multiline: true),
              _field(
                'allowed_gateways',
                l.photonAllowedGateways,
                multiline: true,
              ),
            ],
          ),
          generateSection(
            title: l.photonBootstrap,
            items: [
              for (final hint in _hints)
                Column(
                  key: ObjectKey(hint),
                  children: [
                    FormRow(
                      title: l.photonManagedZone,
                      trailing: FormRowTextField(
                        initialValue: hint['peer'] as String?,
                        autocorrect: false,
                        onChanged: (value) => hint['peer'] = value,
                      ),
                    ),
                    FormRow(
                      title: l.address,
                      trailing: FormRowTextField(
                        initialValue: hint['address'] as String?,
                        hintText: 'gateway.example:33434',
                        autocorrect: false,
                        onChanged: (value) => hint['address'] = value,
                      ),
                    ),
                    TextButton(
                      onPressed: _saving
                          ? null
                          : () => setState(() => _hints.remove(hint)),
                      child: Text(l.remove),
                    ),
                  ],
                ),
              TextButton(
                onPressed: _saving
                    ? null
                    : () => setState(() => _hints.add({})),
                child: Text(l.add),
              ),
            ],
          ),
          generateSection(
            title: l.advancedConfig,
            items: [
              _field('state_path', l.photonStatePath),
              _field('overlay_id', l.photonOverlay),
              _field('gossip_listen', l.photonGossipListen),
              _field('adapter_name', l.photonAdapter),
              _field('mtu', 'MTU'),
              _field('log_level', l.logLevel),
              _field('initial_backoff', l.photonInitialRetry),
              _field('max_backoff', l.photonMaxRetry),
            ],
          ),
        ],
      ),
    );
  }
}

class _PhotonImportForm extends StatefulWidget {
  const _PhotonImportForm({required this.config});

  final String config;

  @override
  State<_PhotonImportForm> createState() => _PhotonImportFormState();
}

class _PhotonImportFormState extends State<_PhotonImportForm> {
  String? _bundle;
  String? _key;
  String? _error;
  bool _busy = false;

  Future<void> _pick({required bool key}) async {
    if (_busy) return;
    setState(() => _busy = true);
    try {
      final selected = await choosePhotonConfig();
      if (!mounted || selected == null) return;
      setState(() {
        if (key) {
          _key = selected;
        } else {
          _bundle = selected;
        }
        _error = null;
      });
    } catch (error) {
      if (mounted) setState(() => _error = error.toString());
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _submit() async {
    if (_busy) return;
    final bundle = _bundle;
    final key = _key;
    if (bundle == null || key == null) {
      setState(() => _error = context.appLocalizations.photonImportFiles);
      return;
    }
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await importPhotonIdentity(
        config: widget.config,
        bundle: bundle,
        key: key,
      );
      if (mounted) Navigator.pop(context, true);
    } catch (error) {
      if (mounted) setState(() => _error = error.toString());
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final l = context.appLocalizations;
    return PopScope(
      canPop: !_busy,
      child: FormPage(
        title: l.photonImportIdentity,
        onSave: _submit,
        saveLabel: l.import,
        saving: _busy,
        error: _error,
        children: [
          Text(widget.config),
          generateSection(
            footer: l.photonImportHint,
            items: [
              FormRow(
                title: l.photonJoinBundle,
                trailing: TextButton(
                  onPressed: _busy ? null : () => _pick(key: false),
                  child: Text(
                    _bundle == null ? l.importFile : path.basename(_bundle!),
                  ),
                ),
              ),
              FormRow(
                title: l.privateKey,
                trailing: TextButton(
                  onPressed: _busy ? null : () => _pick(key: true),
                  child: Text(
                    _key == null ? l.importFile : path.basename(_key!),
                  ),
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }
}
