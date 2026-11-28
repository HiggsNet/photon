import 'dart:convert';

import 'package:fl_clash/common/common.dart';
import 'package:fl_clash/state.dart';
import 'package:fl_clash/widgets/widgets.dart';
import 'package:flutter/services.dart';
import 'package:flutter/widgets.dart';

const photonProxyTemplateExample = '''dns:
  nameserver:
    - https://dns.alidns.com/dns-query
tun:
  mtu: 1400
  route-exclude-address:
    - 192.168.0.0/16
proxy-groups:
  - name: Photon
  - name: Photon Paths
  - name: My Proxy
    type: select
    proxies: [Photon, Photon Auto, Photon Balance, Photon Paths, DIRECT]
  - name: JP
    type: url-test
    use: [photon-services]
    filter: ' / jp / '
    empty-fallback: REJECT
    url: https://www.gstatic.com/generate_204
    interval: 300
  - name: OpenAI
    type: select
    proxies: [Photon, JP]
    use: [photon-services]
    empty-fallback: REJECT
rules:
  - RULE-SET,openai,OpenAI
  - DOMAIN-SUFFIX,example.com,My Proxy
  - DOMAIN-SUFFIX,example.org,Photon Paths
  - MATCH,Photon
rule-providers:
  openai:
    type: http
    behavior: domain
    format: yaml
    url: https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/openai.yaml
    path: ./ruleset/openai.yaml
    interval: 86400
''';

class PhotonTemplateHelp extends StatefulWidget {
  const PhotonTemplateHelp({super.key});

  @override
  State<PhotonTemplateHelp> createState() => _PhotonTemplateHelpState();
}

class _PhotonTemplateHelpState extends State<PhotonTemplateHelp> {
  bool _exporting = false;

  Future<void> _copy(String text) => globalState.safeRun(() async {
    await Clipboard.setData(ClipboardData(text: text));
    if (mounted) dialogs.showBanner(context.appLocalizations.copySuccess);
  });

  Future<void> _export() async {
    if (_exporting) return;
    setState(() => _exporting = true);
    try {
      final saved = await picker.saveFile(
        'photon.proxy.example.yaml',
        Uint8List.fromList(utf8.encode(photonProxyTemplateExample)),
      );
      if (saved != null && mounted) {
        dialogs.showBanner(context.appLocalizations.exportSuccess);
      }
    } catch (error) {
      if (mounted) await dialogs.showAlert(message: TextSpan(text: '$error'));
    } finally {
      if (mounted) setState(() => _exporting = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final l = context.appLocalizations;
    final sections = [
      (l.photonTemplateKept, l.photonTemplateKeptHint),
      (l.photonTemplateManaged, l.photonTemplateManagedHint),
      (l.photonTemplateSafeguards, l.photonTemplateSafeguardsHint),
      (l.photonTemplateIgnored, l.photonTemplateIgnoredHint),
    ];
    final heading = AppTextStyle.headline.of(context);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      spacing: 12,
      children: [
        Text(l.photonTemplateHelp, style: heading),
        Text(l.photonTemplateHint),
        Text(l.photonTemplatePathsHint),
        Text(l.photonTemplateAiHint),
        TextButton(
          onPressed: () => _copy(l.photonTemplateAiPrompt),
          child: Text(l.photonTemplateCopyAiPrompt),
        ),
        for (final (title, body) in sections)
          Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            spacing: 6,
            children: [
              Text(title, style: heading),
              SelectableText(body),
            ],
          ),
        Text(l.photonTemplateExample, style: heading),
        Text(l.photonTemplateExampleHint),
        Wrap(
          spacing: 8,
          runSpacing: 8,
          children: [
            TextButton(
              onPressed: () => _copy(photonProxyTemplateExample),
              child: Text(l.copy),
            ),
            TextButton(
              onPressed: _exporting ? null : _export,
              child: Text(l.photonTemplateExportExample),
            ),
          ],
        ),
        SelectableText(
          photonProxyTemplateExample,
          style: AppTextStyle.body
              .of(context)
              .copyWith(fontFamily: 'monospace'),
        ),
      ],
    );
  }
}
