import 'package:fl_clash/enum/enum.dart';
import 'package:fl_clash/models/models.dart';
import 'package:fl_clash/photon/proxy_bridge.dart';
import 'package:fl_clash/providers/providers.dart';
import 'package:fl_clash/state.dart';
import 'package:fl_clash/views/proxies/card.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';

import '../helpers/host_scaffold.dart';
import '../helpers/test_app.dart';
import '../helpers/test_profiles.dart';

class _ProxySelectionRecorder extends ProxiesAction {
  String? selected;

  @override
  void changeProxyDebounce(String groupName, String proxyName) {
    selected = proxyName;
  }
}

void main() {
  testWidgets(
    'Photon card hides the protocol suffix and selects by full name',
    (tester) async {
      const title = '🇯🇵 jtti-hnd';
      const name = '$title · HTTP';
      const photon = Proxy(
        name: name,
        type: 'Http',
        providerName: 'photon-services',
      );
      const other = Proxy(
        name: name,
        type: 'Http',
        providerName: 'subscription',
      );
      final container = ProviderContainer(
        overrides: [
          profilesProvider.overrideWith(TestProfiles.new),
          proxiesActionProvider.overrideWith(_ProxySelectionRecorder.new),
          photonProxyCardTitlesProvider.overrideWithValue({
            (provider: 'photon-services', name: name): title,
          }),
        ],
      );
      addTearDown(container.dispose);
      globalState.container = container;
      await tester.pumpWidget(
        UncontrolledProviderScope(
          container: container,
          child: TestApp(
            homeBuilder: (child) => HostScaffold(body: child),
            child: Column(
              children: [
                for (final proxy in [photon, other])
                  SizedBox(
                    height: 120,
                    child: ProxyCard(
                      groupName: 'Photon',
                      testUrl: null,
                      proxy: proxy,
                      groupType: GroupType.Selector,
                      type: ProxyCardType.compact,
                    ),
                  ),
              ],
            ),
          ),
        ),
      );
      await tester.pumpAndSettle();

      final titleText = find.text(title, findRichText: true);
      expect(titleText, findsOneWidget);
      expect(find.text(name, findRichText: true), findsOneWidget);
      expect(find.text('Http'), findsNWidgets(2));
      await tester.tap(titleText);
      await tester.pump();
      final recorder = container.read(
        proxiesActionProvider.notifier,
      ) as _ProxySelectionRecorder;
      expect(recorder.selected, name);
    },
  );
}
