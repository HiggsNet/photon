import 'package:fl_clash/common/app_update.dart';
import 'package:fl_clash/common/constant.dart';
import 'package:fl_clash/state.dart';
import 'package:fl_clash/views/about.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:package_info_plus/package_info_plus.dart';

import '../helpers/test_app.dart';

void main() {
  test(
    'Photon builds use Photon releases and disable upstream replacement',
    () {
      const photonBuild = bool.fromEnvironment('PHOTON_BUILD');
      final previous = resolveSelfUpdateSuffix;
      addTearDown(() => resolveSelfUpdateSuffix = previous);
      resolveSelfUpdateSuffix = () => 'windows-amd64-setup.exe';

      expect(repository, photonBuild ? 'HiggsNet/photon' : 'chen08209/FlClash');
      expect(
        selfUpdateSuffix,
        photonBuild ? isNull : 'windows-amd64-setup.exe',
      );
    },
  );

  testWidgets('About shows the packaged Photon and upstream versions', (
    tester,
  ) async {
    const version = String.fromEnvironment('PHOTON_PACKAGE_VERSION');
    globalState.packageInfo = PackageInfo(
      appName: 'FlClash',
      packageName: 'com.follow.clash',
      version: '0.9.3',
      buildNumber: '1',
    );

    await tester.pumpWidget(
      const TestApp(wrapInProviderScope: true, child: AboutView()),
    );

    expect(
      find.text('Photon-FlClash $version'),
      version.isEmpty ? findsNothing : findsOneWidget,
    );
    expect(
      find.text(version.isEmpty ? 'v0.9.3' : 'FlClash v0.9.3'),
      findsOneWidget,
    );
  });
}
