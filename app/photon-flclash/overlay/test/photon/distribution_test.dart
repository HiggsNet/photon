import 'package:fl_clash/common/app_update.dart';
import 'package:fl_clash/common/constant.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('Photon builds use Photon releases and disable upstream replacement', () {
    const photonBuild = bool.fromEnvironment('PHOTON_BUILD');
    final previous = resolveSelfUpdateSuffix;
    addTearDown(() => resolveSelfUpdateSuffix = previous);
    resolveSelfUpdateSuffix = () => 'windows-amd64-setup.exe';

    expect(repository, photonBuild ? 'HiggsNet/photon' : 'chen08209/FlClash');
    expect(selfUpdateSuffix, photonBuild ? isNull : 'windows-amd64-setup.exe');
  });
}
