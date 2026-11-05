import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:yaml/yaml.dart';

Future<void> main(List<String> arguments) async {
  final config = File(arguments[arguments.indexOf('--config') + 1]);
  final bytes = await config.readAsBytes();
  final yaml = loadYaml(utf8.decode(bytes));
  final mode = yaml['fixture'];
  final input = StreamIterator(stdin.expand((chunk) => chunk));
  Future<int> byte() async {
    if (!await input.moveNext()) throw const FormatException('EOF');
    return input.current;
  }

  Future<void> send(String method, Map<String, dynamic> result) async {
    final body = utf8.encode(
      jsonEncode({'version': 1, 'method': method, 'result': result}),
    );
    final header = ByteData(4)..setUint32(0, body.length);
    // Exercise arbitrary transport boundaries, including a partial length.
    stdout.add(header.buffer.asUint8List().sublist(0, 1));
    await stdout.flush();
    stdout.add(header.buffer.asUint8List().sublist(1));
    stdout.add(body);
    await stdout.flush();
  }

  if (mode == 'oversized') {
    stdout.add((ByteData(4)..setUint32(0, (1 << 20) + 1)).buffer.asUint8List());
    await stdout.flush();
    await stdin.drain<void>();
    return;
  }
  await send('ready', {
    'pid': mode == 'wrong-pid' ? pid + 1 : pid,
    'state_path': mode == 'wrong-path' ? '/wrong' : yaml['state']['path'],
    'config_sha256': mode == 'wrong-config'
        ? '0' * 64
        : sha256.convert(bytes).toString(),
  });
  final marker = yaml['marker'] as String?;
  try {
    while (true) {
      final header = Uint8List.fromList([
        await byte(),
        await byte(),
        await byte(),
        await byte(),
      ]);
      final size = ByteData.sublistView(header).getUint32(0);
      final body = <int>[];
      for (var i = 0; i < size; i++) {
        body.add(await byte());
      }
      final method = jsonDecode(utf8.decode(body))['method'] as String;
      if (marker != null) {
        await File(marker).writeAsString('$method\n', mode: FileMode.append);
      }
      if (mode == 'crash') exit(23);
      if (mode == 'timeout') {
        await Future<void>.delayed(const Duration(seconds: 2));
      }
      await send(
        method,
        method == 'stop'
            ? {'stopped': true}
            : {'running': true, 'tunnel_ready': true, 'peers': []},
      );
      if (await byte() != 1) {
        throw const FormatException('Missing acknowledgement');
      }
      if (method == 'stop') break;
    }
  } on FormatException {
    // Closing the frontend is the backend's cancellation signal.
  } finally {
    await input.cancel();
    if (marker != null) {
      await File(marker).writeAsString('exited\n', mode: FileMode.append);
    }
  }
}
