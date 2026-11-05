import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

/// Real UDP ASSOCIATE probe through a local SOCKS5 listener, to an IPv4 DNS
/// target. Keeps the control connection open for the lifetime of the relay.
Future<Map<String, dynamic>> probeSocksUDP(int port) async {
  final control = await Socket.connect(
    InternetAddress.loopbackIPv4,
    port,
    timeout: const Duration(seconds: 10),
  );
  final bytes = StreamIterator<int>(control.expand((chunk) => chunk));
  RawDatagramSocket? udp;
  StreamSubscription<RawSocketEvent>? udpEvents;
  Future<List<int>> read(int count) async {
    final result = <int>[];
    for (var i = 0; i < count; i++) {
      if (!await bytes.moveNext().timeout(const Duration(seconds: 10))) {
        throw const SocketException('SOCKS control connection closed');
      }
      result.add(bytes.current);
    }
    return result;
  }

  try {
    control.add([5, 1, 0]);
    final method = await read(2);
    if (method[0] != 5 || method[1] != 0) {
      throw const SocketException(
        'SOCKS listener rejected no-auth negotiation',
      );
    }
    control.add([5, 3, 0, 1, 0, 0, 0, 0, 0, 0]);
    final header = await read(4);
    if (header[0] != 5 || header[1] != 0) {
      throw SocketException('SOCKS UDP associate failed: $header');
    }
    final InternetAddress relay;
    if (header[3] == 1) {
      relay = InternetAddress.fromRawAddress(Uint8List.fromList(await read(4)));
    } else if (header[3] == 4) {
      relay = InternetAddress.fromRawAddress(
        Uint8List.fromList(await read(16)),
      );
    } else {
      throw SocketException('Unexpected local UDP relay address: ${header[3]}');
    }
    final rawPort = await read(2);
    final relayPort = rawPort[0] * 256 + rawPort[1];
    final destination = relay.rawAddress.every((byte) => byte == 0)
        ? control.remoteAddress
        : relay;
    udp = await RawDatagramSocket.bind(
      destination.type == InternetAddressType.IPv6
          ? InternetAddress.loopbackIPv6
          : InternetAddress.loopbackIPv4,
      0,
    );
    final socket = udp;
    final received = Completer<Datagram>();
    udpEvents = socket.listen((event) {
      if (event != RawSocketEvent.read) return;
      final datagram = socket.receive();
      if (datagram != null && !received.isCompleted) {
        received.complete(datagram);
      }
    });
    // DNS example.com IN A, transaction ID 0x5048, recursive query.
    final query = <int>[
      0x50,
      0x48,
      1,
      0,
      0,
      1,
      0,
      0,
      0,
      0,
      0,
      0,
      7,
      ...'example'.codeUnits,
      3,
      ...'com'.codeUnits,
      0,
      0,
      1,
      0,
      1,
    ];
    udp.send([0, 0, 0, 1, 1, 1, 1, 1, 0, 53, ...query], destination, relayPort);
    final response = await received.future.timeout(const Duration(seconds: 15));
    final data = response.data;
    final offset = data.length < 4
        ? data.length
        : switch (data[3]) {
            1 => 10,
            4 => 22,
            3 => data.length < 5 ? data.length : 7 + data[4],
            _ => data.length,
          };
    if (data.length < offset + 12 ||
        data[0] != 0 ||
        data[1] != 0 ||
        data[2] != 0 ||
        data[offset] != 0x50 ||
        data[offset + 1] != 0x48 ||
        data[offset + 2] & 0x80 == 0 ||
        data[offset + 3] & 15 != 0) {
      throw const SocketException('Invalid relayed DNS response');
    }
    return {
      'relay': '${destination.address}:$relayPort',
      'bytes': data.length,
      'answers': data[offset + 6] * 256 + data[offset + 7],
    };
  } finally {
    await udpEvents?.cancel();
    udp?.close();
    control.destroy();
    await bytes.cancel();
  }
}
