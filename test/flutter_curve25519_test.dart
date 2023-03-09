import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:test/test.dart';

import 'package:flutter_curve25519/flutter_curve25519.dart';

void main() {
  test('adds one to input values', () {
    var seed = List.generate(32, (index) => Random().nextInt(256));
    seed = [
      111,
      86,
      162,
      109,
      102,
      28,
      169,
      34,
      246,
      115,
      174,
      238,
      63,
      152,
      213,
      203,
      171,
      99,
      57,
      26,
      114,
      57,
      127,
      12,
      172,
      206,
      83,
      95,
      67,
      151,
      17,
      16
    ];
    final keypair = Curve25519KeyPair.fromSeed(Uint8List.fromList(seed));
    final message =
        base64Decode("BSHHNbsuQxc5vqIU/8C9zp4ziaF+kbyAqSzvc2b6zDUG");
    var optRandom = List.generate(64, (index) => Random().nextInt(256));
    optRandom = [
      72,
      108,
      255,
      189,
      12,
      66,
      16,
      26,
      60,
      32,
      109,
      193,
      139,
      244,
      209,
      194,
      163,
      219,
      131,
      155,
      195,
      168,
      170,
      201,
      106,
      26,
      86,
      248,
      216,
      250,
      95,
      138,
      100,
      248,
      13,
      51,
      134,
      221,
      125,
      169,
      211,
      221,
      133,
      148,
      10,
      151,
      0,
      189,
      246,
      178,
      125,
      104,
      140,
      187,
      36,
      83,
      181,
      58,
      13,
      79,
      27,
      107,
      177,
      182
    ];
    final signature = Curve25519.sign(
        keypair.privateKey, message, Uint8List.fromList(optRandom));
    var pass = Curve25519.verify(keypair.publicKey, message, signature);
    // final publickey =
    //     base64Decode("Bfehf5eexgV5if/bW2B3+RGJJDaE7sE6YiTABzzUHQwl").sublist(1);
    // final message =
    //     base64Decode("BSHHNbsuQxc5vqIU/8C9zp4ziaF+kbyAqSzvc2b6zDUG");
    // final signature = base64Decode(
    //     "NrGeCn6ReYhGgFcD3KzBl/rpfk4lIpKxGkliuLWLQwU7vb7orbxUPJ9opqn1XS7ql31H6Tu2qwjqVmN12+gehA==");

    // var pass = Curve25519.verify(publickey, message, signature);
    expect(pass, 1);
  });
}
