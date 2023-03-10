import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter_curve25519/flutter_curve25519.dart';

void main(List<String> args) {
  var seed = List.generate(32, (index) => Random().nextInt(256));
  final keypair = Curve25519KeyPair.fromSeed(Uint8List.fromList(seed));
  // private key to public key
  final keypair1 = Curve25519KeyPair.fromSeed(keypair.privateKey);
  print(keypair1);
  final message = base64Decode("BSHHNbsuQxc5vqIU/8C9zp4ziaF+kbyAqSzvc2b6zDUG");
  var optRandom = List.generate(64, (index) => Random().nextInt(256));
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
  print('pass: $pass');
}
