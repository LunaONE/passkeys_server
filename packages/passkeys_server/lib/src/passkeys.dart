import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';
import 'package:passkeys_server/passkeys_server.dart';
import 'package:passkeys_server/src/rng.dart';
import 'package:passkeys_server/src/util/internal.dart';

class Passkeys {
  Passkeys({
    required PasskeysConfig config,
  })  : _config = config,
        relyingPartyId = config.relyingPartyId;

  final PasskeysConfig _config;

  final String relyingPartyId;

  // ES256 (aka P256)
  static const _es256AlgorithmId = -7;

  // RS256 (aka RSA)
  static const _rs256AlgorithmId = -257;

  final supportedAlgorithms = Set.unmodifiable({
    _es256AlgorithmId,
    _rs256AlgorithmId,
  });

  Future<Uint8List> createChallenge() async {
    return Uint8ListUtil.random(32);
  }

  /// Throws if invalid
  Future<void> verifyRegistration({
    required Uint8List keyId,
    required Uint8List clientDataJSON,
    required Uint8List attestationObject,

    /// The challenge created by the server for the client
    required Uint8List challenge,
  }) async {
    final rp256 = sha256.convert(utf8.encode(_config.relyingPartyId)).bytes;

    final (authenticatorData,) = parseAttestationObject(attestationObject);

    if (!bytesEqual(keyId, authenticatorData.credentialId!)) {
      throw Exception(
        'Client did not provide the same key ID as the authenticator data',
      );
    }

    if (!bytesEqual(rp256, authenticatorData.rpIdHash)) {
      throw Exception(
        'Client did not provide correct rpId hash in authenticator data',
      );
    }

    final clientData = jsonDecode(utf8.decode(clientDataJSON)) as Map;
    final clientChallege = base64Decode(
      padBase64(clientData['challenge'] as String),
    );

    if (!bytesEqual(challenge, clientChallege)) {
      throw Exception('The wrong challenge was solved by the client.');
    }
  }

  Future<void> verifyLogin({
    required Uint8List registrationAttestationObject,
    required Uint8List authenticatorData,
    required Uint8List clientDataJSON,
    required Uint8List signature,

    /// The challenge created by the server for the client
    required Uint8List challenge,
  }) async {
    final (registrationAuthenticatorData,) =
        parseAttestationObject(registrationAttestationObject);

    switch (registrationAuthenticatorData.alg) {
      case _es256AlgorithmId:
        final originalChallenge = challenge;

        final publicKey =
            registrationAuthenticatorData.publicKey! as ECPublicKey;

        final clientData = jsonDecode(utf8.decode(clientDataJSON)) as Map;
        final clientChallege = base64Decode(
          padBase64(clientData['challenge'] as String),
        );

        if (!bytesEqual(originalChallenge, clientChallege)) {
          throw Exception('The wrong challenge was solved by the client.');
        }

        final signedData = Uint8List.fromList([
          ...authenticatorData,
          ...sha256.convert(clientDataJSON).bytes,
        ]);

        final valid = const ECDSAAlgorithm('ES256').verify(
          publicKey,
          signedData,
          derToRawSignature(signature),
        );

        if (!valid) {
          throw Exception('Invalid signature');
        }

      case _rs256AlgorithmId:
        final originalChallenge = challenge;

        final publicKey =
            registrationAuthenticatorData.publicKey! as RSAPublicKey;

        final clientData = jsonDecode(utf8.decode(clientDataJSON)) as Map;
        final clientChallege = base64Decode(
          padBase64(clientData['challenge'] as String),
        );

        if (!bytesEqual(originalChallenge, clientChallege)) {
          throw Exception('The wrong challenge was solved by the client.');
        }

        final signedData = Uint8List.fromList([
          ...authenticatorData,
          ...sha256.convert(clientDataJSON).bytes,
        ]);

        final valid = const RSAAlgorithm('RS256', null).verify(
          publicKey,
          signedData,
          signature,
        );

        if (!valid) {
          throw Exception('Invalid signature');
        }

      default:
        throw Exception(
          'Unsupport algorithm ${registrationAuthenticatorData.alg}.',
        );
    }
  }
}
