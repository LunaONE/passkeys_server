import 'dart:convert';
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import 'package:crypto/crypto.dart';
import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';
import 'package:passkeys_server/src/config.dart';
import 'package:passkeys_server/src/rng.dart';
import 'package:passkeys_server/src/storage.dart';

class Passkeys {
  Passkeys({
    required PasskeysConfig config,
    required PasskeyStorage storage,
  })  : _config = config,
        _storage = storage,
        relyingPartyId = config.relyingPartyId;

  final PasskeysConfig _config;

  final PasskeyStorage _storage;

  final String relyingPartyId;

  final supportedAlgorithms = Set.unmodifiable({-7});

  Future<
      ({
        Uint8List challenge,
        Uint8List userId,
      })> createRegistrationChallenge() async {
    final userId = Uint8ListUtil.random(16);
    final challenge = Uint8ListUtil.random(32);

    await _storage.storeRegistrationChallenge(
      userId: userId,
      challenge: challenge,
    );

    return (challenge: challenge, userId: userId);
  }

  /// Throws if invalid
  Future<void> verifyRegistration({
    required Uint8List userId,
    required Uint8List keyId,
    required Uint8List clientDataJSON,
    required Uint8List publicKey,
    required int publicKeyAlgorithm,
    required Uint8List attestationObject,
    required Uint8List authenticatorData,
  }) async {
    final rp256 = sha256.convert(utf8.encode(_config.relyingPartyId)).bytes;
    final clientHash = Uint8List.sublistView(authenticatorData, 0, 32);

    if (!bytesEqual(rp256, clientHash)) {
      throw Exception(
        'Client did not provide correct hash in authenticator data',
      );
    }

    await _storage.storeRegistration(
      userId: userId,
      keyId: keyId,
      clientDataJSON: clientDataJSON,
      publicKey: publicKey,
      publicKeyAlgorithm: publicKeyAlgorithm,
      attestationObject: attestationObject,
      authenticatorData: authenticatorData,
    );
  }

  Future<
      ({
        Uint8List challenge,
        Uint8List loginId,
      })> createLoginChallenge() async {
    final loginId = Uint8ListUtil.random(16);
    final challenge = Uint8ListUtil.random(32);

    await _storage.storeLoginChallenge(id: loginId, challenge: challenge);

    return (challenge: challenge, loginId: loginId);
  }

  Future<void> verifyLogin({
    required Uint8List loginId,
    required Uint8List keyId,
    required Uint8List authenticatorData,
    required Uint8List clientDataJSON,
    required Uint8List signature,
    // required Uint8List userHandle,
  }) async {
    final originalChallenge = await _storage.receiveRegistrationChallenge(
      userId: loginId,
    );

    final publicKey = await _storage.getPublicKey(keyId: keyId);

    final key = ECPublicKey.bytes(publicKey);

    final clientData = jsonDecode(utf8.decode(clientDataJSON)) as Map;
    final clientChallege = base64Decode(
      padBase64(clientData['challenge'] as String),
    );

    if (!bytesEqual(originalChallenge, clientChallege)) {
      throw Exception('Challenge was not solved correctly.');
    }

    final signedData = Uint8List.fromList([
      ...authenticatorData,
      ...sha256.convert(clientDataJSON).bytes,
    ]);

    final valid = const ECDSAAlgorithm('ES256').verify(
      key,
      signedData,
      derToRawSignature(signature),
    );

    if (!valid) {
      throw Exception('Invalid signature');
    }
  }
}

bool bytesEqual(List<int> a, List<int> b) {
  if (a.length != b.length) {
    return false;
  }

  for (var x = 0; x < a.length; x++) {
    if (a[x] != b[x]) {
      return false;
    }
  }

  return true;
}

// TODO: Internal user vs. passkey ID

Uint8List derToRawSignature(Uint8List der) {
  final asn1 = ASN1Parser(der);
  final seq = asn1.nextObject() as ASN1Sequence;
  final r = (seq.elements[0] as ASN1Integer).valueBytes();
  final s = (seq.elements[1] as ASN1Integer).valueBytes();

  Uint8List padOrTrim(Uint8List v) {
    if (v.length == 32) {
      return v;
    }
    if (v.length > 32) {
      return v.sublist(v.length - 32);
    }
    final out = Uint8List(32)..setRange(32 - v.length, 32, v);
    return out;
  }

  final rPadded = padOrTrim(r);
  final sPadded = padOrTrim(s);

  return Uint8List.fromList([...rPadded, ...sPadded]);
}

String padBase64(String s) {
  while (s.length % 4 != 0) {
    // ignore: parameter_assignments, use_string_buffers
    s += '=';
  }

  return s;
}
