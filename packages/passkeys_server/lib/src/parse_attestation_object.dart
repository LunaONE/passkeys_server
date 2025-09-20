import 'dart:typed_data';

import 'package:cbor/cbor.dart';
import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';
import 'package:pointycastle/ecc/curves/secp256r1.dart' show ECCurve_secp256r1;
import 'package:pointycastle/pointycastle.dart' as pc;
import 'package:uuid/uuid.dart';

/// Parses the attestation object received during registration
(AuthenticatorData,) parseAttestationObject(Uint8List attestationObject) {
  final authData = ((cbor.decode(attestationObject)
          as CborMap)[CborString('authData')]! as CborBytes)
      .bytes;

  return (_parseAuthenticatorData(Uint8List.fromList(authData)),);
}

AuthenticatorData _parseAuthenticatorData(Uint8List authenticatorData) {
  final rpIdHash = Uint8List.sublistView(authenticatorData, 0, 32);
  final flag = authenticatorData[32];

  // Signature counter (signCount), 32-bit unsigned big-endian integer.
  final signCount =
      ByteData.sublistView(authenticatorData, 33, 33 + 4).getUint32(0);

  final up = hasBitSet(flag, 0);
  final uv = hasBitSet(flag, 2);
  final be = hasBitSet(flag, 3);
  final bs = hasBitSet(flag, 4);

  final UuidValue? aaGuid;
  final Uint8List? credentialId;
  final int? alg;
  final JWTKey? publicKey;
  if (authenticatorData.length > 37) {
    aaGuid = (UuidValue.fromByteList(authenticatorData, offset: 37)
      ..validate(ValidationMode.nonStrict));

    final credentialIdLength = ByteData.sublistView(
      authenticatorData,
      37 + 16,
      37 + 16 + 2,
    ).getUint16(0);

    credentialId = Uint8List.sublistView(
      authenticatorData,
      37 + 16 + 2,
      37 + 16 + 2 + credentialIdLength,
    );

    final credentialPublicKey = cbor.decode(
      Uint8List.sublistView(
        authenticatorData,
        37 + 16 + 2 + credentialIdLength,
      ),
    ) as CborMap;

    // https://datatracker.ietf.org/doc/html/rfc8152#section-7.1
    alg = (credentialPublicKey[CborValue(3)]! as CborInt).toInt();

    if (alg == -7) {
      final algorithm = ECCurve_secp256r1();

      publicKey = ECPublicKey.raw(
        pc.ECPublicKey(
          algorithm.curve.createPoint(
            BigInt.parse(
              (credentialPublicKey[CborValue(-2)]! as CborBytes).bytes.toHex(),
              radix: 16,
            ),
            BigInt.parse(
              (credentialPublicKey[CborValue(-3)]! as CborBytes).bytes.toHex(),
              radix: 16,
            ),
          ),
          algorithm,
        ),
      );
    } else if (alg == -257) {
      publicKey = RSAPublicKey.raw(
        pc.RSAPublicKey(
          BigInt.parse(
            (credentialPublicKey[CborValue(-1)]! as CborBytes).bytes.toHex(),
            radix: 16,
          ),
          BigInt.parse(
            (credentialPublicKey[CborValue(-2)]! as CborBytes).bytes.toHex(),
            radix: 16,
          ),
        ),
      );
    } else {
      throw Exception('Unsupported algorithm');
    }
  } else {
    aaGuid = null;
    credentialId = null;
    alg = null;
    publicKey = null;
  }

  return AuthenticatorData(
    rpIdHash: rpIdHash,
    userPresence: up,
    userVerification: uv,
    backupEligbility: be,
    backupState: bs,
    signCount: signCount,
    aaGuid: aaGuid,
    credentialId: credentialId,
    alg: alg,
    publicKey: publicKey,
  );
}

/// https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API/Authenticator_data
class AuthenticatorData {
  AuthenticatorData({
    required this.rpIdHash,
    required this.userPresence,
    required this.userVerification,
    required this.backupEligbility,
    required this.backupState,
    required this.signCount,
    required this.aaGuid,
    required this.credentialId,
    required this.alg,
    required this.publicKey,
  });

  /// SHA-256 hash of the Relying Party ID
  final Uint8List rpIdHash;

  final bool userPresence;
  final bool userVerification;
  final bool backupEligbility;
  final bool backupState;

  /// Optional signature counter. Set to 0 if not available (e.g. iCloud and Chrome do not send this).
  final int signCount;

  /// Authenticator Attestation Globally Unique Identifier
  ///
  /// Can be matched against https://github.com/passkeydeveloper/passkey-authenticator-aaguids/blob/main/aaguid.json
  final UuidValue? aaGuid;

  /// Credential (key) ID
  final Uint8List? credentialId;

  final int? alg;

  final JWTKey? publicKey;
}

bool hasBitSet(int value, int index) {
  return (value & (1 << index)) != 0;
}

extension on List<int> {
  String toHex() {
    return map((e) => e.toRadixString(16).padLeft(2, '0')).join();
  }
}
