import 'dart:typed_data';

import 'package:uuid/uuid.dart';

AuthenticatorData parseAuthenticatorData(Uint8List authenticatorData) {
  final rpIdHash = Uint8List.sublistView(authenticatorData, 0, 32);
  final flag = authenticatorData[32];

  // Signature counter (signCount), 32-bit unsigned big-endian integer.
  final signCount =
      ByteData.sublistView(authenticatorData, 33, 33 + 4).getUint32(0);

  final up = hasBitSet(flag, 0);
  final uv = hasBitSet(flag, 2);
  final be = hasBitSet(flag, 3);
  final bs = hasBitSet(flag, 4);

  final aaGuid = authenticatorData.length > 37
      ? (UuidValue.fromByteList(authenticatorData, offset: 37)
        ..validate(ValidationMode.nonStrict))
      : null;

  return AuthenticatorData(
    rpIdHashHex:
        rpIdHash.map((e) => e.toRadixString(16).padLeft(2, '0')).join(),
    userPresence: up,
    userVerification: uv,
    backupEligbility: be,
    backupState: bs,
    signCount: signCount,
    aaGuid: aaGuid,
  );
}

/// https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API/Authenticator_data
class AuthenticatorData {
  AuthenticatorData({
    required this.rpIdHashHex,
    required this.userPresence,
    required this.userVerification,
    required this.backupEligbility,
    required this.backupState,
    required this.signCount,
    required this.aaGuid,
  });

  /// SHA-256 hash of the Relying Party ID
  final String rpIdHashHex;

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
}

bool hasBitSet(int value, int index) {
  return (value & (1 << index)) != 0;
}
