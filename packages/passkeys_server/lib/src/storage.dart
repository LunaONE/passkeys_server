import 'dart:convert';
import 'dart:typed_data';

abstract class PasskeyStorage {
  // factory PasskeyStorage.create() = _PasskeyStorageFromFunc.new;

  ///
  Future<void> storeRegistrationChallenge({
    required Uint8List userId,
    required Uint8List challenge,
  });

  Future<Uint8List> receiveRegistrationChallenge({
    required Uint8List userId,
  });

  Future<void> storeRegistration({
    required Uint8List userId,
    required Uint8List keyId,
    required Uint8List clientDataJSON, // type?
    required Uint8List publicKey,
    required int publicKeyAlgorithm,
    required Uint8List attestationObject,
    required Uint8List authenticatorData,
  });

  // TODO: Challenge store could be the same, just with TTL parameter

  Future<void> storeLoginChallenge({
    required Uint8List id,
    required Uint8List challenge,
  });

  Future<Uint8List> getLoginChallenge({
    required Uint8List id,
  });

  Future<Uint8List> getPublicKey({
    required Uint8List keyId,
  });
}

class InMemoryPasskeyStorage implements PasskeyStorage {
  final _loginChallenges = <String, Uint8List>{};
  final _registrationChallenges = <String, Uint8List>{};
  final _keys = <String, (Uint8List key, int alg)>{};

  @override
  Future<void> storeLoginChallenge({
    required Uint8List id,
    required Uint8List challenge,
  }) async {
    _loginChallenges[base64Encode(id)] = challenge;
  }

  @override
  Future<Uint8List> getLoginChallenge({
    required Uint8List id,
  }) async {
    return _loginChallenges.remove(base64Encode(id))!;
  }

  @override
  Future<Uint8List> getPublicKey({required Uint8List keyId}) async {
    return _keys[base64Encode(keyId)]!.$1;
  }

  @override
  Future<Uint8List> receiveRegistrationChallenge({
    required Uint8List userId,
  }) async {
    return _registrationChallenges.remove(base64Encode(userId))!;
  }

  @override
  Future<void> storeRegistration({
    required Uint8List userId,
    required Uint8List keyId,
    required Uint8List clientDataJSON,
    required Uint8List publicKey,
    required int publicKeyAlgorithm,
    required Uint8List attestationObject,
    required Uint8List authenticatorData,
  }) async {
    _keys[base64Encode(keyId)] = (publicKey, publicKeyAlgorithm);
  }

  @override
  Future<void> storeRegistrationChallenge({
    required Uint8List userId,
    required Uint8List challenge,
  }) async {
    _registrationChallenges[base64Encode(userId)] = challenge;
  }
}
