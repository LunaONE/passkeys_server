import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:passkeys_server/passkeys_server.dart';
import 'package:uuid/uuid.dart';

import 'keyfile.dart';

class PasskeyRepository {
  PasskeyRepository({
    required String relyingPartyId,
    required Directory storageRoot,
  })  : _passkeys = Passkeys(
          config: PasskeysConfig(
            relyingPartyId: relyingPartyId,
          ),
        ),
        // _challengesDir = Directory.fromUri(
        //   storageRoot.uri.resolve('./challenges'),
        // ),
        _publicKeysDir = Directory.fromUri(
          storageRoot.uri.resolve('./public_keys'),
        ) {
    for (final dir in [_publicKeysDir]) {
      if (dir.existsSync()) {
        dir.createSync(recursive: true);
      }
    }
  }

  final Passkeys _passkeys;

  // final Directory _challengesDir;

  final Directory _publicKeysDir;

  final _activeChallenges = <UuidValue,
      ({
    Uint8List challenge,
    ChallengeKind kind,
    DateTime createdAt,
  })>{};

  Future<
      ({
        Uint8List challengeId,
        Uint8List challenge,
      })> createChallenge(ChallengeKind kind) async {
    final challengeId = const Uuid().v7obj();
    final challenge = await _passkeys.createChallenge();

    _activeChallenges[challengeId] = (
      challenge: challenge,
      kind: kind,
      createdAt: DateTime.now(),
    );

    return (
      challengeId: challengeId.toBytes(),
      challenge: challenge,
    );
  }

  Future<UuidValue> completeRegistration({
    required Uint8List challengeId,
    required Uint8List keyId,
    required Uint8List clientDataJSON,
    required Uint8List publicKey,
    required int publicKeyAlgorithm,
    required Uint8List attestationObject,
    required Uint8List authenticatorData,
  }) async {
    final challengeData =
        _activeChallenges[UuidValue.fromByteList(challengeId)];

    if (challengeData == null ||
        challengeData.createdAt
            .isBefore(DateTime.now().subtract(const Duration(minutes: 5)))) {
      throw 'Challenge not found';
    }

    if (challengeData.kind != ChallengeKind.registration) {
      throw 'wrong challenge kind';
    }

    await _passkeys.verifyRegistration(
      // userId: challengeId,
      // keyId: keyId,
      // clientDataJSON: clientDataJSON,
      // publicKey: publicKey,
      // publicKeyAlgorithm: publicKeyAlgorithm,
      // attestationObject: attestationObject,
      authenticatorData: authenticatorData,
      // challenge: challengeData.challenge,
    );

    final userId = Uuid().v4obj();

    final keyFile = Keyfile(
      keyId: keyId,
      clientDataJSON: clientDataJSON,
      publicKey: publicKey,
      publicKeyAlgorithm: publicKeyAlgorithm,
      attestationObject: attestationObject,
      authenticatorData: authenticatorData,
      userId: userId,
      originalChallenge: challengeData.challenge,
      createdAt: DateTime.now(),
    );

    await keyFile.write(_publicKeysDir);

    return userId;
  }

  Future<UuidValue> login({
    required Uint8List loginId,
    required Uint8List keyId,
    required Uint8List authenticatorData,
    required Uint8List clientDataJSON,
    required Uint8List signature,
  }) async {
    final keyFile = await Keyfile.read(_publicKeysDir, keyId);

    final challengeData = _activeChallenges[UuidValue.fromByteList(loginId)];

    if (challengeData == null ||
        challengeData.createdAt
            .isBefore(DateTime.now().subtract(const Duration(minutes: 5)))) {
      throw 'Challenge not found';
    }

    // if (challengeData.kind != ChallengeKind.registration) {
    //   throw 'wrong challenge kind';
    // }

    print('found key');

    await _passkeys.verifyLogin(
      loginId: loginId,
      key: (
        algorithm: keyFile.publicKeyAlgorithm,
        publicKey: keyFile.publicKey
      ),
      authenticatorData: authenticatorData,
      clientDataJSON: clientDataJSON,
      signature: signature,
      challenge: challengeData.challenge,
    );

    return keyFile.userId;
  }

  /// Link a new
  Future<void> link() async {
    throw UnimplementedError();
  }

  Future<List<Keyfile>> listKeys() async {
    final keys = <Keyfile>[];

    for (final file in _publicKeysDir.listSync()) {
      print(file);
      if (file is File) {
        final keyFile = await Keyfile.readFile(file);

        // final userId = UuidValue.fromList(
        //     (keyFileContent[CborString('userId')]! as CborBytes).bytes);

        keys.add(keyFile);
      }
    }

    return keys;
  }
}

enum ChallengeKind {
  registration,
  login,
}

extension X on Uint8List {
  String toBase64Url() {
    return base64UrlEncode(this);
  }
}
