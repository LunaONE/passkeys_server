import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cbor/cbor.dart';
import 'package:uuid/uuid.dart';

class Keyfile {
  Keyfile({
    required this.keyId,
    required this.clientDataJSON,
    required this.publicKey,
    required this.publicKeyAlgorithm,
    required this.attestationObject,
    required this.authenticatorData,
    required this.userId,
    required this.originalChallenge,
    required this.createdAt,
  });

  Future<void> write(Directory dir) async {
    final keyFile = dir.keyFile(keyId);

    if (keyFile.existsSync()) {
      throw Exception('File for key already exists.');
    }

    final encoded = cbor.encode(
      CborMap({
        CborString(_clientDataJSONKey): CborBytes(clientDataJSON),
        CborString(_publicKeyKey): CborBytes(publicKey),
        CborString(_publicKeyAlgorithmKey):
            CborInt(BigInt.from(publicKeyAlgorithm)),
        CborString(_attestationObjectKey): CborBytes(attestationObject),
        CborString(_authenticatorDataKey): CborBytes(authenticatorData),
        CborString(_userIdKey): CborBytes(userId.toBytes()),
        CborString(_originalChallengeKey): CborBytes(originalChallenge),
        CborString(_createdAtKey):
            CborInt(BigInt.from(createdAt.millisecondsSinceEpoch)),
      }),
    );

    await keyFile.create(recursive: true);
    await keyFile.writeAsBytes(encoded);
  }

  static Future<Keyfile> read(Directory dir, Uint8List keyId) async {
    final keyFile = dir.keyFile(keyId);

    return readFile(keyFile);
  }

  static Future<Keyfile> readFile(File keyFile) async {
    if (!keyFile.existsSync()) {
      throw Exception('File for key does not exist.');
    }

    final keyId = base64Url.decode(keyFile.uri.pathSegments.last);

    final keyFileContent = cbor.decode(keyFile.readAsBytesSync()) as CborMap;

    final publicKeyAlgorithm =
        (keyFileContent[CborString(_publicKeyAlgorithmKey)]! as CborInt)
            .toInt();

    final publicKey = Uint8List.fromList(
      (keyFileContent[CborString(_publicKeyKey)]! as CborBytes).bytes,
    );

    final clientDataJSON = Uint8List.fromList(
      (keyFileContent[CborString(_clientDataJSONKey)]! as CborBytes).bytes,
    );

    final attestationObject = Uint8List.fromList(
      (keyFileContent[CborString(_attestationObjectKey)]! as CborBytes).bytes,
    );

    final authenticatorData = Uint8List.fromList(
      (keyFileContent[CborString(_authenticatorDataKey)]! as CborBytes).bytes,
    );

    final userId = UuidValue.fromList(
      (keyFileContent[CborString(_userIdKey)]! as CborBytes).bytes,
    );

    final originalChallenge = Uint8List.fromList(
      (keyFileContent[CborString(_originalChallengeKey)]! as CborBytes).bytes,
    );

    final createdAt = DateTime.fromMillisecondsSinceEpoch(
      (keyFileContent[CborString(_createdAtKey)]! as CborInt).toInt(),
    );

    return Keyfile(
      keyId: keyId,
      clientDataJSON: clientDataJSON,
      publicKey: publicKey,
      publicKeyAlgorithm: publicKeyAlgorithm,
      attestationObject: attestationObject,
      authenticatorData: authenticatorData,
      userId: userId,
      originalChallenge: originalChallenge,
      createdAt: createdAt,
    );
  }

  final Uint8List keyId;

  final Uint8List clientDataJSON;

  final Uint8List publicKey;

  final int publicKeyAlgorithm;

  final Uint8List attestationObject;

  final Uint8List authenticatorData;

  final UuidValue userId;

  final Uint8List originalChallenge;

  final DateTime createdAt;

  static const _clientDataJSONKey = 'clientDataJSON';
  static const _publicKeyKey = 'publicKey';
  static const _publicKeyAlgorithmKey = 'publicKeyAlgorithm';
  static const _attestationObjectKey = 'attestationObject';
  static const _authenticatorDataKey = 'authenticatorData';
  static const _userIdKey = 'userId';
  static const _originalChallengeKey = 'originalChallenge';
  static const _createdAtKey = 'createdAt';
}

extension on Directory {
  File keyFile(Uint8List keyId) {
    return File.fromUri(uri.resolve('./${base64Url.encode(keyId)}'));
  }
}
