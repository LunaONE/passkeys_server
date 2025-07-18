import 'dart:convert';
import 'dart:typed_data';

// import 'package:asn1lib/asn1lib.dart';
import 'package:asn1lib/asn1lib.dart';
import 'package:cbor/cbor.dart';
import 'package:crypto/crypto.dart';
// import 'package:crypto_keys/crypto_keys.dart';
// import 'package:cryptography/cryptography.dart';
import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';
// import 'package:webcrypto/webcrypto.dart' as wc;

// https://developers.google.com/identity/passkeys/developer-guides/server-authentication#appendix_verification_of_the_authentication_response
// Check that the up (user present) flag in authenticatorData is true, since user presence is always required for passkeys.

void main() async {
  // final userId = '6f45eb8c-9e6e-41d4-84b7-5490f97dfdfa';
  // final keyId = 'NhShmVK70qYBm3_vtCOvKQ';
  // final publicKey =
  //     'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcdcCOQDXzQIBMzs2XUNMpX3YONfy0ActdBw1ZzsplT87A8hGCTXwKibVZLj4nOv1N6lAPkXUfv4yvZhxDomCdQ';
  // final publicKeyAlgorithm = '-7';
  // var clientDataJSON =
  //     'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiWlFiQjQwZkwzNnN2SG9ZMXRLbGVQb0JRUkJ2TXdnWE5JX2lTaUc2S1NCVSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZX0';
  // while (clientDataJSON.length % 4 != 0) {
  //   clientDataJSON += "=";
  // }

  // final challenge = 'ZQbB40fL36svHoY1tKlePoBQRBvMwgXNI/iSiG6KSBU=';
  final originalRpId = "localhost";

  // for registration
  // https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorAttestationResponse

  final userId = "6d8b443b-d1c6-4188-a6ee-2327abba31ed";
  final keyId = "smRGEPLBiguLVdDctsYGBQ";
  final publicKey =
      "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEkoCYhdhCvJfNoqD1pscWeiXJQF5G2RSeqDTE85g8nDv4rRfcgnxffuLLktXBqPm1Yx9X961Z74FLCwZ_oCuFMg";
  final publicKeyAlgorithm = "-7";
  final clientDataJSON =
      "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiMjhHSVZ1dUNTXzVERzBMQTF0TnItMDEtcVd6TWY4UGZ5QlpOUVB0dFhxWSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZX0";
  final attestationObject =
      "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViUSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NdAAAAAOqbjWZNAR0hPOS2tIy1ddQAELJkRhDywYoLi1XQ3LbGBgWlAQIDJiABIVggkoCYhdhCvJfNoqD1pscWeiXJQF5G2RSeqDTE85g8nDsiWCD4rRfcgnxffuLLktXBqPm1Yx9X961Z74FLCwZ_oCuFMg";
  final authenticatorData =
      "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NdAAAAAOqbjWZNAR0hPOS2tIy1ddQAELJkRhDywYoLi1XQ3LbGBgWlAQIDJiABIVggkoCYhdhCvJfNoqD1pscWeiXJQF5G2RSeqDTE85g8nDsiWCD4rRfcgnxffuLLktXBqPm1Yx9X961Z74FLCwZ_oCuFMg";
  final originalChallenge = "28GIVuuCS/5DG0LA1tNr+01+qWzMf8PfyBZNQPttXqY=";

  final clientData =
      jsonDecode(utf8.decode(base64Decode(padBase64(clientDataJSON)))) as Map;

  print(clientData);
  print(base64Decode(padBase64(clientData['challenge'])));
  print(base64Decode(originalChallenge));

  final authenticatorDataBytes = base64Decode(padBase64(authenticatorData));
  final attestationObjectBytes = base64Decode(padBase64(attestationObject));

  print('rp id check');
  print(sha256.convert(utf8.encode(originalRpId)).bytes);
  print(Uint8List.sublistView(authenticatorDataBytes, 0, 32));

  print(attestationObjectBytes);

  // get(key: 'fmt'): AttestationFormat;
  // get(key: 'attStmt'): AttestationStatement;
  // get(key: 'authData'): Uint8Array;
  final attestationObjectMap = cbor.decode(attestationObjectBytes) as CborMap;
  // print(attestationObjectMap);

  final attestationAuthData =
      attestationObjectMap[CborString('authData')] as CborBytes;
  print(attestationObjectMap);

  // print(cbor.decode(attestationAuthData.bytes));
  // print(authenticatorDataBytes);

  {
    // final base64Spki = publicKey;

    final spkiBytes = base64Decode(padBase64(publicKey));
    final asn1Parser = ASN1Parser(spkiBytes);
    final topLevelSeq = asn1Parser.nextObject() as ASN1Sequence;

    final pubKeyBitString = topLevelSeq.elements[1] as ASN1BitString;
    final pubKeyBytes = pubKeyBitString.valueBytes();

    print('pubKeyBytes');
    print(pubKeyBytes);

    if (pubKeyBytes[0] != 0 || pubKeyBytes[1] != 4) {
      throw Exception(
        'Only uncompressed EC points are supported, ${pubKeyBytes[0]}',
      );
    }

    // final xBytes = pubKeyBytes.sublist(1, 33);
    // final yBytes = pubKeyBytes.sublist(33, 65);

    // final coseKey = {
    //   1: 2, // kty: EC2
    //   3: -7, // alg: ES256
    //   -1: 1, // crv: P-256
    //   -2: xBytes,
    //   -3: yBytes,
    // };

    // print('COSE Key (decoded from SPKI):');
    // print({
    //   1: 2,
    //   3: -7,
    //   -1: 1,
    //   -2: base64Url.encode(xBytes),
    //   -3: base64Url.encode(yBytes),
    // });
  }

  // print(attestationObjectMap[CborString('authData')].runtimeType);
  // print(cbor.decode(attestationObjectBytes).toObject().runtimeType);

  {
    print('\n\nCLIENT');

    final loginChallenge = "tzDU2jDhlLCF3/hJSEFLZIi3M/xPf06twHtArTYQ5f8=";
    final loginKeyId = "smRGEPLBiguLVdDctsYGBQ";
    final authenticatorData =
        "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MdAAAAAA";
    final clientDataJSON =
        "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoidHpEVTJqRGhsTENGM19oSlNFRkxaSWkzTV94UGYwNnR3SHRBclRZUTVmOCIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZSwib3RoZXJfa2V5c19jYW5fYmVfYWRkZWRfaGVyZSI6ImRvIG5vdCBjb21wYXJlIGNsaWVudERhdGFKU09OIGFnYWluc3QgYSB0ZW1wbGF0ZS4gU2VlIGh0dHBzOi8vZ29vLmdsL3lhYlBleCJ9";
    final signature =
        "MEUCIQDtgwZM-M-ilKkHwfOouoVb2pMuKwhzpmXFqT2yE6BEEAIgOl_OFgvmSf2fSfVe4NhgG6J2yWSp9eb1MvNt2xcU-CY";
    final userHandle = "bYtEO9HGQYim7iMnq7ox7Q";

    print('publicKey');
    // print(base64Url.decode(padBase64(publicKey)));
    print((base64.decode(padBase64(publicKey))));
    print(cbor.decode(base64.decode(padBase64(publicKey))));

    final publicKeyBytes = base64.decode(padBase64(publicKey));
    print(publicKeyBytes);
    print(publicKeyBytes.lengthInBytes);

    // var publicKeyFromDer =
    //     EcPublicKey.parseDer(publicKeyBytes, type: KeyPairType.p256);
    // print(publicKeyFromDer);

    print(cborDecode(publicKeyBytes).tags);

    // x = -2,
    // y = -3,

    // {
    //   final signatureBytes = base64Decode(padBase64(signature));

    //   print(signatureBytes);
    //   print(signatureBytes.lengthInBytes);
    // }

    // // print((utf8.decode(attestationAuthData.bytes)));
    // return;

    final x = publicKeyBytes;

    final key = ECPublicKey.bytes(publicKeyBytes);
    // final key = ECPublicKey.raw(pc.ECPublicKey(
    //   pc1.ECCurve_prime256v1()
    //       .curve
    //       .decodePoint([0x02, ...base64.decode(padBase64(publicKey))]),
    //   pc1.ECCurve_prime256v1(),
    // ));
    // pc.ECPublicKey()

    print(jsonDecode(utf8.decode(base64Decode(padBase64(clientDataJSON)))));
    // print(cbor.decode(base64Decode(padBase64(signature))));
    print((base64Decode(padBase64(authenticatorData))));

    final signedData = Uint8List.fromList([
      ...base64Decode(padBase64(authenticatorData)),
      // ...sha256.convert(base64Decode(padBase64(clientDataJSON))).bytes,
      ...sha256.convert(base64Decode(padBase64(clientDataJSON))).bytes,
    ]);

    final signatureBytes = base64Decode(padBase64(signature));

    // {
    //   // var bytes = Uint8List.fromList(sdecoded);
    //   var p = ASN1Parser(publicKeyBytes);
    //   var seq = p.nextObject() as ASN1Sequence;
    //   var ar = seq.elements?[0] as ASN1Integer;
    //   var as = seq.elements?[1] as ASN1Integer;

    //   var r = ar.valueAsBigInteger!;
    //   var s = as.valueAsBigInteger!;

    //   print(r);
    //   print(s);

    //   return;

    //   // var ecSignature = ECSignature(r, s);
    // }

    // final res222 = await Ecdsa.p256(Sha256()).verify(
    //   signedData,
    //   signature: Signature(
    //     signatureBytes,
    //     publicKey: publicKeyFromDer,
    //   ),
    // );
    // print('res $res222');

    // return;

    // ECPublicKey.bytes(bytes)

    // Hash the concatenated data with SHA-256
// final signedDataHash = sha256.convert(signedData).bytes;
    // final bodySha256Bytes = Uint8List.fromList(sha256.convert(bodyBytes).bytes);

    // print(key.toJWK());
    // final checkRes = EcPublicKey(
    //   xCoordinate: key.key.parameters!.G.x!.toBigInteger()!,
    //   yCoordinate: key.key.parameters!.G.y!.toBigInteger()!,
    //   curve: curves.p256,
    // )
    //     .createVerifier(algorithms.signing.ecdsa.sha256)
    //     .verify(signedData, Signature(signatureBytes));

    // print('checkRes $checkRes');

    // final result = (await wc.EcdsaPublicKey.importRawKey(
    //         base64Decode(padBase64(publicKey)), wc.EllipticCurve.p256))
    //     .verifyBytes(
    //   signatureBytes,
    //   signedData,
    //   wc.Hash.sha256,
    // );
    // print('result $result ');

    // print(bodySha256Bytes);

    print('xxx');
    print(signatureBytes[4]);
    // signatureBytes[4] = 243;
    // signatureBytes[25] = 243;
    print(signatureBytes[4]);

    final valid = ECDSAAlgorithm('ES256').verify(
      key,
      signedData,
      // signatureBytes.sublist(0),
      derToRawSignature(signatureBytes),
    );

    print('is valid $valid');

    //     var ec = getP256();
    // // var priv = ec.generatePrivateKey();
    // var pub = PublicKey(curve, X, Y)
    // print(priv);
    // print(pub);
    // var hashHex =
    //     'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9';
    // var hash = List<int>.generate(hashHex.length ~/ 2,
    //     (i) => int.parse(hashHex.substring(i * 2, i * 2 + 2), radix: 16));
    // var sig = signature(priv, hash);

    // var result = verify(pub, hash, sig);

    // 3. Construct signed data: hash(authenticatorData + clientDataJSON)
// let signedData = new Uint8Array([...authenticatorData, ...clientDataJSON]);
// let signedDataHash = await crypto.subtle.digest('SHA-256', signedData);

// // 4. Verify the signature
// let isValid = await crypto.subtle.verify(
//   { name: "ECDSA", hash: "SHA-256" },
//   publicKey,
//   signature,
//   signedDataHash
// );
// if (!isValid) throw new Error("Verification failed!");
  }
}

// Uint8List derToRawSignature(Uint8List der) {
//   final asn1 = ASN1Parser(der);
//   final seq = asn1.nextObject() as ASN1Sequence;
//   final r = (seq.elements![0] as ASN1Integer).valueBytes();
//   final s = (seq.elements![1] as ASN1Integer).valueBytes();

//   // Pad r and s to 32 bytes if needed
//   final rPadded = Uint8List(32)..setRange(32 - r.length, 32, r);
//   final sPadded = Uint8List(32)..setRange(32 - s.length, 32, s);

//   return Uint8List.fromList([...rPadded, ...sPadded]);
// }

Uint8List derToRawSignature(Uint8List der) {
  final asn1 = ASN1Parser(der);
  final seq = asn1.nextObject() as ASN1Sequence;
  final r = (seq.elements[0] as ASN1Integer).valueBytes();
  final s = (seq.elements[1] as ASN1Integer).valueBytes();

  Uint8List padOrTrim(Uint8List v) {
    if (v.length == 32) return v;
    if (v.length > 32) return v.sublist(v.length - 32);
    final out = Uint8List(32);
    out.setRange(32 - v.length, 32, v);
    return out;
  }

  final rPadded = padOrTrim(r);
  final sPadded = padOrTrim(s);

  return Uint8List.fromList([...rPadded, ...sPadded]);
}

String padBase64(String s) {
  // Instead use: base64Url.decode(source)

  while (s.length % 4 != 0) {
    s += "=";
  }

  return s;
}

// Future<EcPublicKey> decodeCosePublicKey(Uint8List coseKey) async {
//   cborDecode(value)
//   final cbor = cbor.Cbor();
//   cbor.decodeFromBuffer(coseKey);
//   final decoded = cbor.getDecodedData();
//   final keyMap = decoded.first as Map;

//   final x = keyMap[-2] as Uint8List;
//   final y = keyMap[-3] as Uint8List;

//   return EcPublicKey(
//     x: x,
//     y: y,
//     curve: EllipticCurve.p256,
//   );
// }

// /// Verify Passkey signature
// Future<bool> verifyPasskeySignature({
//   required Uint8List authenticatorData,
//   required Uint8List clientDataJSON,
//   required Uint8List signature,
//   required Uint8List cosePublicKey,
// }) async {
//   final clientDataHash = sha256.convert(clientDataJSON).bytes;
//   final signedData = Uint8List.fromList(authenticatorData + clientDataHash);

//   final publicKey = await decodeCosePublicKey(cosePublicKey);
//   final algorithm = Ecdsa.p256(Sha256());

//   final signatureObj = Signature(
//     signature,
//     publicKey: publicKey,
//   );

//   return await algorithm.verify(
//     signedData,
//     signature: signatureObj,
//   );
// }
