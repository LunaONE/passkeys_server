import 'dart:convert';
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import 'package:cbor/cbor.dart';
import 'package:crypto/crypto.dart';
import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';

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

    final key = ECPublicKey.bytes(publicKeyBytes);

    print(jsonDecode(utf8.decode(base64Decode(padBase64(clientDataJSON)))));
    // print(cbor.decode(base64Decode(padBase64(signature))));
    print((base64Decode(padBase64(authenticatorData))));

    final signedData = Uint8List.fromList([
      ...base64Decode(padBase64(authenticatorData)),
      // ...sha256.convert(base64Decode(padBase64(clientDataJSON))).bytes,
      ...sha256.convert(base64Decode(padBase64(clientDataJSON))).bytes,
    ]);

    final signatureBytes = base64Decode(padBase64(signature));

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
  }
}

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
