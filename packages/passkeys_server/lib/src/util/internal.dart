import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';

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
