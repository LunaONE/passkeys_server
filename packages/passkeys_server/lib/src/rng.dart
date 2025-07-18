import 'dart:math';
import 'dart:typed_data';

final Random _rng = Random.secure();

extension Uint8ListUtil on Uint8List {
  static Uint8List random(int length) {
    return Uint8List.fromList(
      List<int>.generate(length, (i) => _rng.nextInt(256)),
    );
  }
}
