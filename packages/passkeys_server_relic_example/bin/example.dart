import 'dart:io';

import 'package:passkeys_server_relic_example/src/server.dart';

final relyingPartyId = Platform.environment['RELYING_PARTY'] ?? 'localhost';

final storageRoot = Directory(
  Platform.environment['STORAGE_LOCATION'] ?? './.passkey_storage',
);

Future<void> main() async {
  await startServer(
    relyingPartyId: relyingPartyId,
    storageRoot: storageRoot,
  );
}
