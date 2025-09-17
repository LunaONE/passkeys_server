import 'dart:io';

import 'package:passkeys_server/passkeys_server.dart';
import 'package:relic/io_adapter.dart';
import 'package:relic/relic.dart';

final passkeys = Passkeys(
  config: PasskeysConfig(relyingPartyId: 'localhost'),
);

Future<void> startServer() async {
  // Setup router
  final router = Router<Handler>()..get('/', homepage);

  final handler = const Pipeline()
      .addMiddleware(logRequests())
      .addMiddleware(routeWith(router))
      .addHandler(fallback404);

  // Start the server with the handler
  final port = int.parse(Platform.environment['PORT'] ?? '8080');
  await serve(handler, InternetAddress.anyIPv4, port);

  // ignore: avoid_print
  print('Serving at http://localhost:$port');
}

ResponseContext homepage(NewContext ctx) {
  return ctx.respond(
    Response.ok(
      body: Body.fromString(
        File('./assets/index.html').readAsStringSync(),
        mimeType: MimeType.html,
      ),
    ),
  );
}

ResponseContext fallback404(NewContext ctx) {
  return ctx.respond(Response.notFound());
}
