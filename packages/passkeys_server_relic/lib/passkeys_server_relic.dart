import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:relic/io_adapter.dart';
import 'package:relic/relic.dart';
import 'package:uuid/uuid.dart';

final pendingRegistrations = <UuidValue, Uint8List>{};

Future<void> startServer() async {
  // Setup router
  final router = Router<Handler>()
    ..post('/api/new-user', newUser)
    ..post('/api/finish-registration', registerPublicKey)

    // // Health check path for render.com
    // ..get('/healthz', healthCheck)
    ..get('/', homepage);

  final handler = const Pipeline()
      .addMiddleware(logRequests())
      .addMiddleware(routeWith(router))
      .addHandler(fallback404);

  // Start the server with the handler
  final port = int.parse(Platform.environment['PORT'] ?? '8080');
  await serve(handler, InternetAddress.anyIPv4, port);

  print('Serving at http://localhost:$port');
}

ResponseContext newUser(final RequestContext ctx) {
  final userId = Uuid().v4obj();
  final challenge = Uint8ListUtil.random(32);

  pendingRegistrations[userId] = challenge;

  return (ctx as RespondableContext).withResponse(
    Response.ok(
      body: Body.fromString(
        jsonEncode({
          'userId': base64Encode(userId.toBytes()),
          'challenge': base64Encode(challenge),
        }),
        mimeType: MimeType.json,
      ),
    ),
  );
}

ResponseContext registerPublicKey(final RequestContext ctx) {
  try {
    final userId = UuidValue.fromByteList(
      base64Decode(ctx.request.requestedUri.queryParameters['userId']!),
    );

    final keyId = ctx.request.requestedUri.queryParameters['keyId']!;
    final publicKey = ctx.request.requestedUri.queryParameters['publicKey']!;
    final publicKeyAlgorithm =
        ctx.request.requestedUri.queryParameters['publicKeyAlgorithm']!;
    final clientDataJSON =
        ctx.request.requestedUri.queryParameters['clientDataJSON']!;
    final attestationObject =
        ctx.request.requestedUri.queryParameters['attestationObject']!;
    final authenticatorData =
        ctx.request.requestedUri.queryParameters['authenticatorData']!;

    print('final userId = "$userId";');
    print('final keyId = "$keyId";');
    print('final publicKey = "$publicKey";');
    print('final publicKeyAlgorithm = "$publicKeyAlgorithm";');
    print('final clientDataJSON = "$clientDataJSON";');
    print('final attestationObject  = "$attestationObject";');
    print('final authenticatorData = "$authenticatorData";');
    print(
      'final originalChallenge = "${base64Encode(pendingRegistrations[userId]!)}";',
    );
  } catch (e, s) {
    print(e);
    print(s);

    rethrow;
  }

  return (ctx as RespondableContext).withResponse(Response.ok());
  // Verifying that the challenge is the same as the challenge that was sent.
  // Ensuring that the origin was the origin expected.
  // Validating that the signature and attestation are using the correct certificate chain for the specific model of the authenticator used to generate the key pair in the first place.
}

ResponseContext homepage(final RequestContext ctx) {
  return (ctx as RespondableContext).withResponse(
    Response.ok(
      body: Body.fromString(
        File('./assets/index.html').readAsStringSync(),
        mimeType: MimeType.html,
      ),
    ),
  );
}

ResponseContext fallback404(final RequestContext ctx) {
  return (ctx as RespondableContext).withResponse(Response.notFound());
}

final Random _rng = Random.secure();

extension Uint8ListUtil on Uint8List {
  static Uint8List random(int length) {
    return Uint8List.fromList(
      List<int>.generate(length, (i) => _rng.nextInt(256)),
    );
  }
}
