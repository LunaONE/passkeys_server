import 'dart:convert';
import 'dart:io';

import 'package:passkeys_server/passkeys_server.dart';
import 'package:relic/io_adapter.dart';
import 'package:relic/relic.dart';

final passkeys = Passkeys(
  config: PasskeysConfig(relyingPartyId: 'localhost'),
  storage: InMemoryPasskeyStorage(),
);

Future<void> startServer() async {
  // Setup router
  final router = Router<Handler>()
    ..post('/api/new-user', newUser)
    ..post('/api/finish-registration', registerPublicKey)
    ..post('/api/login', loginWithKey)

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

Future<ResponseContext> newUser(final RequestContext ctx) async {
  final d = await passkeys.createRegistrationChallenge();

  return (ctx as RespondableContext).withResponse(
    Response.ok(
      body: Body.fromString(
        jsonEncode({
          'userId': base64Encode(d.userId),
          'challenge': base64Encode(d.challenge),
        }),
        mimeType: MimeType.json,
      ),
    ),
  );
}

Future<ResponseContext> registerPublicKey(final RequestContext ctx) async {
  try {
    final userId =
        base64Decode(ctx.request.requestedUri.queryParameters['userId']!);

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

    await passkeys.verifyRegistration(
      userId: userId,
      keyId: base64Decode(padBase64(keyId)),
      clientDataJSON: base64Decode(padBase64(clientDataJSON)),
      publicKey: base64Decode(padBase64(publicKey)),
      publicKeyAlgorithm: int.parse(publicKeyAlgorithm),
      attestationObject: base64Decode(padBase64(attestationObject)),
      authenticatorData: base64Decode(padBase64(authenticatorData)),
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

Future<ResponseContext> loginWithKey(final RequestContext ctx) async {
  try {
    await passkeys.verifyLogin(
      loginId: base64Decode(
          padBase64(ctx.request.requestedUri.queryParameters['loginId']!)),
      keyId: base64Decode(
          padBase64(ctx.request.requestedUri.queryParameters['keyId']!)),
      authenticatorData: base64Decode(padBase64(
          ctx.request.requestedUri.queryParameters['authenticatorData']!)),
      clientDataJSON: base64Decode(padBase64(
          ctx.request.requestedUri.queryParameters['clientDataJSON']!)),
      signature: base64Decode(
          padBase64(ctx.request.requestedUri.queryParameters['signature']!)),
      // userHandle: base64Decode(padBase64(ctx.request.requestedUri.queryParameters['userHandle']!)),
    );
  } catch (e, s) {
    print(e);
    print(s);

    rethrow;
  }

  return (ctx as RespondableContext).withResponse(Response.ok());
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

String padBase64(String s) {
  // Instead use: base64Url.decode(source)

  while (s.length % 4 != 0) {
    s += "=";
  }

  return s;
}
