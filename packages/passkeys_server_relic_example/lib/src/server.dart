// ignore_for_file: avoid_print

import 'dart:convert';
import 'dart:io';

import 'package:passkeys_server/passkeys_server.dart';
import 'package:passkeys_server_relic_example/src/keyfile.dart';
import 'package:passkeys_server_relic_example/src/passkey_repository.dart';
import 'package:relic/io_adapter.dart';
import 'package:relic/relic.dart';
import 'package:uuid/uuid.dart';

late final PasskeyRepository passkeys;

Future<void> startServer({
  required String relyingPartyId,
  required Directory storageRoot,
}) async {
  print(
    'Configuration:\n'
    'relyingPartyId = $relyingPartyId\n'
    'Storage = ${storageRoot.absolute.uri.toFilePath()}',
  );

  passkeys = PasskeyRepository(
    relyingPartyId: relyingPartyId,
    storageRoot: storageRoot,
  );

  final router = Router<Handler>()
    ..post('/api/new-user', newUser)
    ..post('/api/finish-registration', registerPublicKey)
    ..post('/api/login', loginWithKey)
    // Admin API
    ..get('/api/admin/keys', _adminListKeys)
    ..get('/healthz', _healthCheck)

    // Static files
    ..get(
      '/assets/**',
      createStaticHandler(
        './assets/public/',
        cacheControl: (_, __) => null,
      ),
    )
    ..get(
      '/flutter/**',
      createStaticHandler(
        './assets/flutter/',
        cacheControl: (_, __) => null,
      ),
    )
    ..anyOf({Method.get, Method.head}, '/', _landingPage);

  final handler = const Pipeline()
      .addMiddleware(logRequests())
      .addMiddleware(routeWith(router))
      .addHandler(fallback404);

  final port = int.parse(Platform.environment['PORT'] ?? '8080');
  await serve(handler, InternetAddress.anyIPv4, port);

  print('Serving at http://localhost:$port');
}

ResponseContext _healthCheck(NewContext ctx) {
  return ctx.respond(Response.ok());
}

Future<ResponseContext> _adminListKeys(NewContext ctx) async {
  final keys = await passkeys.listKeys();

  return ctx.respond(
    Response.ok(
      body: Body.fromString(
        jsonEncode({
          'keys': [
            for (final key in keys) key.toJson(),
          ],
        }),
        mimeType: MimeType.json,
      ),
    ),
  );
}

extension on Keyfile {
  Map<String, dynamic> toJson() {
    final (authenticatorData,) = parseAttestationObject(attestationObject);

    return <String, dynamic>{
      'keyId': keyId.toBase64Url(),
      'userId': userId.uuid,
      'createdAt': createdAt.toIso8601String(),
      'algorithm': authenticatorData.alg,
      // client data:        ${utf8.decode(key.clientDataJSON)}',
      // original challenge: ${key.originalChallenge.toBase64Url()}',
      'rpIdHash': authenticatorData.rpIdHash
          .map((e) => e.toRadixString(16).padLeft(2, '0'))
          .join(),
      'aaGuid': authenticatorData.aaGuid?.uuid,
      'authenticator': getAuthenticator(authenticatorData.aaGuid),
      'signCount': authenticatorData.signCount,
      'UP': authenticatorData.userPresence,
      'UV': authenticatorData.userVerification,
      'BE': authenticatorData.backupEligbility,
      'BS': authenticatorData.backupState,
    };
  }
}

final authenticatorInfo =
    jsonDecode(File('./assets/aaguid.json').readAsStringSync()) as Map;

String? getAuthenticator(UuidValue? aaGuid) {
  final entry = authenticatorInfo[aaGuid?.uuid];

  if (entry is Map) {
    if (entry['name'] case final String name) {
      return name;
    }
  }

  return null;
}

final _landingPage = createFileHandler(
  './assets/index.html',
  cacheControl: (_, __) => null,
);

Future<ResponseContext> newUser(NewContext ctx) async {
  final challenge = await passkeys.createChallenge(ChallengeKind.registration);

  return ctx.respond(
    Response.ok(
      body: Body.fromString(
        jsonEncode({
          'userId': base64Url.encode(challenge.challengeId),
          'challenge': base64Url.encode(challenge.challenge),
        }),
        mimeType: MimeType.json,
      ),
    ),
  );
}

Future<ResponseContext> registerPublicKey(NewContext ctx) async {
  final UuidValue userId;
  try {
    final challengeid = base64Decode(
      padBase64(ctx.request.requestedUri.queryParameters['userId']!),
    );

    final keyId = ctx.request.requestedUri.queryParameters['keyId']!;
    final clientDataJSON =
        ctx.request.requestedUri.queryParameters['clientDataJSON']!;
    final attestationObject =
        ctx.request.requestedUri.queryParameters['attestationObject']!;

    print('final userId = "$challengeid";');
    print('final keyId = "$keyId";');
    print('final clientDataJSON = "$clientDataJSON";');
    print('final attestationObject  = "$attestationObject";');

    userId = await passkeys.completeRegistration(
      challengeId: challengeid,
      keyId: base64Decode(padBase64(keyId)),
      clientDataJSON: base64Decode(padBase64(clientDataJSON)),
      attestationObject: base64Decode(padBase64(attestationObject)),
    );
  } catch (e, s) {
    print(e);
    print(s);

    rethrow;
  }

  return ctx.respond(
    Response.ok(body: Body.fromString('Registered as user $userId')),
  );
  // Verifying that the challenge is the same as the challenge that was sent.
  // Ensuring that the origin was the origin expected.
  // Validating that the signature and attestation are using the correct certificate chain for the specific model of the authenticator used to generate the key pair in the first place.
}

Future<ResponseContext> loginWithKey(NewContext ctx) async {
  final UuidValue userId;
  try {
    final authenticatorData = base64Decode(
      padBase64(
        ctx.request.requestedUri.queryParameters['authenticatorData']!,
      ),
    );

    userId = await passkeys.login(
      loginId: base64Decode(
        padBase64(ctx.request.requestedUri.queryParameters['loginId']!),
      ),
      keyId: base64Decode(
        padBase64(ctx.request.requestedUri.queryParameters['keyId']!),
      ),
      authenticatorData: authenticatorData,
      clientDataJSON: base64Decode(
        padBase64(
          ctx.request.requestedUri.queryParameters['clientDataJSON']!,
        ),
      ),
      signature: base64Decode(
        padBase64(ctx.request.requestedUri.queryParameters['signature']!),
      ),
      // userHandle: base64Decode(padBase64(ctx.request.requestedUri.queryParameters['userHandle']!)),
    );
  } catch (e, s) {
    print(e);
    print(s);

    rethrow;
  }

  return ctx.respond(
    Response.ok(body: Body.fromString('Logged in as user $userId')),
  );
}

String padBase64(String s) {
  // Instead use: base64Url.decode(source)

  final buf = StringBuffer(s);

  // Use `print('x' * 4);` pattern…
  while (buf.length % 4 != 0) {
    buf.write('=');
  }

  return buf.toString();
}

ResponseContext fallback404(NewContext ctx) {
  return ctx.respond(Response.notFound());
}
