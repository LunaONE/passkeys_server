// ignore_for_file: avoid_print

import 'dart:convert';
import 'dart:io';

import 'package:passkeys_server_relic_example/src/authenticator_data.dart';
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
    ..get('/assets/pico.min.css', _css)
    ..get('/', _landingPage);

  final handler = const Pipeline()
      .addMiddleware(logRequests())
      .addMiddleware(routeWith(router))
      .addHandler(fallback404);

  final port = int.parse(Platform.environment['PORT'] ?? '8080');
  await serve(handler, InternetAddress.anyIPv4, port);

  print('Serving at http://localhost:$port');
}

ResponseContext _healthCheck(RequestContext ctx) {
  return (ctx as RespondableContext).withResponse(Response.ok());
}

Future<ResponseContext> _adminListKeys(RequestContext ctx) async {
  final keys = await passkeys.listKeys();

  return (ctx as RespondableContext).withResponse(
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
    final authenticatorData = parseAuthenticatorData(this.authenticatorData);

    return <String, dynamic>{
      'keyId': keyId.toBase64Url(),
      'userId': userId.uuid,
      'createdAt': createdAt.toIso8601String(),
      // client data:        ${utf8.decode(key.clientDataJSON)}',
      // original challenge: ${key.originalChallenge.toBase64Url()}',
      'rpIdHash': authenticatorData.rpIdHashHex,
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

ResponseContext _landingPage(RequestContext ctx) {
  return (ctx as RespondableContext).withResponse(
    Response.ok(
      body: Body.fromString(
        File('./assets/index.html').readAsStringSync(),
        mimeType: MimeType.html,
      ),
    ),
  );
}

ResponseContext _css(RequestContext ctx) {
  return (ctx as RespondableContext).withResponse(
    Response.ok(
      body: Body.fromString(
        File('./assets/pico.min.css').readAsStringSync(),
        mimeType: MimeType.css,
      ),
    ),
  );
}

Future<ResponseContext> newUser(RequestContext ctx) async {
  final challenge = await passkeys.createChallenge(ChallengeKind.registration);

  return (ctx as RespondableContext).withResponse(
    Response.ok(
      body: Body.fromString(
        jsonEncode({
          'userId': base64Encode(challenge.challengeId),
          'challenge': base64Encode(challenge.challenge),
        }),
        mimeType: MimeType.json,
      ),
    ),
  );
}

Future<ResponseContext> registerPublicKey(RequestContext ctx) async {
  final UuidValue userId;
  try {
    final challengeid =
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

    print('final userId = "$challengeid";');
    print('final keyId = "$keyId";');
    print('final publicKey = "$publicKey";');
    print('final publicKeyAlgorithm = "$publicKeyAlgorithm";');
    print('final clientDataJSON = "$clientDataJSON";');
    print('final attestationObject  = "$attestationObject";');
    print('final authenticatorData = "$authenticatorData";');

    userId = await passkeys.completeRegistration(
      challengeId: challengeid,
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

  return (ctx as RespondableContext).withResponse(
    Response.ok(body: Body.fromString('Registered as user $userId')),
  );
  // Verifying that the challenge is the same as the challenge that was sent.
  // Ensuring that the origin was the origin expected.
  // Validating that the signature and attestation are using the correct certificate chain for the specific model of the authenticator used to generate the key pair in the first place.
}

Future<ResponseContext> loginWithKey(RequestContext ctx) async {
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

  return (ctx as RespondableContext).withResponse(
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

ResponseContext fallback404(RequestContext ctx) {
  return (ctx as RespondableContext).withResponse(Response.notFound());
}
