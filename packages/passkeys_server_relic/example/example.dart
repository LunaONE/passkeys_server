// ignore_for_file: avoid_print

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:relic/io_adapter.dart';
import 'package:relic/relic.dart';
import 'package:uuid/uuid.dart';

import 'passkey_repository.dart';

final relyingPartyId = Platform.environment['RELYING_PARTY'] ?? 'localhost';

final storageRoot = Directory(
  Platform.environment['STORAGE_LOCATION'] ?? './.passkey_storage',
);

final passkeys = PasskeyRepository(
  relyingPartyId: relyingPartyId,
  storageRoot: storageRoot,
);

void main() async {
  print(
    'Configuration:\n'
    'relyingPartyId = $relyingPartyId\n'
    'Storage = ${storageRoot.absolute.uri.toFilePath()}',
  );

  final router = Router<Handler>()
    ..post('/api/new-user', newUser)
    ..post('/api/finish-registration', registerPublicKey)
    ..post('/api/login', loginWithKey)
    ..get('/healthz', _healthCheck)
    ..get('/admin/registered_keys', _adminListKeys)
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
  return (ctx as RespondableContext).withResponse(
    Response.ok(
      body: Body.fromString(
        [
          'Keys:',
          for (final key in await passkeys.listKeys()) ...[
            '  - key ID:             ${key.keyId.toBase64Url()}',
            '    user ID:            ${key.userId}',
            '    created at:         ${key.createdAt.toIso8601String()}',
            '    client data:        ${utf8.decode(key.clientDataJSON)}',
            '    original challenge: ${key.originalChallenge.toBase64Url()}',
            // '    attestation object: ${key.attestationObject}',
            '    authenticator data: ${parseAuthenticatorData(key.authenticatorData)} (${key.authenticatorData.lengthInBytes}B)',
          ],
        ].join('\n'),
      ),
    ),
  );
}

/// https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API/Authenticator_data
String parseAuthenticatorData(Uint8List authenticatorData) {
  final rpIdHash = Uint8List.sublistView(authenticatorData, 0, 32);
  final flag = authenticatorData[32];

  return [
    'rpIdHash: ${rpIdHash.map((e) => e.toRadixString(16).padLeft(2, '0')).join()}',
    'UP ${hasBitSet(flag, 0)}',
    'UV ${hasBitSet(flag, 2)}',
    'BE ${hasBitSet(flag, 3)}',
    'BS ${hasBitSet(flag, 4)}',
  ].join(', ');
}

bool hasBitSet(int value, int index) {
  return (value & (1 << index)) != 0;
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
    userId = await passkeys.login(
      loginId: base64Decode(
        padBase64(ctx.request.requestedUri.queryParameters['loginId']!),
      ),
      keyId: base64Decode(
        padBase64(ctx.request.requestedUri.queryParameters['keyId']!),
      ),
      authenticatorData: base64Decode(
        padBase64(
          ctx.request.requestedUri.queryParameters['authenticatorData']!,
        ),
      ),
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
