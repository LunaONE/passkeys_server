For a complete example showing how to set up a server to handle passkey-based registrations and logins see package [passkeys_server_relic](https://pub.dev/packages/passkeys_server_relic).

The below examples show the basic usage, which would need to be integrated into your server-side API handlers and account system.

## Create the `Passkeys` instance with the desired configuration

```dart
final passkeys = Passkeys(
  config: PasskeysConfig(
    relyingPartyId: 'example.com',
  ),
);
```

## Creating a challenge

Every client interaction works with a server-generated challenge. Use the following code to generate a new challenge for a client, then store it (temporarily) on the server, so it can be retrieved later to check that the incoming request shows that the client correctly solved the assigned challenge.

```dart
final challenge = await passkeys.createChallenge();

// Now store the `challenge` (`Uint8List`) for later retrieval and return it to the client
```

## Verifying a registration

After a registration, the client will send `keyId`, `attestationObject`, and `clientDataJSON` parameters. Additionally you should round-trip an identifier for the challenge assigned to the client.

```dart
// your code to retrieve the previously generated challenge
// the challenge should be deleted / marked as used now, so that it can not be used again
final originalChallenge = getChallenge(challengeId);

await passkeys.verifyRegistration(
  keyId: keyId,
  attestationObject: attestationObject,
  clientDataJSON: clientDataJSON,
  challenge: originalChallenge,
);

// If the above method does not throw, the registration data is coherent and the
// code can proceed (e.g. creating a new user or assigning this Passkey to the
// currently logged-in one).
// For a later look-up upon login, the `attestationObject` and `clientDataJSON`
// should be stored using the `keyId` as the primary key.
```

## Verifying a login

When handling an incoming login, both the challenge (assigned to that specific login) and initial registration data (containing the public key) need to be retrieved.

```dart
final loginChallenge = getChallenge(challengeId); // your code, like above

// Pseudo helper which looks up the user ID and registration data
// (incl. the public key) based on the `keyId` parameter.
final (userId, registrationAttestationObject) = findRegistration(keyId)

await _passkeys.verifyLogin(
  registrationAttestationObject: registrationAttestationObject,
  // The next 3 arguments are just forwarded from the incoming request
  authenticatorData: authenticatorData,
  clientDataJSON: clientDataJSON,
  signature: signature,
  challenge: loginChallenge,
);

// If the above method does not throw, the challenge was correctly solved by
// the client and you can now consider them logged-in.
```
