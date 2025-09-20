import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:passkeys/authenticator.dart';
import 'package:passkeys/types.dart';
import 'package:web/web.dart' as web;

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Flutter Passkey Server Demo',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.pinkAccent),
        useMaterial3: true,
      ),
      home: const MyHomePage(title: 'Flutter Passkey Server Demo'),
    );
  }
}

class MyHomePage extends StatefulWidget {
  const MyHomePage({super.key, required this.title});

  final String title;

  @override
  State<MyHomePage> createState() => _MyHomePageState();
}

class _MyHomePageState extends State<MyHomePage> {
  final _nameController = TextEditingController(
    text: DateTime.now().toIso8601String().substring(0, 19),
  );

  Future<void> _register() async {
    final passkeyAuthenticator = PasskeyAuthenticator();
    final relyingPartyServer = RelyingPartyServer();

    final webAuthnChallenge = await relyingPartyServer.prepareRegistration(
      keyname: _nameController.text,
    );

    final platformRes = await passkeyAuthenticator.register(webAuthnChallenge);

    await relyingPartyServer.finishSignUpWithPasskey(platformRes,
        userId: webAuthnChallenge.user.id);
  }

  Future<void> _signIn() async {
    final passkeyAuthenticator = PasskeyAuthenticator();
    final relyingPartyServer = RelyingPartyServer();

    final (webAuthnChallenge, userId) = await relyingPartyServer.prepareLogin();

    final platformRes = await passkeyAuthenticator.authenticate(
      webAuthnChallenge,
    );

    final result = await relyingPartyServer.finishLoginWithPasskey(
      platformRes,
      userId: userId,
    );

    // ignore: use_build_context_synchronously
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(result)));
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
        title: Text(widget.title),
      ),
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: <Widget>[
            ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 200),
              child: TextField(
                controller: _nameController,
              ),
            ),
            const SizedBox(height: 10),
            OutlinedButton(
              onPressed: () => _register(),
              child: const Text('Register new Passkey'),
            ),
            const SizedBox(height: 10),
            OutlinedButton(
              onPressed: () => _signIn(),
              child: const Text('Sign in with existing Passkey'),
            ),
          ],
        ),
      ),
    );
  }
}

class RelyingPartyServer {
  String get _hostname => web.window.location.hostname;

  Future<RegisterRequestType> prepareRegistration({
    required String keyname,
  }) async {
    final response = await http.post(Uri.parse('/api/new-user'));

    final responseMap = jsonDecode(response.body) as Map;

    return RegisterRequestType(
      challenge: (responseMap["challenge"] as String).replaceAll('=', ''),
      relyingParty: RelyingPartyType(
        name: _hostname,
        id: _hostname,
      ),
      user: UserType(
        displayName: keyname,
        name: keyname,
        id: (responseMap['userId'] as String).replaceAll('=', ''),
      ),
      authSelectionType: AuthenticatorSelectionType(
          requireResidentKey: false, residentKey: '', userVerification: ''),
      excludeCredentials: [],
      pubKeyCredParams: [
        PubKeyCredParamType(alg: -257, type: 'public-key'),
        PubKeyCredParamType(alg: -7, type: 'public-key'),
      ],
      attestation: 'direct',
    );
  }

  Future<
      (
        AuthenticateRequestType,
        String userId,
      )> prepareLogin() async {
    final response = await http.post(Uri.parse('/api/new-user'));

    final responseMap = jsonDecode(response.body) as Map;

    return (
      AuthenticateRequestType(
        relyingPartyId: _hostname,
        challenge: (responseMap["challenge"] as String).replaceAll('=', ''),
        mediation: MediationType.Required,
        preferImmediatelyAvailableCredentials: false,
      ),
      (responseMap['userId'] as String).replaceAll('=', ''),
    );
  }

  Future<void> finishSignUpWithPasskey(
    RegisterResponseType platformRes, {
    required String userId,
  }) async {
    final registrationCall = Uri(
      path: '/api/finish-registration',
      queryParameters: {
        "userId": userId,
        "keyId": platformRes.id,
        "clientDataJSON": platformRes.clientDataJSON,
        "attestationObject": platformRes.attestationObject,
      },
    );

    await http.post(registrationCall);
  }

  Future<String> finishLoginWithPasskey(
    AuthenticateResponseType platformRes, {
    required String userId,
  }) async {
    final registrationCall = Uri(
      path: '/api/login',
      queryParameters: {
        "loginId": userId,
        "keyId": platformRes.id,
        "clientDataJSON": platformRes.clientDataJSON,
        "authenticatorData": platformRes.authenticatorData,
        "signature": platformRes.signature,
      },
    );

    final response = await http.post(registrationCall);

    return response.body;
  }
}
