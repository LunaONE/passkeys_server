import 'package:passkeys_server_relic/passkeys_server_relic.dart'
    as passkeys_server_relic;

void main(List<String> arguments) async {
  await passkeys_server_relic.startServer();
}
