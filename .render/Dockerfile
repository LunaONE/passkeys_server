FROM dart:3.9.0 AS build

WORKDIR /app
COPY . .
WORKDIR /app/packages/passkeys_server_relic_example

RUN dart pub get --enforce-lockfile
RUN dart compile exe bin/example.dart -o server

FROM ghcr.io/cirruslabs/flutter:3.35.2 AS flutter-build

WORKDIR /app
COPY . .
WORKDIR /app/passkeys_server_flutter_example

RUN flutter pub get --enforce-lockfile
RUN flutter build web --base-href="/flutter/" --source-maps --debug

# Build minimal serving image from AOT-compiled `/server` and required system
# libraries and configuration files stored in `/runtime/` from the build stage.
FROM scratch
COPY --from=build /runtime/ /
COPY --from=build /app/packages/passkeys_server_relic_example/server /app/bin/
COPY --from=build /app/packages/passkeys_server_relic_example/assets /app/bin/assets/
COPY --from=flutter-build /app/passkeys_server_flutter_example/build/web /app/bin/assets/flutter/

# Start server.
EXPOSE 10000
WORKDIR /app/bin/
CMD ["/app/bin/server"]