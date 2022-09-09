# Fake OpenID Connect Authorization Server

(c) 2020 Martin Kuba, CESNET

This application implements an OpenID Connect (OIDC) Authorization Server (AS) that
provides a constant set of users. Its original purpose was to provide a temporary OIDC AS that can be
used after deployment of an OIDC client and an OIDC resource server to set them up before
a real OIDC server is deployed. But it can be used for other purposes like testing.

This fake server has the following features:
* it is implemented in Java as Spring Boot application
* is deployed as JAR file executable on Linux
* implements the following grant types:
  * **Implicit Grant flow** (for JavaScript clients - deprecated)
  * **Authorization Code flow with Proof Key for Code Exchange** (for JavaScript clients - recommended)
  * **Authorization Code flow without PKCE** (for web server clients)
* provides the following endpoints:
  * /.well-known/openid-configuration providing metadata
  * /jwks providing JSON Web Key Set for validating cryptographic signature of id_token
  * /authorize which uses HTTP Basic Auth for asking for username and password
  * /token for exchanging authorization code for access token
  * /userinfo that provides data about the user
  * /introspection that provides access token introspection

Build and run it with:   
```bash
mvn package

target/fake_oidc_server.jar
```

By default the application runs at TCP port 8090, uses a self-signed certificate for localhost, and there are
two users with lognames "perun" and "makub", and passwords "test". This can be changed by using command line options:
 
```bash
target/fake_oidc_server.jar \
   --server.port=8100 \
   --server.ssl.key-store=mykeystore.p12 \
   --oidc.users.john.password=bflmpsvz \
   --oidc.users.john.sub=0001@example.com \
   --oidc.users.john.email=john.doe@example.com \
   --oidc.users.john.given_name="John" \
   --oidc.users.john.family_name="Doe"
```
See all the available options in the file src/main/resources/application.yml

To disable SSL entirely you must disable the `ssl` spring profile. In order to do that you must overwrite the active profiles:

```bash
java -jar -Dspring.profiles.active=default target/fake_oidc_server.jar
```

