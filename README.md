# Fake OpenID Connect Authorization Server
**This is a fork of the [this]() repository which was originally developed by Martin Kuba. This repository fixes a few bugs and extends it in order to run in our test-ecosystem.**


--- 

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

For historic reasons, there are two default users which are always availale. This might change in the future. If you depend on usernames we recommend to explicitly set the users. 
The default accounts are:
```
    perun:
      password: "test"
      sub: "perun1"
      given_name: "Master"
      family_name: "Perun"
      email: "perun@cesnet.cz"
    makub:
      password: "test"
      sub: "makub1"
      given_name: "Martin"
      family_name: "Kuba"
      email: "makub@ics.muni.cz"
```

## Docker 

We provide a docker image to run the application easly. Since the image was built via spring, all spring configuration can be set via environment variables. For example:

```
$  docker run ghcr.io/e-learning-by-sse/infrastructure-fake-oidc:latest -e SPRING_PROFILES_ACTIVE='default' -p 8090:8090
```

An example to define a set of users inside a docker-compose file:

```yaml
version: '3.8'
services:
  auth:
    image: ghcr.io/e-learning-by-sse/infrastructure-fake-oidc
    ports:
      - 8090:8090
    environment:
      OIDC_USERS_JOHN_PASSWORD: bflmpsvz
      OIDC_USERS_JOHN_SUB: 0001@example.com
      OIDC_USERS_JOHN_EMAIL: john.doe@example.com
      OIDC_USERS_JOHN_givenName: John
      OIDC_USERS_JOHN_familyName: Doe
```

If you need multiple users, we recommend mounting a YAML (e.g. application-users.yml) as volume to /workspace inside the project and configure the users there.  

## Development
In order to build and publish a docker image, you need to set two variables in maven
- `docker.user`
- `docker.password`

We recommend to set these as properties inside `~/.m2/settings.xml`. They will override the default values inside the pom. 
```console
$ mvn spring-boot:build-image -Dspring-boot.build-image.publish=true
```
It will push an image with the following tags:
- latest
- the major pom version
- the exact pom version