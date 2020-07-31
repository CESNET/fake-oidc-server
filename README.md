# Fake OpenID Connect Authorization Server

(c) 2020 Martin Kuba, CESNET

This application implements an OpenID Connect (OIDC) Authorization Server (AS) that
provides just one user. Its purpose is to provide a temporary OIDC AS that can be
used after deployment of an OIDC client and an OIDC resource server to set them up before
a real OIDC server is deployed.

This fake server has the following features:
* it is implemented in Java as Spring Boot application
* implements **Implicit Grant flow** (for JavaScript clients)
* provides the following endpoints:
  * /.well-known/openid-configuration providing metadata
  * /jwks providing JSON Web Key Set for validating cryptographic signature of id_token
  * /authorize which uses HTTP Basic Auth for asking for username and password
  * /userinfo that provides data about the user
  * /introspection that provides access token introspection

Build and run it with:   
```bash
mvn package

java -jar target/fake_oidc.jar
```

By default the application runs at TCP port 8090, uses a self-signed certificate for localhost, and the only
user has username "perun" and password "test". This can be changed by using command line options:
 
```bash
java -jar target/fake_oidc.jar \
           --server.port=8100 \
           --server.ssl.key-store=mykeystore.p12 \
           --oidc.user.logname=john \
           --oidc.user.password=bflmpsvz \
           --oidc.user.sub=1@example.com \
           --oidc.user.name="John Doe"
```  
See all the available options in the file src/main/resources/application.yml

