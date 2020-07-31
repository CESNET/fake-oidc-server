package cz.metacentrum.fake_oidc;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.UriComponentsBuilder;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Run with "mvn spring-boot:run".
 * <p>
 * Provides OIDC metadata. Seet the spec at https://openid.net/specs/openid-connect-discovery-1_0.html
 */
@RestController
public class OidcController {

    private static final Logger log = LoggerFactory.getLogger(OidcController.class);

    public static final String METADATA_ENDPOINT = "/.well-known/openid-configuration";
    public static final String AUTHORIZATION_ENDPOINT = "/authorize";
    public static final String TOKEN_ENDPOINT = "/token";
    public static final String USERINFO_ENDPOINT = "/userinfo";
    public static final String JWKS_ENDPOINT = "/jwks";
    public static final String INTROSPECTION_ENDPOINT = "/introspection";

    private JWSSigner signer;
    private JWKSet publicJWKSet;
    private JWSHeader jwsHeader;

    private Map<String, AccessTokenInfo> accessTokens = new HashMap<>();

    @Autowired
    private FakeOidcProperties fakeOidcProperties;

    @PostConstruct
    public void init() throws IOException, ParseException, JOSEException {
        log.info("initializing JWK");
        JWKSet jwkSet = JWKSet.load(getClass().getResourceAsStream("/jwks.json"));
        JWK key = jwkSet.getKeys().get(0);
        signer = new RSASSASigner((RSAKey) key);
        publicJWKSet = jwkSet.toPublicJWKSet();
        jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build();
        log.info("config {}", fakeOidcProperties);
    }

    @RequestMapping(value = METADATA_ENDPOINT, method = RequestMethod.GET, produces = MediaType.APPLICATION_JSON_VALUE)
    @CrossOrigin
    public ResponseEntity<?> metadata(UriComponentsBuilder uriBuilder, HttpServletRequest req) {
        log.info(METADATA_ENDPOINT + " from {}", req.getRemoteHost());
        String urlPrefix = uriBuilder.replacePath(null).build().encode().toUriString();
        Map<String, Object> m = new LinkedHashMap<>();
        // https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
        m.put("issuer", urlPrefix + "/"); // REQUIRED
        m.put("authorization_endpoint", urlPrefix + AUTHORIZATION_ENDPOINT); // REQUIRED
        m.put("token_endpoint", urlPrefix + TOKEN_ENDPOINT); // REQUIRED unless only the Implicit Flow is used
        m.put("userinfo_endpoint", urlPrefix + USERINFO_ENDPOINT); // RECOMMENDED
        m.put("jwks_uri", urlPrefix + JWKS_ENDPOINT); // REQUIRED
        m.put("introspection_endpoint", urlPrefix + INTROSPECTION_ENDPOINT);
        m.put("scopes_supported", Arrays.asList("openid", "profile", "email")); // RECOMMENDED
        m.put("response_types_supported", Collections.singletonList("id_token token")); // REQUIRED
        m.put("subject_types_supported", Collections.singletonList("public")); // REQUIRED
        m.put("id_token_signing_alg_values_supported", Arrays.asList("RS256", "none")); // REQUIRED
        m.put("claims_supported", Arrays.asList("sub", "iss", "name", "family_name", "given_name", "preferred_username", "email"));
        return ResponseEntity.ok().body(m);
    }

    @RequestMapping(value = JWKS_ENDPOINT, method = RequestMethod.GET, produces = MediaType.APPLICATION_JSON_VALUE)
    @CrossOrigin
    public ResponseEntity<String> jwks() {
        log.info("/jwks");
        return ResponseEntity.ok().body(publicJWKSet.toString());
    }

    @RequestMapping(value = USERINFO_ENDPOINT, method = RequestMethod.GET, produces = MediaType.APPLICATION_JSON_VALUE)
    @CrossOrigin(allowedHeaders = {"Authorization", "Content-Type"})
    public ResponseEntity<?> userinfo(@RequestHeader("Authorization") String auth) {
        log.info("/userinfo");
        if (!auth.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("No token");
        }
        auth = auth.substring(7);
        AccessTokenInfo accessTokenInfo = accessTokens.get(auth);
        if (accessTokenInfo == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("access token not found");
        }
        Map<String, Object> m = new LinkedHashMap<>();
        User user = accessTokenInfo.user;
        m.put("sub", user.getSub());
        m.put("name", user.getName());
        m.put("family_name", user.getFamily_name());
        m.put("given_name", user.getGiven_name());
        m.put("preferred_username", user.getPreferred_username());
        m.put("email", user.getEmail());
        return ResponseEntity.ok().body(m);
    }

    @RequestMapping(value = INTROSPECTION_ENDPOINT, method = RequestMethod.POST, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> introspection(@RequestParam String token,
                                           @RequestHeader("Authorization") String auth) {
        log.info("/introspection auth = {} token= {}", auth, token);
        Map<String, Object> m = new LinkedHashMap<>();
        AccessTokenInfo accessTokenInfo = accessTokens.get(token);
        if( accessTokenInfo == null) {
            m.put("active", false);
        } else {
            m.put("active", true);
            m.put("scope", String.join(" ", accessTokenInfo.scopes));
            m.put("username", accessTokenInfo.user.getSub());
            m.put("sub", accessTokenInfo.user.getSub());
        }
        return ResponseEntity.ok().body(m);
    }

    @RequestMapping(value = AUTHORIZATION_ENDPOINT, method = RequestMethod.GET)
    public ResponseEntity<?> authorize(@RequestParam String client_id,
                                       @RequestParam String redirect_uri,
                                       @RequestParam String response_type,
                                       @RequestParam String scope,
                                       @RequestParam String state,
                                       @RequestParam String nonce,
                                       @RequestHeader(name = "Authorization", required = false) String auth,
                                       UriComponentsBuilder uriBuilder) throws JOSEException, NoSuchAlgorithmException {
        log.info("/authorize scope={} response_type={} client_id={} redirect_uri={}", scope, response_type, client_id, redirect_uri);
        if (auth == null) {
            log.info("user and password not provided");
            return response401();
        } else {
            String[] creds = new String(Base64.getDecoder().decode(auth.split(" ")[1])).split(":", 2);
            String logname = creds[0];
            String password = creds[1];
            User user = fakeOidcProperties.getUser();
            if (user.getLogname().equals(logname) && user.getPassword().equals(password)) {
                log.info("user {} correct", logname);
                String iss = uriBuilder.replacePath("/").build().encode().toUriString();
                String sub = user.getSub();
                String access_token = createAccessToken(iss, user, client_id, scope);
                String id_token = createIdToken(iss, user, client_id, nonce, access_token);
                String url = redirect_uri + "#" +
                        "access_token=" + urlencode(access_token) +
                        "&token_type=Bearer" +
                        "&state=" + urlencode(state) +
                        "&expires_in=36000" +
                        "&id_token=" + urlencode(id_token);
                return ResponseEntity.status(HttpStatus.FOUND).header("Location", url).build();
            } else {
                log.info("wrong user and password combination");
                return response401();
            }
        }
    }

    private String createAccessToken(String iss, User user, String client_id, String scope) throws JOSEException {
        // create JWT claims
        Date expiration = new Date(System.currentTimeMillis() + 10 * 3600 * 1000L);
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .subject(user.getSub())
                .issuer(iss)
                .audience(client_id)
                .issueTime(new Date())
                .expirationTime(expiration)
                .jwtID(UUID.randomUUID().toString())
                .claim("scope", scope)
                .build();
        // create JWT token
        SignedJWT jwt = new SignedJWT(jwsHeader, jwtClaimsSet);
        // sign the JWT token
        jwt.sign(signer);
        String access_token = jwt.serialize();
        accessTokens.put(access_token, new AccessTokenInfo(user, access_token, expiration, scope.split(" ")));
        return access_token;
    }

    private String createIdToken(String iss, User user, String client_id, String nonce, String accessToken) throws NoSuchAlgorithmException, JOSEException {
        // compute at_hash
        MessageDigest hasher = MessageDigest.getInstance("SHA-256");
        hasher.reset();
        hasher.update(accessToken.getBytes(StandardCharsets.UTF_8));
        byte[] hashBytes = hasher.digest();
        byte[] hashBytesLeftHalf = Arrays.copyOf(hashBytes, hashBytes.length / 2);
        Base64URL encodedHash = Base64URL.encode(hashBytesLeftHalf);
        // create JWT claims
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .subject(user.getSub())
                .issuer(iss)
                .audience(client_id)
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + 10 * 3600 * 1000L))
                .jwtID(UUID.randomUUID().toString())
                .claim("nonce", nonce)
                .claim("at_hash", encodedHash)
                .build();
        // create JWT token
        SignedJWT myToken = new SignedJWT(jwsHeader, jwtClaimsSet);
        // sign the JWT token
        myToken.sign(signer);
        return myToken.serialize();
    }

    private static String urlencode(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    private static ResponseEntity<String> response401() {
        HttpHeaders responseHeaders = new HttpHeaders();
        responseHeaders.setContentType(MediaType.TEXT_HTML);
        responseHeaders.add("WWW-Authenticate", "Basic realm=\"Fake OIDC server\"");
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).headers(responseHeaders).body("<html><body><h1>401 Unauthorized</h1>Fake OIDC server</body></html>");
    }


    private static class AccessTokenInfo {
        User user;
        String accessToken;
        Date expiration;
        String[] scopes;

        public AccessTokenInfo(User user, String accessToken, Date expiration, String[] scopes) {
            this.user = user;
            this.accessToken = accessToken;
            this.expiration = expiration;
            this.scopes = scopes;
        }

        public User getUser() {
            return user;
        }

        public String getAccessToken() {
            return accessToken;
        }

        public Date getExpiration() {
            return expiration;
        }

        public String[] getScopes() {
            return scopes;
        }
    }
}
