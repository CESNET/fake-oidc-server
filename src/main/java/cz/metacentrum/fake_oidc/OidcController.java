package cz.metacentrum.fake_oidc;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;

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
import com.nimbusds.jwt.JWTClaimsSet.Builder;
import com.nimbusds.jwt.SignedJWT;

/**
 * Implementation of all necessary OIDC endpoints.
 *
 * @author Martin Kuba makub@ics.muni.cz
 */
@RestController
public class OidcController {

    private static final Logger log = LoggerFactory.getLogger(OidcController.class);

    public static final String METADATA_ENDPOINT = "/.well-known/openid-configuration";
    public static final String AUTHORIZATION_ENDPOINT = "/authorize";
    public static final String TOKEN_ENDPOINT = "/token";
    public static final String USERINFO_ENDPOINT = "/userinfo";
    public static final String JWKS_ENDPOINT = "/jwks";
    public static final String INTROSPECTION_ENDPOINT = "/introspect";
    
    // only for testing
    public static final String TEST_GETUSERTOKEN = "/testing/getusertoken";

    private JWSSigner signer;
    private JWKSet publicJWKSet;
    private JWSHeader jwsHeader;

    private final Map<String, AccessTokenInfo> accessTokens = new HashMap<>();
    private final Map<String, CodeInfo> authorizationCodes = new HashMap<>();
    private final SecureRandom random = new SecureRandom();

    private final FakeOidcServerProperties serverProperties;

    public OidcController(@Autowired FakeOidcServerProperties serverProperties) {
        this.serverProperties = serverProperties;
    }

    @PostConstruct
    public void init() throws IOException, ParseException, JOSEException {
        log.info("initializing JWK");
        JWKSet jwkSet = JWKSet.load(getClass().getResourceAsStream("/jwks.json"));
        JWK key = jwkSet.getKeys().get(0);
        signer = new RSASSASigner((RSAKey) key);
        publicJWKSet = jwkSet.toPublicJWKSet();
        jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build();
        log.info("config {}", serverProperties);
    }

    /**
     * Provides OIDC metadata. See the spec at https://openid.net/specs/openid-connect-discovery-1_0.html
     */
    @RequestMapping(value = METADATA_ENDPOINT, method = RequestMethod.GET, produces = MediaType.APPLICATION_JSON_VALUE)
    @CrossOrigin
    public ResponseEntity<?> metadata(UriComponentsBuilder uriBuilder, HttpServletRequest req) {
        log.info("called " + METADATA_ENDPOINT + " from {}", req.getRemoteHost());
        String urlPrefix = uriBuilder.replacePath(null).build().encode().toUriString();
        Map<String, Object> m = new LinkedHashMap<>();
        // https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
        // https://tools.ietf.org/html/rfc8414#section-2
        m.put("issuer", urlPrefix + "/"); // REQUIRED
        m.put("authorization_endpoint", urlPrefix + AUTHORIZATION_ENDPOINT); // REQUIRED
        m.put("token_endpoint", urlPrefix + TOKEN_ENDPOINT); // REQUIRED unless only the Implicit Flow is used
        m.put("userinfo_endpoint", urlPrefix + USERINFO_ENDPOINT); // RECOMMENDED
        m.put("jwks_uri", urlPrefix + JWKS_ENDPOINT); // REQUIRED
        m.put("introspection_endpoint", urlPrefix + INTROSPECTION_ENDPOINT);
        m.put("scopes_supported", Arrays.asList("openid", "profile", "email")); // RECOMMENDED
        m.put("response_types_supported", Arrays.asList("id_token token", "code")); // REQUIRED
        m.put("grant_types_supported", Arrays.asList("authorization_code", "client_credentials", "implicit")); //OPTIONAL
        m.put("subject_types_supported", Collections.singletonList("public")); // REQUIRED
        m.put("id_token_signing_alg_values_supported", Arrays.asList("RS256", "none")); // REQUIRED
        m.put("claims_supported", Arrays.asList("sub", "iss", "name", "family_name", "given_name", "preferred_username", "email"));
        m.put("code_challenge_methods_supported", Arrays.asList("plain", "S256")); // PKCE support advertised
        return ResponseEntity.ok().body(m);
    }

    /**
     * Provides JSON Web Key Set containing the public part of the key used to sign ID tokens.
     */
    @RequestMapping(value = JWKS_ENDPOINT, method = RequestMethod.GET, produces = MediaType.APPLICATION_JSON_VALUE)
    @CrossOrigin
    public ResponseEntity<String> jwks(HttpServletRequest req) {
        log.info("called " + JWKS_ENDPOINT + " from {}", req.getRemoteHost());
        return ResponseEntity.ok().body(publicJWKSet.toString());
    }

    /**
     * Provides claims about a user. Requires a valid access token.
     */
    @RequestMapping(value = USERINFO_ENDPOINT, method = RequestMethod.GET, produces = MediaType.APPLICATION_JSON_VALUE)
    @CrossOrigin(allowedHeaders = {"Authorization", "Content-Type"})
    public ResponseEntity<?> userinfo(@RequestHeader("Authorization") String auth,
                                      @RequestParam(required = false) String access_token,
                                      HttpServletRequest req) {
        log.info("called " + USERINFO_ENDPOINT + " from {}", req.getRemoteHost());
        if (!auth.startsWith("Bearer ")) {
            if (access_token == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("No token");
            }
            auth = access_token;
        } else {
            auth = auth.substring(7);
        }
        AccessTokenInfo accessTokenInfo = accessTokens.get(auth);
        if (accessTokenInfo == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("access token not found");
        }
        Set<String> scopes = setFromSpaceSeparatedString(accessTokenInfo.scope);
        Map<String, Object> m = new LinkedHashMap<>();
        User user = serverProperties.getUsers().get(accessTokenInfo.sub);
        m.put("sub", user.getSub());
        if (scopes.contains("profile")) {
            m.put("name", user.getName());
            m.put("family_name", user.getFamily_name());
            m.put("given_name", user.getGiven_name());
            m.put("preferred_username", user.getPreferred_username());
        }
        if (scopes.contains("email")) {
            m.put("email", user.getEmail());
        }
        return ResponseEntity.ok().body(m);
    }

    /**
     * Provides information about a supplied access token.
     */
    @RequestMapping(value = INTROSPECTION_ENDPOINT, method = RequestMethod.POST, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> introspection(@RequestParam String token,
                                           @RequestHeader("Authorization") String auth,
                                           HttpServletRequest req) {
        log.info("called " + INTROSPECTION_ENDPOINT + " from {}", req.getRemoteHost());
        Map<String, Object> m = new LinkedHashMap<>();
        AccessTokenInfo accessTokenInfo = accessTokens.get(token);
        if (accessTokenInfo == null) {
            log.error("token not found in memory: {}", token);
            m.put("active", false);
        } else {
            log.info("found token for user {}, releasing scopes: {}", accessTokenInfo.sub, accessTokenInfo.scope);
            // see https://tools.ietf.org/html/rfc7662#section-2.2 for all claims
            m.put("active", true);
            m.put("scope", accessTokenInfo.scope);
            m.put("client_id", accessTokenInfo.clientId);
            m.put("username", accessTokenInfo.sub);
            m.put("token_type", "Bearer");
            m.put("exp", accessTokenInfo.expiration.toInstant().toEpochMilli());
            m.put("sub", accessTokenInfo.sub);
            m.put("iss", accessTokenInfo.iss);
        }
        return ResponseEntity.ok().body(m);
    }

    /**
     * Provides token endpoint.
     */
    @RequestMapping(value = TOKEN_ENDPOINT, method = RequestMethod.POST, produces = MediaType.APPLICATION_JSON_VALUE)
    @CrossOrigin
    public ResponseEntity<?> token(@RequestParam String grant_type,
                                   @RequestParam(required = false) String code,
                                   @RequestParam(required = false) String redirect_uri,
                                   @RequestParam(required = false) String client_id,
                                   @RequestParam(required = false) String client_secret,
                                   @RequestParam(required = false) String code_verifier,
                                   @RequestHeader(name = "Authorization", required = false) String auth,
                                   UriComponentsBuilder uriBuilder,
                                   HttpServletRequest req) throws NoSuchAlgorithmException, JOSEException {
        log.info("called " + TOKEN_ENDPOINT + " from {}, grant_type={}", req.getRemoteHost(), grant_type);
        
        switch (grant_type) {
        case "authorization_code":
            log.info("code={} redirect_uri={} client_id={}", code, redirect_uri, client_id);
            return tokenForAuthorizationCodeFlow(code, redirect_uri, client_id, code_verifier, auth, uriBuilder, req);
            
        case "client_credentials":
            log.info("client_id={} client_secret={} auth={}", client_id, client_secret, auth);
            return tokenForClientCredentialsFlow(client_id, client_secret, auth, uriBuilder, req);
            
        default:
            return jsonError("unsupported_grant_type", "grant_type " + grant_type + " not supported");
        }
    }
    
    private ResponseEntity<?> tokenForAuthorizationCodeFlow(String code, String redirect_uri, String client_id,
            String code_verifier, String auth, UriComponentsBuilder uriBuilder, HttpServletRequest req)
            throws NoSuchAlgorithmException, JOSEException {
        CodeInfo codeInfo = authorizationCodes.get(code);
        if (codeInfo == null) {
            return jsonError("invalid_grant", "code not valid");
        }
        if (!redirect_uri.equals(codeInfo.redirect_uri)) {
            return jsonError("invalid_request", "redirect_uri not valid");
        }
        if (codeInfo.codeChallenge != null) {
            // check PKCE
            if (code_verifier == null) {
                return jsonError("invalid_request", "code_verifier missing");
            }
            if ("S256".equals(codeInfo.codeChallengeMethod)) {
                MessageDigest s256 = MessageDigest.getInstance("SHA-256");
                s256.reset();
                s256.update(code_verifier.getBytes(StandardCharsets.UTF_8));
                String hashedVerifier = Base64URL.encode(s256.digest()).toString();
                if (!codeInfo.codeChallenge.equals(hashedVerifier)) {
                    log.warn("code_verifier {} hashed using S256 to {} does not match code_challenge {}", code_verifier, hashedVerifier, codeInfo.codeChallenge);
                    return jsonError("invalid_request", "code_verifier not correct");
                }
                log.info("code_verifier OK");
            } else {
                if (!codeInfo.codeChallenge.equals(code_verifier)) {
                    log.warn("code_verifier {} does not match code_challenge {}", code_verifier, codeInfo.codeChallenge);
                    return jsonError("invalid_request", "code_verifier not correct");
                }
            }
        }
        // return access token
        Map<String, String> map = new LinkedHashMap<>();
        String accessToken = createAccessToken(codeInfo.iss, codeInfo.user.getSub(), codeInfo.client_id, codeInfo.scope);
        map.put("access_token", accessToken);
        map.put("token_type", "Bearer");
        map.put("expires_in", String.valueOf(serverProperties.getTokenExpirationSeconds()));
        map.put("scope", codeInfo.scope);
        map.put("id_token", createIdToken(codeInfo.iss, codeInfo.user, codeInfo.client_id, codeInfo.nonce, accessToken));
        return ResponseEntity.ok(map);
    }
    
    private ResponseEntity<?> tokenForClientCredentialsFlow(String client_id, String client_secret, String auth,
            UriComponentsBuilder uriBuilder, HttpServletRequest req)
            throws NoSuchAlgorithmException, JOSEException {
        
        if (client_id == null || client_secret == null) {
            if (auth != null) {
                return jsonError("invalid_request", "client authentication via Authorization header not supported");
            } else {
                return jsonError("invalid_client", "neither client_id and client_secret nor Authorization header set");
            }
        }
        
        if(this.serverProperties.getClients().values().stream().filter(element -> 
        element.id().equals(client_id) && element.secret().equals(client_secret))
        .findFirst().isEmpty()) {
            log.info("wrong client_id and client_secret combination");
            return response401();
        }
        
        
        
        // return access token
        Map<String, String> map = new LinkedHashMap<>();
        String iss = uriBuilder.replacePath("/").build().encode().toUriString();
        String sub = client_id; // TODO?
        String accessToken = createAccessToken(iss, sub, client_id, null);
        map.put("access_token", accessToken);
        map.put("token_type", "Bearer");
        map.put("expires_in", String.valueOf(serverProperties.getTokenExpirationSeconds()));
        return ResponseEntity.ok(map);
    }
    
    
    /**
     * Provides authorization endpoint.
     */
    @RequestMapping(value = AUTHORIZATION_ENDPOINT, method = RequestMethod.GET)
    public ResponseEntity<?> authorize(@RequestParam String client_id,
                                       @RequestParam String redirect_uri,
                                       @RequestParam String response_type,
                                       @RequestParam String scope,
                                       @RequestParam String state,
                                       @RequestParam(required = false) String nonce,
                                       @RequestParam(required = false) String code_challenge,
                                       @RequestParam(required = false) String code_challenge_method,
                                       @RequestParam(required = false) String response_mode,
                                       @RequestHeader(name = "Authorization", required = false) String auth,
                                       UriComponentsBuilder uriBuilder,
                                       HttpServletRequest req) throws JOSEException, NoSuchAlgorithmException {
        log.info("called " + AUTHORIZATION_ENDPOINT + " from {}, scope={} response_type={} client_id={} redirect_uri={}",
                req.getRemoteHost(), scope, response_type, client_id, redirect_uri);
        if (auth == null) {
            log.info("user and password not provided");
            return response401();
        } else {
            String[] creds = new String(Base64.getDecoder().decode(auth.split(" ")[1])).split(":", 2);
            String login = creds[0];
            String password = creds[1];
            for (User user : serverProperties.getUsers().values()) {
                if (user.getLogname().equals(login) && user.getPassword().equals(password)) {
                    log.info("password for user {} is correct", login);
                    Set<String> responseType = setFromSpaceSeparatedString(response_type);
                    String iss = uriBuilder.replacePath("/").build().encode().toUriString();
                    if (responseType.contains("token")) {
                        // implicit flow
                        log.info("using implicit flow");
                        String access_token = createAccessToken(iss, user.getSub(), client_id, scope);
                        String id_token = createIdToken(iss, user, client_id, nonce, access_token);
                        String url = redirect_uri + "#" +
                                "access_token=" + urlencode(access_token) +
                                "&token_type=Bearer" +
                                "&state=" + urlencode(state) +
                                "&expires_in=" + serverProperties.getTokenExpirationSeconds() +
                                "&id_token=" + urlencode(id_token);
                        return ResponseEntity.status(HttpStatus.FOUND).header("Location", url).build();
                    } else if (responseType.contains("code")) {
                        // authorization code flow
                        log.info("using authorization code flow {}", code_challenge != null ? "with PKCE" : "");
                        String code = createAuthorizationCode(code_challenge, code_challenge_method, client_id, redirect_uri, user, iss, scope, nonce);
                        String url = redirect_uri + "?" +
                                "code=" + code +
                                "&state=" + urlencode(state);
                        return ResponseEntity.status(HttpStatus.FOUND).header("Location", url).build();
                    } else {
                        String url = redirect_uri + "#" + "error=unsupported_response_type";
                        return ResponseEntity.status(HttpStatus.FOUND).header("Location", url).build();
                    }
                }
            }
            log.info("wrong user and password combination");
            return response401();
        }
    }
    
    @RequestMapping(value = TEST_GETUSERTOKEN, method = RequestMethod.GET)
    public ResponseEntity<?> getUserToken(@RequestParam String userName,
                                        @RequestParam String client_id,
                                        @RequestParam String scope,
                                        UriComponentsBuilder uriBuilder) throws JOSEException, NoSuchAlgorithmException {
        
        User user = this.serverProperties.getUsers().get(userName);
        if(user == null) {
            return response401();
        }
        
        String iss = uriBuilder.replacePath("/").build().encode().toUriString();
        String accessToken = createAccessToken(iss, userName, client_id, scope);
        
        Map<String, String> map = new LinkedHashMap<>();
        map.put("access_token", accessToken);
        map.put("token_type", "Bearer");
        map.put("expires_in", String.valueOf(serverProperties.getTokenExpirationSeconds()));
        map.put("scope", scope);
        map.put("id_token", createIdToken(iss, user, client_id, UUID.randomUUID().toString(), accessToken));
        return ResponseEntity.ok(map);
    }

    private String createAuthorizationCode(String code_challenge, String code_challenge_method, String client_id, String redirect_uri, User user, String iss, String scope, String nonce) {
        byte[] bytes = new byte[16];
        random.nextBytes(bytes);
        String code = Base64URL.encode(bytes).toString();
        log.info("issuing code={}", code);
        authorizationCodes.put(code, new CodeInfo(code_challenge, code_challenge_method, code, client_id, redirect_uri, user, iss, scope, nonce));
        return code;
    }

    private String createAccessToken(String iss, String sub, String client_id, String scope) throws JOSEException {
        // create JWT claims
        Date expiration = new Date(System.currentTimeMillis() + serverProperties.getTokenExpirationSeconds() * 1000L);
        Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder()
                .subject(sub)
                .issuer(iss)
                .audience(client_id)
                .issueTime(new Date())
                .expirationTime(expiration)
                .jwtID(UUID.randomUUID().toString());
        if (scope != null) {
            jwtClaimsSetBuilder.claim("scope", scope);
        }
        JWTClaimsSet jwtClaimsSet = jwtClaimsSetBuilder.build();
        // create JWT token
        SignedJWT jwt = new SignedJWT(jwsHeader, jwtClaimsSet);
        // sign the JWT token
        jwt.sign(signer);
        String access_token = jwt.serialize();
        accessTokens.put(access_token, new AccessTokenInfo(sub, access_token, expiration, scope, client_id, iss));
        return access_token;
    }

    private String createIdToken(String iss, User user, String client_id, String nonce, String accessToken) throws NoSuchAlgorithmException, JOSEException {
        // compute at_hash
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.reset();
        digest.update(accessToken.getBytes(StandardCharsets.UTF_8));
        byte[] hashBytes = digest.digest();
        byte[] hashBytesLeftHalf = Arrays.copyOf(hashBytes, hashBytes.length / 2);
        Base64URL encodedHash = Base64URL.encode(hashBytesLeftHalf);
        // create JWT claims
        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                .subject(user.getSub())
                .issuer(iss)
                .audience(client_id)
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + serverProperties.getTokenExpirationSeconds() * 1000L))
                .jwtID(UUID.randomUUID().toString())
                .claim("nonce", nonce)
                .claim("at_hash", encodedHash.toString())
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
        final String sub;
        final String accessToken;
        final Date expiration;
        final String scope;
        final String clientId;
        final String iss;

        public AccessTokenInfo(String sub, String accessToken, Date expiration, String scope, String clientId, String iss) {
            this.sub = sub;
            this.accessToken = accessToken;
            this.expiration = expiration;
            this.scope = scope;
            this.clientId = clientId;
            this.iss = iss;
        }

    }

    private static class CodeInfo {
        final String codeChallenge;
        final String codeChallengeMethod;
        final String code;
        final String client_id;
        final String redirect_uri;
        final User user;
        final String iss;
        final String scope;
        final String nonce;

        public CodeInfo(String codeChallenge, String codeChallengeMethod, String code, String client_id, String redirect_uri, User user, String iss, String scope, String nonce) {
            this.codeChallenge = codeChallenge;
            this.codeChallengeMethod = codeChallengeMethod;
            this.code = code;
            this.client_id = client_id;
            this.redirect_uri = redirect_uri;
            this.user = user;
            this.iss = iss;
            this.scope = scope;
            this.nonce = nonce;
        }
    }

    private static Set<String> setFromSpaceSeparatedString(String s) {
        if (s == null || s.isBlank()) return Collections.emptySet();
        return new HashSet<>(Arrays.asList(s.split(" ")));
    }

    private static ResponseEntity<?> jsonError(String error, String error_description) {
        log.warn("error={} error_description={}", error, error_description);
        Map<String, String> map = new LinkedHashMap<>();
        map.put("error", error);
        map.put("error_description", error_description);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(map);
    }

}
