package de.fraunhofer.fokus.ids.utils.services.authService;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.vertx.circuitbreaker.CircuitBreaker;
import io.vertx.circuitbreaker.CircuitBreakerOptions;
import io.vertx.core.*;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTAuthOptions;
import io.vertx.ext.jwt.JWTOptions;
import io.vertx.ext.web.client.HttpResponse;
import io.vertx.ext.web.client.WebClient;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

/**
 * @author Vincent Bohlen, vincent.bohlen@fokus.fraunhofer.de
 * Based on the TokenManagerService of https://github.com/industrial-data-space/trusted-connector
 */
public class AuthAdapterServiceImpl implements AuthAdapterService {

    private Logger LOGGER = LoggerFactory.getLogger(AuthAdapterServiceImpl.class.getName());
    private String connectorUUID;
    private Key privKey;
    private X509Certificate cert;
    private Vertx vertx;
    private String dapsUrl;
    private String dapsIssuer;
    private String targetAudience = "idsc:IDS_CONNECTORS_ALL";
    private WebClient webClient;
    private CircuitBreaker breaker;

    public AuthAdapterServiceImpl(Vertx vertx,
                                  WebClient webClient,
                                  Path targetDirectory,
                                  JsonObject config,
                                  Handler<AsyncResult<AuthAdapterService>> readyHandler) {
        {
            this.webClient = webClient;
            this.vertx = vertx;
            this.dapsUrl = config.getString("dapsurl");
            this.dapsIssuer = config.getString("dapsissuer");
            this.breaker = CircuitBreaker.create("token-circuit-breaker", vertx,
                new CircuitBreakerOptions().setMaxRetries(10)
            ).retryPolicy(retryCount -> retryCount * 500L);

            // Try clause for setup phase (loading keys, building trust manager)
            try {
                InputStream jksKeyStoreInputStream =
                        Files.newInputStream(targetDirectory.resolve(config.getString("keystorename")));
                InputStream jksTrustStoreInputStream =
                        Files.newInputStream(targetDirectory.resolve(config.getString("truststorename")));

                KeyStore keystore = KeyStore.getInstance("PKCS12");
                KeyStore trustManagerKeyStore = KeyStore.getInstance("PKCS12");

                LOGGER.info("Loading key store: " + config.getString("keystorename"));
                LOGGER.info("Loading trust store: " + config.getString("truststorename"));
                keystore.load(jksKeyStoreInputStream, config.getString("keystorepassword").toCharArray());
                trustManagerKeyStore.load(jksTrustStoreInputStream,  config.getString("keystorepassword").toCharArray());
                java.security.cert.Certificate[] certs = trustManagerKeyStore.getCertificateChain("aisecdaps");
                LOGGER.info("Cert chain: " + Arrays.toString(certs));

                LOGGER.info("LOADED CA CERT: " + trustManagerKeyStore.getCertificate("aisecdaps"));
                jksKeyStoreInputStream.close();
                jksTrustStoreInputStream.close();

                // get private key
                this.privKey = keystore.getKey(config.getString("keystorealias"), config.getString("keystorepassword").toCharArray());
                // Get certificate of public key
                this.cert = (X509Certificate) keystore.getCertificate(config.getString("keystorealias"));

                LOGGER.info("\tCertificate Subject: " + cert.getSubjectDN());

                // Get AKI
                //GET 2.5.29.14	SubjectKeyIdentifier / 2.5.29.35	AuthorityKeyIdentifier
                String aki_oid = Extension.authorityKeyIdentifier.getId();
                byte[] rawAuthorityKeyIdentifier = cert.getExtensionValue(aki_oid);
                ASN1OctetString akiOc = ASN1OctetString.getInstance(rawAuthorityKeyIdentifier);
                AuthorityKeyIdentifier aki = AuthorityKeyIdentifier.getInstance(akiOc.getOctets());
                byte[] authorityKeyIdentifier = aki.getKeyIdentifier();

                //GET SKI
                String ski_oid = Extension.subjectKeyIdentifier.getId();
                byte[] rawSubjectKeyIdentifier = cert.getExtensionValue(ski_oid);
                ASN1OctetString ski0c = ASN1OctetString.getInstance(rawSubjectKeyIdentifier);
                SubjectKeyIdentifier ski = SubjectKeyIdentifier.getInstance(ski0c.getOctets());
                byte[] subjectKeyIdentifier = ski.getKeyIdentifier();

                String aki_result = beautifyHex(encodeHexString(authorityKeyIdentifier).toUpperCase());
                String ski_result = beautifyHex(encodeHexString(subjectKeyIdentifier).toUpperCase());

                this.connectorUUID = ski_result + "keyid:" + aki_result.substring(0, aki_result.length() - 1);

                LOGGER.info("AKI: " + aki_result);
                LOGGER.info("SKI: " + ski_result);
                LOGGER.info("ConnectorUUID: " + this.connectorUUID);
                readyHandler.handle(Future.succeededFuture(this));

            } catch (KeyStoreException
                    | NoSuchAlgorithmException
                    | CertificateException
                    | UnrecoverableKeyException e) {
                LOGGER.error("Cannot acquire token:", e);
                readyHandler.handle(Future.failedFuture(e));
            } catch (IOException e) {
                LOGGER.error("Error retrieving token:", e);
                readyHandler.handle(Future.failedFuture(e));
            } catch (Exception e) {
                LOGGER.error("Something else went wrong:", e);
                readyHandler.handle(Future.failedFuture(e));
            }
        }
    }

    @Override
    public AuthAdapterService isAuthenticated(String token, Handler<AsyncResult<Void>> handler) {
        verifyJWT(new JsonObject().put("jwt", token),  reply -> {
            if(reply.succeeded()){
                handler.handle(Future.succeededFuture());
            } else {
                handler.handle(Future.failedFuture(reply.cause()));
            }
        });
        return this;
    }

    private void verifyJWT(
            JsonObject dynamicAttributeTokenJson,
            Handler<AsyncResult<User>> resultHandler) {

        LOGGER.info("Verifying JWT...");
        URL url = null;
        try {
            url = new URL(dapsUrl);
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }

        webClient.get(443,url.getHost(), url.getPath()+"/.well-known/jwks.json")
                .ssl(true)
                .send(jwksReply -> {
                    if(jwksReply.succeeded()){
                        JsonArray jArray = jwksReply.result().bodyAsJsonObject().getJsonArray("keys");
                        List<JsonObject> objList = new ArrayList<>();
                        for(int i = 0;i<jArray.size();i++){
                            objList.add(jArray.getJsonObject(i));
                        }
                        AuthProvider p = JWTAuth.create(vertx,
                                new JWTAuthOptions()
                                        .setJwks(objList).setJWTOptions(
                                                new JWTOptions()
                                                        .setIgnoreExpiration(false)
                                                        .setAudience(Arrays.asList(this.targetAudience))
                                                        .setIssuer(dapsIssuer)));
                        p.authenticate(dynamicAttributeTokenJson, authReply -> {
                            if(authReply.succeeded()){
                                resultHandler.handle(Future.succeededFuture(authReply.result()));
                            } else {
                                LOGGER.info(authReply.cause());
                                resultHandler.handle(Future.failedFuture(authReply.cause()));
                            }
                        });
                    } else {
                        LOGGER.info(jwksReply.cause());
                        resultHandler.handle(Future.failedFuture(jwksReply.cause()));
                    }
                });
    }

    @Override
    public AuthAdapterService retrieveToken(Handler<AsyncResult<String>> resultHandler){

        LOGGER.info("Retrieving Dynamic Attribute Token...");
        Promise<MultiMap> formPromise = Promise.promise();

        buildJWT( reply -> {
            if(reply.succeeded()){
                buildForm(reply, formPromise);
            }
        });

        Promise<URL> urlPromise = Promise.promise();
        try {
            URL url = new URL(dapsUrl);
            urlPromise.complete(url);
        } catch (MalformedURLException e) {
            LOGGER.error(e);
            urlPromise.fail(e);
        }

        executeRequest(formPromise.future(), urlPromise.future(), resultHandler);

        return this;
    }

    void buildForm(AsyncResult<String> jwsFuture, Handler<AsyncResult<MultiMap>> resultHandler){
        if(jwsFuture.succeeded()) {
            MultiMap form = MultiMap.caseInsensitiveMultiMap();
            form.set("grant_type", "client_credentials");
            form.set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
            form.set("client_assertion", jwsFuture.result());
            form.set("scope", "idsc:IDS_CONNECTOR_ATTRIBUTES_ALL");
            resultHandler.handle(Future.succeededFuture(form));
        } else {
            resultHandler.handle(Future.failedFuture(jwsFuture.cause()));
        }
    }

    void buildJWT(Handler<AsyncResult<String>> resultHandler){
        Date expiryDate = Date.from(Instant.now().plusSeconds(86400));
        JwtBuilder jwtb =
                Jwts.builder()
                        .setIssuer(connectorUUID)
                        .setSubject(connectorUUID)
                        .claim("@context", "https://w3id.org/idsa/contexts/context.jsonld")
                        .claim("@type", "ids:DatRequestToken")
                        .setExpiration(expiryDate)
                        .setIssuedAt(Date.from(Instant.now()))
                        .setAudience(targetAudience)
                        .setNotBefore(Date.from(Instant.now()));

        LOGGER.info("\tCertificate Subject: " + cert.getSubjectDN());
        String jws = jwtb.signWith(privKey, SignatureAlgorithm.RS256).compact();
        resultHandler.handle(Future.succeededFuture(jws));

    }

    private void executeRequest(Future<MultiMap> form, Future<URL> url, Handler<AsyncResult<String>> next){
        CompositeFuture.all(url, form).onComplete( prepareResult -> {
            if (prepareResult.succeeded()) {
                breaker.<HttpResponse<Buffer>>execute(future -> {
                    webClient
                            .post(443, url.result().getHost(), url.result().getPath() + "/token")
                            .ssl(true)
                            .sendForm(form.result(), tokenReply -> {
                                if (tokenReply.failed() ||  tokenReply.result().statusCode() != 200) {
                                    LOGGER.info("DAT could not be retrieved. Retrying...");
                                    future.fail(tokenReply.cause());
                                } else {
                                    future.complete(tokenReply.result());
                                }
                            });
                })
                        .onComplete(ar -> {
                            if (ar.succeeded()) {
                                JsonObject jwtJson = ar.result().bodyAsJsonObject();
                                String dynamicAttributeToken = jwtJson.getString("access_token");
                                LOGGER.info("Dynamic Attribute Token: " + dynamicAttributeToken);
                                verifyJWT(new JsonObject().put("jwt", dynamicAttributeToken), ac -> {
                                    if (ac.succeeded()) {
                                        next.handle(Future.succeededFuture(dynamicAttributeToken));
                                    } else {
                                        LOGGER.error(ac.cause());
                                        next.handle(Future.failedFuture(ac.cause()));
                                    }
                                });
                            } else {
                                LOGGER.error(ar.cause());
                                next.handle(Future.failedFuture(ar.cause()));
                            }
                        });
            } else {

            }
        });
    }

    /***
     * Split string ever len chars and return string array
     * @param src
     * @param len
     * @return
     */
    public static String[] split(String src, int len) {
        String[] result = new String[(int)Math.ceil((double)src.length()/(double)len)];
        for (int i=0; i<result.length; i++)
            result[i] = src.substring(i*len, Math.min(src.length(), (i+1)*len));
        return result;
    }

    /***
     * Beautyfies Hex strings and will generate a result later used to create the client id (XX:YY:ZZ)
     * @param hexString HexString to be beautified
     * @return beautifiedHex result
     */
    private String beautifyHex(String hexString) {
        String[] splitString = split(hexString, 2);
        StringBuffer sb = new StringBuffer();
        for(int i =0; i < splitString.length; i++) {
            sb.append(splitString[i]);
            sb.append(":");
        }
        return sb.toString();
    }

    /**
     * Convert byte array to hex without any dependencies to libraries.
     * @param num
     * @return
     */
    private String byteToHex(byte num) {
        char[] hexDigits = new char[2];
        hexDigits[0] = Character.forDigit((num >> 4) & 0xF, 16);
        hexDigits[1] = Character.forDigit((num & 0xF), 16);
        return new String(hexDigits);
    }

    /**
     * Encode a byte array to an hex string
     * @param byteArray
     * @return
     */
    private String encodeHexString(byte[] byteArray) {
        StringBuffer hexStringBuffer = new StringBuffer();
        for (int i = 0; i < byteArray.length; i++) {
            hexStringBuffer.append(byteToHex(byteArray[i]));
        }
        return hexStringBuffer.toString();
    }
}
