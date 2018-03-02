package com.interactivebrokers.webtradingapi.client.http;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Map;
import java.util.Set;

import javax.crypto.spec.DHParameterSpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpEntityEnclosingRequestBase;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.interactivebrokers.webtradingapi.client.oauth.OAuthUtils;
import com.interactivebrokers.webtradingapi.client.oauth.SecuredRequest;
import com.interactivebrokers.webtradingapi.client.start.ThirdPartyConsumer;
import com.interactivebrokers.webtradingapi.client.utils.KeyUtils;
import com.interactivebrokers.webtradingapi.client.utils.SignatureBaseStringBuilder;

public class HttpConsumerClient {

    private final static Logger logger = LoggerFactory.getLogger(HttpConsumerClient.class);
    private static final String AUTH_XYZ_INIT = "/auth/xyz/init";
    private static final String AUTH_XYZ_PROOF = "/auth/xyz/proof";
    private static final String OAUTH_CONSUMER_ACCESS_TOKEN = "/oauth/access_token";
    private static final String OAUTH_CONSUMER_REQUEST_TOKEN = "/oauth/request_token";
    private static final String OAUTH_LIVE_SESSION_TOKEN = "/oauth/live_session_token";
    private static final String OAUTH_VERIFY_TOKEN = "/oauth/verify_token";
    private static final String OAUTH_TOKEN_INFO = "/oauth/token_info";
    private static final String OAUTH_TOKEN_AGREEMENT = "/oauth/token_agreement";
    static final String HTTP_POST = "POST";

    private static final int CONNECTION_TIMEOUT_MS = 10 * 1000;

    private final String baseUrl;
    private final String oauthBaseUrl;
    private final ThirdPartyConsumer consumer;
    private boolean debugHttp = false;
    private final BigInteger dhRandom = new BigInteger(200, new SecureRandom());
    private final BasicCookieStore cookieStore = new BasicCookieStore();

    private final RequestConfig requestConfig = RequestConfig.custom()
            .setConnectTimeout(CONNECTION_TIMEOUT_MS)
            .setSocketTimeout(CONNECTION_TIMEOUT_MS)
            .build();
    private final CloseableHttpClient client = HttpClients.custom()
            .setDefaultRequestConfig(requestConfig)
            .setDefaultCookieStore(cookieStore).build();

    public HttpConsumerClient(ThirdPartyConsumer consumer, String baseUrl, String oauthBaseUrl) {
        this.consumer = consumer;
        this.baseUrl = baseUrl;
        this.oauthBaseUrl = oauthBaseUrl;
    }

    public ThirdPartyConsumer getConsumer() {
        return consumer;
    }

    public BigInteger getDhRandom() {
        return dhRandom;
    }

    public Map<String, Object> sendXYZInit(String ahex, String username) throws IOException {

        String endpointUrl = oauthBaseUrl + AUTH_XYZ_INIT;
        HttpUriRequest uriRequest = RequestBuilder.post()
                .setUri(endpointUrl)
                .addParameter("A", ahex)
                .addParameter("user", username)
                .build();

        logger.debug("sending POST to: {}, A {}, user {}", endpointUrl, ahex, username);
        if (debugHttp) {
            HttpConsumerUtils.printHttp(uriRequest);
        }

        String response = client.execute(uriRequest, this::getResponseString);

        Map<String, Object> map = HttpConsumerUtils.getResponseMap(response);
        logger.debug("received response: {}", map);
        logger.debug("received cookies: {}", cookieStore.getCookies());
        return map;
    }

    public Map<String, Object> sendXYZProof(String M1hex, String mode) throws IOException {

        String endpointUrl = oauthBaseUrl + AUTH_XYZ_PROOF;
        HttpUriRequest uriRequest = RequestBuilder.post()
                .setUri(endpointUrl)
                .addParameter("M1", M1hex)
                .addParameter("mode", mode)
                .build();

        logger.debug("sending POST to: {}, M1 {}", endpointUrl, M1hex);
        if (debugHttp) {
            HttpConsumerUtils.printHttp(uriRequest);
        }

        String response = client.execute(uriRequest, this::getResponseString);

        Map<String, Object> map = HttpConsumerUtils.getResponseMap(response);
        logger.debug("received response: {}", map);
        return map;
    }

    public String sendVerify(String token) throws IOException {
        final RequestBuilder builder = RequestBuilder.post().addParameter("signature", "OAuth Consumer Test System");
        final HttpUriRequest uriRequest = buildRequest(builder, OAUTH_VERIFY_TOKEN, token);
        final Map<String, Object> map = sendAndCheckForError(uriRequest);
        logger.debug("received response: {}", map);

        return (String) map.get("oauth_verifier");
    }

    public void requestTokenInfo(String token) throws IOException {
        final HttpUriRequest uriRequest = buildRequest(RequestBuilder.post(), OAUTH_TOKEN_INFO, token);
        sendAndCheckForError(uriRequest);
    }

    public void requestTokenAgreement(String token) throws IOException {
        final HttpUriRequest uriRequest = buildRequest(RequestBuilder.get(), OAUTH_TOKEN_AGREEMENT, token);
        sendAndCheckForError(uriRequest);
    }

    private HttpUriRequest buildRequest(RequestBuilder input, String endpoint, String token) {
        final String endpointUrl = oauthBaseUrl + endpoint;
        return input.setUri(endpointUrl).addParameter("oauth_token", token).build();
    }

    private Map<String, Object> sendAndCheckForError(HttpUriRequest uriRequest)
            throws IOException {

        logger.debug("sending {}", uriRequest.getURI());
        if (debugHttp) {
            HttpConsumerUtils.printHttp(uriRequest);
        }

        String response = client.execute(uriRequest, this::getResponseString);

        Map<String, Object> map = HttpConsumerUtils.getResponseMap(response);
        logger.debug("received response: {}", map);

        final String error = (String) map.get("error");
        if (error != null) {
            throw new IOException(error);
        }

        return map;
    }

    public Map<String, Object> sendConsumerAccessRequest(String token, String verifier) throws IOException {

        Set<HttpParam> param = OAuthUtils.getOAuthCommonParams(consumer);
        param.add(new HttpParam("oauth_token", token));
        param.add(new HttpParam("oauth_verifier", verifier));

        final String endpointUrl = baseUrl + OAUTH_CONSUMER_ACCESS_TOKEN;
        final String oauthSignature;
        final String signatureBase;
        try {
            signatureBase = HttpUtils.generateSignatureBase(null, param, endpointUrl);
            oauthSignature = OAuthUtils.getOAuthSignature(consumer, signatureBase);
        } catch (Exception e) {
            logger.error("couldn't create oauth signature: {}", e, e.getMessage());
            return null;
        }

        logger.debug("oauth_signature: {}", oauthSignature);
        param.add(new HttpParam("oauth_signature", oauthSignature));
        param.add(new HttpParam("realm", consumer.getRealmName()));

        String authHeader = "OAuth " + HttpParam.serialize(param);
        logger.debug("authorize header: {}", authHeader);

        HttpPost post = new HttpPost(endpointUrl);
        post.addHeader("Authorization", authHeader);
        // we add the signature base string to the request for debugging purposes
        //post.addHeader("SBS", signatureBase);
        logger.debug("sending POST to: " + endpointUrl);
        if (debugHttp) {
            HttpConsumerUtils.printHttp(post);
        }

        String response = client.execute(post, this::getResponseString);

        Map<String, Object> map = HttpConsumerUtils.getResponseMap(response);
        logger.debug("received response: {}", map);

        return map;
    }

    public String sendConsumerRequestToken() throws IOException {

        String ret = "";
        Set<HttpParam> param = OAuthUtils.getOAuthCommonParams(consumer);
        param.add(new HttpParam("oauth_callback", "oob"));
        final String url = baseUrl + OAUTH_CONSUMER_REQUEST_TOKEN;
        final String oauthSignature;
        final String signatureBase;
        try {
            signatureBase = HttpUtils.generateSignatureBase(null, param, url);
            oauthSignature = OAuthUtils.getOAuthSignature(consumer, signatureBase);
        } catch (Exception e) {
            logger.error("couldn't create oauth signature: {}", e, e.getMessage());
            return ret;
        }

        logger.debug("oauth_signature: {}", oauthSignature);
        param.add(new HttpParam("oauth_signature", oauthSignature));
        param.add(new HttpParam("realm", consumer.getRealmName()));
        String authHeader = "OAuth " + HttpParam.serialize(param);
        logger.debug("authorize header: {}", authHeader);

        String endpointUrl = baseUrl + OAUTH_CONSUMER_REQUEST_TOKEN;
        HttpPost post = new HttpPost(endpointUrl);
        post.addHeader("Authorization", authHeader);

        logger.debug("sending POST to: " + endpointUrl);
        if (debugHttp) {
            HttpConsumerUtils.printHttp(post);
        }

        String response = client.execute(post, this::getResponseString);

        Map<String, Object> map = HttpConsumerUtils.getResponseMap(response);
        logger.debug("received response: {}", map);
        return (String) map.get("oauth_token");

    }

    public Map<String, Object> sendLiveSessionTokenRequest(String accessToken, byte[] tokenSecret)
            throws IOException, URISyntaxException, GeneralSecurityException {

        logger.debug("access token: {}", accessToken);
        logger.debug("token secret: {}", Base64.encodeBase64String(tokenSecret));

        DHParameterSpec spec = consumer.getDhSpec();

        BigInteger clientChallenge = spec.getG().modPow(dhRandom, spec.getP()); // A = g^a mod P
        logger.debug("a: {}", dhRandom.toString(10));
        logger.debug("A: {}", clientChallenge.toString(10));

        Set<HttpParam> param = OAuthUtils.getOAuthCommonParams(consumer, accessToken);
        param.add(new HttpParam("diffie_hellman_challenge", clientChallenge.toString(16)));
        final String url = baseUrl + OAUTH_LIVE_SESSION_TOKEN;
        final String signatureBase = HttpUtils.generateSignatureBase(tokenSecret, param, url);
        final String oauthSignature = OAuthUtils.getOAuthSignature(consumer, signatureBase);

        logger.debug("oauth_signature: {}", URLDecoder.decode(oauthSignature, HttpUtils.UTF_8));
        param.add(new HttpParam("oauth_signature", oauthSignature));
        param.add(new HttpParam("realm", consumer.getRealmName()));

        String authHeader = "OAuth " + HttpParam.serialize(param);
        logger.debug("authorize header: {}", authHeader);

        String endpointUrl = baseUrl + OAUTH_LIVE_SESSION_TOKEN;
        HttpPost post = new HttpPost(endpointUrl);
        post.addHeader("Authorization", authHeader);
        // we add the signature base string to the request for debugging purposes
        //post.addHeader("SBS", signatureBase);
        logger.debug("sending POST to: " + endpointUrl);
        if (debugHttp) {
            HttpConsumerUtils.printHttp(post);
        }

        String response = client.execute(post, this::getResponseString);

        Map<String, Object> map = HttpConsumerUtils.getResponseMap(response);
        logger.debug("received response: {}", map);
        return map;
    }

    private String getResponseString(HttpResponse res) throws IOException {

        if (res.getEntity() == null) {
            logger.error("empty entity in response {}", res);
            return "";
        }

        final String entity = EntityUtils.toString(res.getEntity());

        if (debugHttp)
            HttpConsumerUtils.printHttp(res, entity);

        return entity;
    }

    private RequestBuilder getBuilder(final SecuredRequest request) {
        final String uri = baseUrl + request.api;

        if ("GET".equals(request.method))
            return RequestBuilder.get(uri);

        if ("POST".equals(request.method))
            return RequestBuilder.post(uri);

        if ("DELETE".equals(request.method))
            return RequestBuilder.delete(uri);

        if ("PUT".equals(request.method))
            return RequestBuilder.put(uri);

        throw new RuntimeException("Unsupported method " + request.method);
    }

    private HttpUriRequest getRequest(final SecuredRequest request) {
        final RequestBuilder builder = getBuilder(request);

        if (request.payload != null) {
            for (Map.Entry<String, String> entry : request.payload.entrySet())
                builder.addParameter(entry.getKey(), entry.getValue());
        }

        return builder.build();
    }

    private String getWwwFormUrlEncodedBody(HttpUriRequest uriRequest) throws IOException {

        if (!(uriRequest instanceof HttpEntityEnclosingRequestBase)) {
            return "";
        }

        HttpEntityEnclosingRequestBase entityUriRequest = (HttpEntityEnclosingRequestBase) uriRequest;
        final HttpEntity entity = entityUriRequest.getEntity();
        final InputStream content = entity.getContent();

        final byte[] contents = new byte[content.available()];
        content.read(contents);

        final String payload = new String(contents, "UTF-8");
        logger.debug("payload is: {}", payload);

        return payload;
    }

    public void sendProtectedResourceRequest(String accessToken, byte[] lst, SecuredRequest req)
            throws IOException, URISyntaxException {
        final HttpUriRequest uriRequest = getRequest(req);
        final String body = getWwwFormUrlEncodedBody(uriRequest);

        final Set<HttpParam> params = OAuthUtils.getOAuthParametersWithMethod(consumer, "HMAC-SHA256");
        params.add(new HttpParam("oauth_token", accessToken));

        final SignatureBaseStringBuilder builder = new SignatureBaseStringBuilder(
                uriRequest.getURI().toString(),
                req.method.toUpperCase(),
                HttpParam.serialize(params), body);

        final String baseString = builder.getSignatureBaseString();

        logger.debug("live token : " + Base64.encodeBase64String(lst));
        logger.debug("base string: " + baseString);

        final byte[] signature = KeyUtils.hmacSHA256Sign(lst, baseString.getBytes());
        final String oauthSignature;
        try {
            oauthSignature = URLEncoder.encode(Base64.encodeBase64String(signature), HttpUtils.UTF_8);
        } catch (Exception e) {
            logger.error("couldn't create oauth signature: {}", e, e.getMessage());
            return;
        }

        params.add(new HttpParam("oauth_signature", oauthSignature));
        params.add(new HttpParam("realm", consumer.getRealmName()));

        final String authHeader = HttpParam.serialize(params);
        uriRequest.addHeader("Authorization", "OAuth " + authHeader);

        logger.debug("oauth_signature: {}", oauthSignature);
        logger.debug("authorize header: {}", authHeader);
        logger.debug("sending {} to: {}", req.method, uriRequest.getURI());

        if (debugHttp) {
            HttpConsumerUtils.printHttp(uriRequest);
        }

        final String response = client.execute(uriRequest, res -> handleResourceResponse(uriRequest, res));

        logger.debug("response: {}", response);

    }

    private String handleResourceResponse(HttpUriRequest uriRequest, HttpResponse res) throws IOException {
        final int statusCode = res.getStatusLine().getStatusCode();
        if (statusCode >= 400) {
            final String message = "Received error response for " + uriRequest + ": " + statusCode;
            if (statusCode >= 500) {
                logger.error(message);
            } else {
                logger.warn(message);
            }
        }

        return getResponseString(res);
    }

    public void setDebugHttp(boolean value) {
        this.debugHttp = value;
    }

}
