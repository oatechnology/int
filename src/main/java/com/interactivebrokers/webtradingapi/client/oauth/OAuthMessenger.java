package com.interactivebrokers.webtradingapi.client.oauth;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;
import java.util.Map;
import java.util.Scanner;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.interactivebrokers.webtradingapi.client.http.HttpConsumerClient;
import com.interactivebrokers.webtradingapi.client.start.ThirdPartyConsumer;
import com.interactivebrokers.webtradingapi.client.utils.KeyUtils;
import com.interactivebrokers.webtradingapi.client.utils.LiveSessionToken;

public class OAuthMessenger {

    private final static Logger logger = LoggerFactory.getLogger(OAuthMessenger.class);

    public static Pair<String, String> obtainAccessToken(
            HttpConsumerClient client, String username, String password, String mode)
            throws IOException, GeneralSecurityException {

        final String token = client.sendConsumerRequestToken();
        if (token == null || token.isEmpty()) {
            logger.error("Invalid request token, aborting authentication");
            return null;
        }

        logger.debug("received token: {}", token);

        return obtainAccessTokenFromRequestToken(client, username, password, mode, token);
    }

    private static Pair<String, String> obtainAccessTokenFromRequestToken(HttpConsumerClient client, String username,
            String password, String mode, String token) throws IOException, GeneralSecurityException {

        if (!runAuthentication(client, username, password, mode)) {
            logger.error("Authentication failed");
            return null;
        }

        client.requestTokenInfo(token);
        client.requestTokenAgreement(token);

        final String verifier = client.sendVerify(token);
        if (verifier == null || verifier.isEmpty()) {
            logger.error("Failed to verify token {} for {}", token, username);
            return null;
        }

        logger.debug("received verifier: {}", verifier);

        final Map<String, Object> res = client.sendConsumerAccessRequest(token, verifier);
        final String accessToken = getString(res, "oauth_token");
        final String tokenSecret = getString(res, "oauth_token_secret");
        if (tokenSecret.isEmpty()) {
            logger.error("empty token secret");
            return null;
        }

        final byte[] data = Base64.decodeBase64(tokenSecret);
        final byte[] decrypted = KeyUtils.decrypt(client.getConsumer().getEncryptionKeyPrivate(), data);
        logger.debug("oauth_token        " + accessToken);
        logger.debug("encoded_secret     " + tokenSecret);
        logger.debug("oauth_token_secret " + Base64.encodeBase64String(decrypted));

        return new ImmutablePair<>(accessToken, tokenSecret);
    }

    private static Boolean runAuthentication(HttpConsumerClient client,
            String username, String password, String mode) throws IOException {
        Boolean result = false;
        Scanner sc = new Scanner(System.in);

        if (username == null || username.isEmpty()) {
            System.out.println("username: ");
            username = sc.nextLine();
        }

        ClientAuthenticationContext ctx = new ClientAuthenticationContext();
        Map<String, Object> map = client.sendXYZInit(ctx.getAhex(), username);
        String N = getString(map, "N");
        String g = getString(map, "g");
        String B = getString(map, "B");
        String s = getString(map, "s");

        if (N.isEmpty() || g.isEmpty() || B.isEmpty()) {
            logger.error("invalid authentication parameters, username probably unknown");
        } else {
            ctx.setInitParams(N, g, B, s);
            if (password == null || password.isEmpty()) {
                System.out.println("password: ");
                password = sc.nextLine();
            }
            ctx.calculateProof(username, password);
            map = client.sendXYZProof(ctx.getM1hex(), mode);
            result = !getString(map, "M2").isEmpty() && "ok".equals(getString(map, "r"));
        }
        sc.close();
        return result;
    }

    public static byte[] getLiveSessionToken(HttpConsumerClient client, String accessToken, String secret)
            throws GeneralSecurityException, IOException, URISyntaxException {
        byte[] tokenSecret = decryptSecret(client, secret);

        Map<String, Object> map = client.sendLiveSessionTokenRequest(accessToken, tokenSecret);

        String dhResponse = getString(map, "diffie_hellman_response");
        if (dhResponse == null || dhResponse.isEmpty()) {
            logger.error("no diffie hellman response for {}, something wrong with our request", accessToken);
            return null;
        }

        String serverLstSign = getString(map, "live_session_token_signature");

        // 'B' and 'a' follow standard DH naming:
        // a -> client secret
        // B -> server response
        final ThirdPartyConsumer consumer = client.getConsumer();
        final BigInteger a = client.getDhRandom();
        final BigInteger B = new BigInteger(dhResponse, 16);

        final BigInteger p = consumer.getDhSpec().getP();
        final BigInteger g = consumer.getDhSpec().getG();
        final BigInteger A = g.modPow(a, p);
        final BigInteger K = B.modPow(a, p);

        final byte[] livetoken = LiveSessionToken.generate(consumer.getDhSpec(), B, a, tokenSecret);
        final byte[] signature = LiveSessionToken.signature(livetoken, consumer.getConsumerKey());
        final String calculated = Hex.encodeHexString(signature);
        final String encodedLST = Base64.encodeBase64String(livetoken);

        logger.debug("secret integer   (a) : {}", a);
        logger.debug("request integer  (A) : {}", A);
        logger.debug("response integer (B) : {}", B);
        logger.debug("shared secret    (K) : {}", K);
        logger.debug("shared secret bytes  : {}", Base64.encodeBase64String(K.toByteArray()));
        logger.debug("token secret bytes   : {}", Base64.encodeBase64String(tokenSecret));
        logger.debug("client signature     : {}", calculated);
        logger.debug("server signature     : {}", serverLstSign);
        logger.debug("access token         : {}", accessToken);
        logger.debug("live session token   : {}", encodedLST);

        return calculated.equals(serverLstSign) ? livetoken : null;
    }

    private static byte[] decryptSecret(HttpConsumerClient client, String encoded) throws GeneralSecurityException {

        final ThirdPartyConsumer consumer = client.getConsumer();
        final byte[] secretBytes = Base64.decodeBase64(encoded);
        return KeyUtils.decrypt(consumer.getEncryptionKeyPrivate(), secretBytes);
    }

    private static String getString(Map<String, Object> map, String key) {
        return (String) map.getOrDefault(key, "");
    }

}
