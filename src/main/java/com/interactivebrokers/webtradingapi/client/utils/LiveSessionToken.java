package com.interactivebrokers.webtradingapi.client.utils;

import java.math.BigInteger;

import javax.crypto.spec.DHParameterSpec;

public final class LiveSessionToken {

    /**
     * Generates the live session token as defined in specs: HMAC_SHA1(K, access_token_secret)
     * <p>
     * Where K = shared diffie hellman secret.
     * access_token_secret = returned on valid /access_token request.
     *
     * @param spec              Diffie-hellman specs generated from g(en) and p(rime) known before hand.
     * @param dhExchange        The other's side key.
     *                          Client challenge (A) or
     *                          Server response (B)
     * @param accessTokenSecret from /access_token response
     * @return the live session token where LST = HMAC_SHA1(K (A or B), access_token_secret)
     */
    public static byte[] generate(DHParameterSpec spec,
            BigInteger dhExchange,
            BigInteger random,
            byte[] accessTokenSecret) {

        final BigInteger prime = spec.getP();
        final BigInteger K = dhExchange.modPow(random, prime); // shared secret
        return KeyUtils.hmacSHA1Sign(K.toByteArray(), accessTokenSecret);
    }

    /**
     * @param lst         Live Session Token generated by {@link #generate}
     * @param consumerKey
     * @return byte[] signature
     */
    public static byte[] signature(byte[] lst, String consumerKey) {
        return KeyUtils.hmacSHA1Sign(lst, consumerKey.getBytes());
    }

}
