package com.interactivebrokers.webtradingapi.client.oauth;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Calendar;
import java.util.Set;
import java.util.TimeZone;
import java.util.TreeSet;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.RandomUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.interactivebrokers.webtradingapi.client.http.HttpParam;
import com.interactivebrokers.webtradingapi.client.http.HttpUtils;
import com.interactivebrokers.webtradingapi.client.start.ThirdPartyConsumer;
import com.interactivebrokers.webtradingapi.client.utils.KeyUtils;

public class OAuthUtils {

    private static final Logger logger = LoggerFactory.getLogger(OAuthUtils.class);

    public static String getOAuthSignature(final ThirdPartyConsumer consumer, final String signatureBaseString)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, UnsupportedEncodingException {
        byte[] sigData = KeyUtils.createSignatureRsaSha256(consumer.getSignatureKeyPrivate(), signatureBaseString);
        String signature = URLEncoder.encode(Base64.encodeBase64String(sigData), HttpUtils.UTF_8);
        logger.debug("private_key: {}", Base64.encodeBase64String(consumer.getSignatureKeyPrivate().getEncoded()));
        logger.debug("base_string: {}", signatureBaseString);
        logger.debug("signature:   {}", Base64.encodeBase64String(sigData));
        return signature;
    }

    public static Set<HttpParam> getOAuthCommonParams(ThirdPartyConsumer consumer, String accessToken) {
        Set<HttpParam> ret = getOAuthCommonParams(consumer);
        ret.add(new HttpParam("oauth_token", accessToken));
        return ret;
    }

    public static Set<HttpParam> getOAuthCommonParams(ThirdPartyConsumer consumer) {
        return getOAuthParametersWithMethod(consumer, consumer.getSignatureMethod());
    }

    public static Set<HttpParam> getOAuthParametersWithMethod(ThirdPartyConsumer consumer, String method) {
        Set<HttpParam> ret = new TreeSet<>();

        Calendar cl = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
        Long timestamp = cl.getTimeInMillis() / 1000;

        final byte[] nonce = RandomUtils.nextBytes(10);

        ret.add(new HttpParam("oauth_consumer_key", consumer.getConsumerKey()));
        ret.add(new HttpParam("oauth_timestamp", timestamp.toString()));
        ret.add(new HttpParam("oauth_signature_method", method));
        ret.add(new HttpParam("oauth_nonce", Hex.encodeHexString(nonce)));

        return ret;
    }

}
