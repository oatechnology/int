package com.interactivebrokers.webtradingapi.client.http;

import java.net.URISyntaxException;
import java.util.Set;

import com.interactivebrokers.webtradingapi.client.utils.SignatureBaseStringBuilder;

public class HttpUtils {

    public static final String UTF_8 = "UTF-8";

    public static String generateSignatureBase(byte[] prepend, Set<HttpParam>
            parameters, String uri) throws URISyntaxException {
        final String header = HttpParam.serialize(parameters);
        final SignatureBaseStringBuilder builder =
                new SignatureBaseStringBuilder(uri, HttpConsumerClient.HTTP_POST, header);

        builder.setPrefix(prepend);
        return builder.getSignatureBaseString();
    }

    public static String stripQuotesAndSpace(final String original) {
        String value = original.trim();

        if (value.isEmpty())
            return value;

        if (value.charAt(0) == '"')
            value = value.substring(1);

        final int length = value.length();
        if (value.charAt(length - 1) == '"')
            value = value.substring(0, length - 1);

        return value;
    }

}
