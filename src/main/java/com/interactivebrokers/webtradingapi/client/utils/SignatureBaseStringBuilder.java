package com.interactivebrokers.webtradingapi.client.utils;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import org.apache.commons.codec.binary.Hex;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URIBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.interactivebrokers.webtradingapi.client.http.HttpParam;
import com.interactivebrokers.webtradingapi.client.http.HttpUtils;

public class SignatureBaseStringBuilder {

    private final static Logger logger = LoggerFactory.getLogger(SignatureBaseStringBuilder.class);

    private URI uri;

    private String method;

    private byte[] prefix;

    private List<NameValuePair> parameters;

    /**
     * no preprocessing should occur (in particular, url decoding) before use.
     */
    public SignatureBaseStringBuilder(final String uri, final String method, final String authorizeHeader)
            throws URISyntaxException {

        this.uri = new URI(Objects.requireNonNull(uri));
        this.method = Objects.requireNonNull(method).toUpperCase();

        validateURI();

        parameters = new ArrayList<>();
        parseAuthorizeHeader(Objects.requireNonNull(authorizeHeader));

        final String query = this.uri.getRawQuery();
        if (query != null) {
            parseQueryParameters(query);
        }
    }

    public SignatureBaseStringBuilder(final String uri, final String method,
            final String authorizeHeader, final String body) throws URISyntaxException {
        this(uri, method, authorizeHeader);

        parseFormUrlEncodedBody(body);
    }

    private String getOAuthRequestURL() throws URISyntaxException {
        final URIBuilder builder = new URIBuilder();
        builder.setHost(uri.getHost().toLowerCase());

        final String scheme = uri.getScheme().toLowerCase();
        final int port = uri.getPort();
        if (scheme.equals("https")) {
            if (port != 443)
                builder.setPort(port);
        } else if (scheme.equals("http")) {
            if (port != 80)
                builder.setPort(port);
        }

        builder.setScheme(scheme);
        builder.setPath(uri.getPath());

        return builder.build().toString();
    }

    public String getSignatureBaseString() throws URISyntaxException {
        try {
            return (prefix == null ? "" : Hex.encodeHexString(prefix))
                    + method
                    + "&" + URLEncoder.encode(getOAuthRequestURL(), HttpUtils.UTF_8)
                    + "&" + URLEncoder.encode(getNormalizedRequestParameters(), HttpUtils.UTF_8);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    private void parseQueryParameters(String query) {
        int begin = 0;
        while (begin < query.length()) {
            int end = query.indexOf('&', begin);
            if (end == -1) {
                end = query.length();
            }

            final int equals = query.indexOf('=', begin);
            if (equals != -1 && equals < end) {
                final String key = query.substring(begin, equals);
                final String value = query.substring(equals + 1, end);
                parameters.add(new HttpParam(key, value));
            }

            begin = end + 1;
        }

    }

    private String getNormalizedRequestParameters() {
        String result = "";

        Collections.sort(parameters, (lhs, rhs) -> {
            final int name = lhs.getName().compareTo(rhs.getName());
            return name == 0 ? lhs.getValue().compareTo(rhs.getValue()) : name;
        });

        for (NameValuePair pair : parameters) {
            if (pair.getName().equals("realm"))
                continue;

            if (!result.isEmpty())
                result += "&";

            result += pair.getName() + "=" + pair.getValue();
        }

        return result;
    }

    public void setPrefix(byte[] prefix) {
        this.prefix = prefix;
    }

    private void validateURI() throws URISyntaxException {
        final String authority = uri.getRawAuthority();

        if (authority == null || authority.isEmpty())
            throw new URISyntaxException(uri.toString(), "URI contains an empty authority");

        final String scheme = uri.getScheme();

        if (scheme == null || scheme.isEmpty())
            throw new URISyntaxException(uri.toString(), "URI contains an empty scheme");
    }

    private void parseFormUrlEncodedBody(String body) {

        if (body.isEmpty())
            return;

        String[] bodyParameters = body.split("&");
        for (String pair : bodyParameters) {
            final String[] fields = pair.split("=");
            if (fields.length != 2) {
                logger.warn("invalid key/value in body: {}  {}  {}  {}", pair, uri, method, body);
                continue;
            }
            try {
                final String key = URLDecoder.decode(fields[0], HttpUtils.UTF_8);
                final String value = URLDecoder.decode(fields[1], HttpUtils.UTF_8);
                parameters.add(new HttpParam(key, value));
            } catch (UnsupportedEncodingException e) {
                // not possible, just java being java
            }
        }
    }

    private void parseAuthorizeHeader(String header) {

        if (header.startsWith("OAuth ")) {
            header = header.substring(6);
        }

        final String[] pairs = header.split(",");

        for (final String pair : pairs) {
            final String[] keyValue = pair.split("=");
            if (keyValue.length != 2) {
                logger.warn("invalid key/value pair '{}' in header '{}'", pair, header);
                continue;
            }

            final String key = keyValue[0].trim();
            if ("realm".equals(key))
                continue;

            if ("oauth_signature".equals(key))
                continue;

            final String value = HttpUtils.stripQuotesAndSpace(keyValue[1]);

            parameters.add(new HttpParam(key, value));
        }
    }

}
