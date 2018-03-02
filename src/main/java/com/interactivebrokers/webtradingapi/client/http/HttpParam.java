package com.interactivebrokers.webtradingapi.client.http;

import java.util.Set;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.http.NameValuePair;

public class HttpParam implements NameValuePair, Comparable<HttpParam> {

    private final String name;
    private final String value;

    public HttpParam(String name, String value) {
        this.name = name;
        this.value = value;
    }

    public static String serialize(Set<HttpParam> param) {
        StringBuilder sb = new StringBuilder();
        for (HttpParam p : param) {
            p.append(sb).append(", ");
        }
        if (sb.length() > 2) {
            sb.setLength(sb.length() - 2);
        }
        return sb.toString();
    }

    private StringBuilder append(StringBuilder sb) {
        return sb.append(name).append("=\"").append(value).append("\"");
    }

    @Override
    public int compareTo(HttpParam o) {
        return name.compareTo(o.name);
    }

    @Override
    public boolean equals(Object o) {
        if (o == null) {
            return false;
        }
        if (o == this) {
            return true;
        }
        if (o.getClass() != getClass()) {
            return false;
        }
        HttpParam rhs = (HttpParam) o;
        return new EqualsBuilder().append(name, rhs.name).isEquals();
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public String getValue() {
        return value;
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder().append(name).append(value).hashCode();
    }

    @Override
    public String toString() {
        return String.format("param[name=%s,value=%s]", name, value);
    }

}
