package com.interactivebrokers.webtradingapi.client.oauth;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

public class SecuredRequest {
    @JsonProperty("api")
    public String api;
    @JsonProperty("method")
    public String method;
    @JsonProperty("payload")
    public Map<String, String> payload;

    /**
     * Tries to load the request file from the given absolute path, falls back to a classloader path.
     */
    public static SecuredRequest load(String path) throws IOException {
    	InputStream reader =  SecuredRequest.class.getClassLoader().getResourceAsStream(path);

        return new ObjectMapper().readValue(reader, SecuredRequest.class);
    }

    public SecuredRequest() {
    }

    private SecuredRequest(String method, String api, Map<String, String> payload) {
        this.api = api;
        this.method = method;
        this.payload = payload;
    }

    @Override
    public String toString() {
        try {
            return new ObjectMapper().writeValueAsString(this);
        } catch (JsonProcessingException e) {
            return e.getMessage();
        }
    }
}
