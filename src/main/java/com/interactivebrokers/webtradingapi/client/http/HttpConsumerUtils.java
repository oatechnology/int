package com.interactivebrokers.webtradingapi.client.http;

import java.io.IOException;
import java.io.PrintStream;
import java.util.HashMap;
import java.util.Map;

import org.apache.http.Header;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpMessage;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.type.MapType;

class HttpConsumerUtils {

    private static final Logger logger = LoggerFactory.getLogger(HttpConsumerUtils.class);

    public static Map<String, Object> getResponseMap(String response) {
        ObjectMapper mapper = new ObjectMapper();
        MapType type = mapper.getTypeFactory().constructMapType(Map.class, String.class, Object.class);
        Map<String, Object> map = new HashMap<>();
        try {
            map = mapper.readValue(response, type);
        } catch (IOException e) {
            logger.error("can't create map from body: {}, error: {}", e, response, e.getMessage());
        }
        return map;
    }

    private static void printHeaders(HttpMessage message, PrintStream ps) {
        for (Header h : message.getAllHeaders()) {
            ps.print(h.getName() + ": " + h.getValue());
        }
        ps.println();
    }

    public synchronized static void printHttp(HttpResponse response, String entity) {
        System.err.println("\n--- RESPONSE BEGIN ----------------------------------------------");
        System.err.println(response);
        System.err.println(entity);
        System.err.println("--- RESPONSE END ------------------------------------------------\n");
    }

    public synchronized static void printHttp(HttpRequest post) {
        System.err.println("\n--- REQUEST BEGIN ----------------------------------------------");
        System.err.println(post.getRequestLine());
        printHeaders(post, System.err);
        if (post instanceof HttpEntityEnclosingRequest)
            System.err.println(((HttpEntityEnclosingRequest) post).getEntity());
        System.err.println("--- REQUEST END ------------------------------------------------\n");
        System.err.flush();
    }

}
