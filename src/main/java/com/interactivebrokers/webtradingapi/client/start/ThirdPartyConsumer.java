package com.interactivebrokers.webtradingapi.client.start;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Objects;

import javax.crypto.spec.DHParameterSpec;

import org.apache.commons.lang3.builder.ToStringBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.aop.ThrowsAdvice;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.interactivebrokers.webtradingapi.client.utils.KeyUtils;
import com.interactivebrokers.webtradingapi.client.utils.PKCS3;

public class ThirdPartyConsumer {

    private final String signatureMethod;
    private final String consumerKey;
    private final String realmName;
    private final DHParameterSpec dhSpec;
    private final PrivateKey signatureKeyPrivate;
    private final PrivateKey encryptionKeyPrivate;

    private static final Logger logger = LoggerFactory.getLogger(ThirdPartyConsumer.class);

    public ThirdPartyConsumer(String pathToConsumerFilesJson)
            throws IOException, InvalidKeySpecException, PKCS3.InvalidEncodingException {
    	InputStream reader = this.getClass().getClassLoader().getResourceAsStream(pathToConsumerFilesJson);
 
    	if(reader == null)
				throw new NullPointerException("The file path is null");
			 
    	 
    	  
        //final FileReader reader = new FileReader(new Fil);
        final Path root = Paths.get(pathToConsumerFilesJson).getParent();
        logger.debug("loading consumer from directory {}", root.toString());
 
        final ConsumerFilesJson json = new ObjectMapper().readValue(reader, ConsumerFilesJson.class);

        signatureMethod = Objects.requireNonNull(json.signatureMethod);
        consumerKey = Objects.requireNonNull(json.consumerKey);
        realmName = Objects.requireNonNull(json.realmName);

        final String dhPath = Paths.get(root.toString(), json.diffieHellmanFile).toString();
        logger.debug("loading diffie-hellman parameters from {}", dhPath);
        dhSpec = PKCS3.decodePEMFile(dhPath);

        encryptionKeyPrivate = readFromPEM(root, json.encryptionKeyFile);
        signatureKeyPrivate = readFromPEM(root, json.signatureKeyFile);
    }

    private PrivateKey readFromPEM(Path root, String file) throws IOException, InvalidKeySpecException {
        final Path path = Paths.get(root.toString(), file);
        
        final String pemContents = new String(Files.readAllBytes(path));

        logger.debug("loading key from PEM file {}", path.toString());

        return KeyUtils.loadPrivateKeyFromPEM(pemContents);
    }

    public String getConsumerKey() {
        return consumerKey;
    }

    public DHParameterSpec getDhSpec() {
        return dhSpec;
    }

    public String getSignatureMethod() {
        return signatureMethod;
    }

    public String getRealmName() {
        return realmName;
    }

    public PrivateKey getEncryptionKeyPrivate() {
        return encryptionKeyPrivate;
    }

    public PrivateKey getSignatureKeyPrivate() {
        return signatureKeyPrivate;
    }

    public static class ConsumerFilesJson {

        @JsonProperty("consumer_key")
        public String consumerKey;
        @JsonProperty("signature_method")
        public String signatureMethod;
        @JsonProperty("diffie_hellman")
        public String diffieHellmanFile;
        @JsonProperty("encryption_key")
        public String encryptionKeyFile;
        @JsonProperty("signature_key")
        public String signatureKeyFile;
        @JsonProperty("realm_name")
        public String realmName;

        @Override
        public String toString() {
            return ToStringBuilder.reflectionToString(this);
        }
    }
}
