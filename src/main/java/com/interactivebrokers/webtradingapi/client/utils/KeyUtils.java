package com.interactivebrokers.webtradingapi.client.utils;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class KeyUtils {

    private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";
    private static final String HMAC_SHA256_ALGORITHM = "HmacSHA256";
    private static final String SHA256WITH_RSA = "SHA256withRSA";
    private static final Logger logger = LoggerFactory.getLogger(KeyUtils.class);
    private static KeyFactory keyFactory;

    private static KeyFactory getRsaFactory() {
        if (keyFactory != null) {
            return keyFactory;
        }

        try {
            keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory;
        } catch (NoSuchAlgorithmException e) {
            // note: RSA is required by the java spec, so if it doesn't exist, something is seriously wrong
            logger.error("RSA encryption missing in JVM implementation: {}", e, e.getMessage());
            throw new RuntimeException(e);
        }
    }

    /**
     * Uses {@link #HMAC_SHA1_ALGORITHM}.
     *
     * @param K      the key used to sign
     * @param toSign the data to be signed
     * @return the signature
     */
    public static byte[] hmacSHA1Sign(final byte[] K, byte[] toSign) {
        return hmacSign(K, toSign, HMAC_SHA1_ALGORITHM);
    }

    /**
     * Uses {@link #HMAC_SHA256_ALGORITHM}.
     *
     * @param K      the key used to sign
     * @param toSign the data to be signed
     * @return the signature
     */
    public static byte[] hmacSHA256Sign(final byte[] K, byte[] toSign) {
        return hmacSign(K, toSign, HMAC_SHA256_ALGORITHM);
    }

    private static byte[] hmacSign(final byte[] K, byte[] toSign, String algorithm) {
        try {
            final SecretKeySpec keySpec = new SecretKeySpec(K, algorithm);
            Mac mac = Mac.getInstance(algorithm);
            mac.init(keySpec);
            return mac.doFinal(toSign);
        } catch (Exception e) {
            logger.error("failed to generate live session token: {}", e, e.getMessage());
        }
        return new byte[] {};
    }

    private static PrivateKey loadPrivateKeyBase64(String encoded) throws InvalidKeySpecException {
        final byte[] decoded = Base64.decodeBase64(encoded);
        return getRsaFactory().generatePrivate(new PKCS8EncodedKeySpec(decoded));
    }

    public static PrivateKey loadPrivateKeyFromPEM(String pemContents) throws InvalidKeySpecException {
        return loadPrivateKeyBase64(pemContents
                .replace("-----BEGIN PRIVATE KEY-----\n", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replace("\n", ""));
    }

    public static byte[] createSignatureRsaSha256(PrivateKey key, String signatureBaseString)
            throws InvalidKeyException, SignatureException, NoSuchAlgorithmException {

        final Signature signer = Signature.getInstance(SHA256WITH_RSA);
        signer.initSign(key);
        signer.update(signatureBaseString.getBytes());
        return signer.sign();
    }

    public static byte[] decrypt(PrivateKey privateKey, byte[] data)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException {

        final Cipher rsa = Cipher.getInstance("RSA");
        rsa.init(Cipher.DECRYPT_MODE, privateKey);
        return rsa.doFinal(data);
    }

}
