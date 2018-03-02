package com.interactivebrokers.webtradingapi.client.oauth;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Random;

import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class ClientAuthenticationContext {
    private static final byte COLON = (byte) 0x3A;

    private static final Logger logger = LoggerFactory.getLogger(ClientAuthenticationContext.class);
    private static final int RADIX = 16;

    private static final BigInteger TWO = new BigInteger("2", 16);

    private BigInteger a;
    private BigInteger g = new BigInteger("2", 10);
    private BigInteger N = new BigInteger(
            "d4c7f8a2b32c11b8fba9581ec4ba4f1b04215642ef7355e37c0fc0443ef756ea2c6b8eeb755a1c723027663caa265ef785b8ff6a9b35227a52d86633dbdfca43",
            16);
    private BigInteger B;
    private BigInteger M1;
    private final Random RNG = new SecureRandom();
    private final BigInteger A;
    private BigInteger s;

    public ClientAuthenticationContext() {
        a = new BigInteger(8 * 32, RNG);
        if (a.compareTo(N) >= 0)
            a = a.mod(N.subtract(BigInteger.ONE));
        if (a.compareTo(TWO) < 0)
            a = TWO;
        A = g.modPow(a, N);
    }

    public void calculateProof(String username, String pwd) {
        MessageDigest m_Hash;
        try {
            m_Hash = MessageDigest.getInstance("SHA-1"); // "MD5", "SHA-1"
        } catch (Exception e) {
            logger.warn("Cannot create Hash function.");
            return;
        }

        byte[] xb;
        try {
            xb = computeX(trim(s.toByteArray()), username, pwd);
        } catch (Exception e) {
            logger.error("failed to compute x: {}", e, e.getMessage());
            return;
        }
        BigInteger x = new BigInteger(1, xb);
        logger.debug("x: " + x.toString(16));

        m_Hash.update(trim(A.toByteArray()));
        m_Hash.update(trim(B.toByteArray()));
        byte[] ub = m_Hash.digest();
        BigInteger u = new BigInteger(1, ub);
        BigInteger k = new BigInteger("3");
        BigInteger v = g.modPow(x, N);

        logger.debug("v: " + v.toString(16));

        BigInteger i1 = B.subtract(k.multiply(v));
        BigInteger i2 = a.add(u.multiply(x));
        BigInteger S = i1.modPow(i2, N);
        logger.debug("S: " + S.toString(16));

        m_Hash.update(trim(S.toByteArray()));
        byte[] key = m_Hash.digest();
        BigInteger K = new BigInteger(1, key);
        logger.debug("K: " + K.toString(16));

        byte[] userb;
        try {
            userb = m_Hash.digest(username.getBytes("US-ASCII"));
        } catch (UnsupportedEncodingException e) {
            logger.error("bad username: {}", e, e.getMessage());
            return;
        }

        byte[] bN = m_Hash.digest(trim(N.toByteArray()));
        byte[] bg = m_Hash.digest(trim(g.toByteArray()));
        byte[] b = xor(bN, bg, bN.length);
        m_Hash.update(b);
        m_Hash.update(userb);
        m_Hash.update(trim(s.toByteArray()));
        m_Hash.update(trim(A.toByteArray()));
        m_Hash.update(trim(B.toByteArray()));
        m_Hash.update(trim(K.toByteArray()));
        M1 = new BigInteger(1, m_Hash.digest());
        logger.debug("M1: " + M1.toString(16));
    }

    public String getAhex() {
        return A.toString(RADIX);
    }

    public String getM1hex() {
        return M1.toString(RADIX);
    }

    public void setInitParams(String Nhex, String ghex, String Bhex, String shex) {
        N = new BigInteger(Nhex, 16);
        g = new BigInteger(ghex, 16);
        B = new BigInteger(Bhex, 16);
        s = new BigInteger(shex, 16);
        logger.debug("after init: {}", this.toString());
    }

    @Override
    public String toString() {
        return ToStringBuilder.reflectionToString(this, ToStringStyle.DEFAULT_STYLE);
    }

    private static byte[] computeX(final byte[] s, final String user, final String password)
            throws Exception {
        return computeX(s, user.getBytes("US-ASCII"), password.getBytes("US-ASCII"));
    }

    // Treat the input as the MSB representation of a number,
    // and lop off leading zero elements. For efficiency, the
    // input is simply returned if no leading zeroes are found.
    private static byte[] trim(byte[] in) {
        if (in.length == 0 || in[0] != 0)
            return in;

        int len = in.length;
        int i = 1;
        while (in[i] == 0 && i < len)
            ++i;
        byte[] ret = new byte[len - i];
        System.arraycopy(in, i, ret, 0, len - i);
        return ret;
    }

    private static byte[] computeX(final byte[] s, final byte[] user, final byte[] p) throws Exception {
        MessageDigest hash = MessageDigest.getInstance("SHA-1"); // "MD5"
        hash.update(user, 0, user.length);
        hash.update(COLON);
        hash.update(p, 0, p.length);
        final byte[] up = hash.digest();
        hash.update(s, 0, s.length);
        hash.update(up, 0, up.length);
        return hash.digest();
    }

    private static final byte[] xor(final byte[] b1, final byte[] b2, final int length) {
        final byte[] result = new byte[length];
        for (int i = 0; i < length; ++i) {
            result[i] = (byte) (b1[i] ^ b2[i]);
        }
        return result;
    }
}
