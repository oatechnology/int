package com.interactivebrokers.webtradingapi.client.utils;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.math.BigInteger;
import java.nio.ByteBuffer;

import javax.crypto.spec.DHParameterSpec;

import org.apache.commons.codec.binary.Base64;

final public class PKCS3 {

    public static class InvalidEncodingException extends Exception {
        InvalidEncodingException(String message) {
            super(message);
        }
    }

    private static final String ENCODING_BEGIN = "-----BEGIN DH PARAMETERS-----";
    private static final String ENCODING_END = "-----END DH PARAMETERS-----";
    private static final String INVALID_PEM = "invalid PKCS#3 PEM format, missing ";

    public static DHParameterSpec decodePEMFile(final String path) throws IOException, InvalidEncodingException {
        return decodePEM(  path );
    }

    private static DHParameterSpec decodePEM(final String reader) throws IOException, InvalidEncodingException {
        final BufferedReader br = new BufferedReader(new InputStreamReader
        		(PKCS3.class.getClassLoader().getResourceAsStream(reader)));
        boolean firstLine = true;
        String encoded = "";
        String line;
        while ((line = br.readLine()) != null) {
            if (!firstLine) {
                if (line.equals(ENCODING_END))
                    return decodeDER(Base64.decodeBase64(encoded));
                else
                    encoded += line;
            } else if (!ENCODING_BEGIN.equals(line)) {
                final String message = INVALID_PEM + "'" + ENCODING_BEGIN + "'";
                throw new InvalidEncodingException(message);
            } else
                firstLine = false;
        }

        final String message = INVALID_PEM + "'" + ENCODING_END + "'";
        throw new InvalidEncodingException(message);
    }

    /**
     * Reads DER-encoded PKCS#3 format
     * <p>
     * References:
     * - https://en.wikipedia.org/wiki/Abstract_Syntax_Notation_One
     * - ftp://ftp.rsasecurity.com/pub/pkcs/ascii/pkcs-3.asc
     * <p>
     * DHParameter ::= SEQUENCE {
     * prime INTEGER, -- p
     * base INTEGER, -- g
     * privateValueLength INTEGER OPTIONAL
     * }
     * <p>
     * Note that privateValueLength is not parsed.
     */
    private static DHParameterSpec decodeDER(byte[] bits) throws InvalidEncodingException {
        if (bits == null || bits.length < 2) {
            throw new InvalidEncodingException("Not enough data to decode");
        }

        final byte sequenceTag = 0x30;
        final ByteBuffer buffer = ByteBuffer.wrap(bits);

        final byte indicator = buffer.get();
        if (sequenceTag != indicator) {
            final String message = "Bytes did not start with sequence tag '"
                    + sequenceTag + "'; found '" + indicator + "' at byte "
                    + (buffer.position() - 1) + " of " + bits.length;
            throw new InvalidEncodingException(message);
        }

        // needs to be at least two tag/length/value entries
        final int contentLength = readLengthValue(buffer);
        if (contentLength < 6) {
            final String message = "Purported content length " + contentLength
                    + " is insufficient for the PKCS#3 specification";
            throw new InvalidEncodingException(message);
        }

        final BigInteger prime = readIntegerTagLengthValue(buffer);
        if (prime == null) {
            final String message = "Unable to decode prime";
            throw new InvalidEncodingException(message);
        }

        final BigInteger generator = readIntegerTagLengthValue(buffer);
        if (generator == null) {
            final String message = "Unable to decode generator";
            throw new InvalidEncodingException(message);
        }

        return new DHParameterSpec(prime, generator);
    }

    private static BigInteger readIntegerTagLengthValue(final ByteBuffer buffer) throws InvalidEncodingException {
        final byte integerTag = 0x02;
        if (integerTag != buffer.get()) {
            final String message = "Expected INTEGER tag (0x02) at byte position "
                    + (buffer.position() - 1) + ", got 0x"
                    + String.format("%02X", integerTag);
            throw new InvalidEncodingException(message);
        }

        final int encodedLength = readLengthValue(buffer);
        if (encodedLength <= 0)
            return null;

        return readBigInteger(buffer, encodedLength);
    }

    private static int readLengthValue(final ByteBuffer buffer) throws InvalidEncodingException {
        final byte entry = buffer.get();
        final byte sentry = -128;  // -128 == 0x80 in two's complement

        // sentry => value is all remaining bytes
        if (entry == sentry) {
            return buffer.limit() - buffer.position();
        }

        // 0x80 not set in first octet => length is encoded in this byte
        if (entry > 0) {
            return entry;
        }

        // 0x80 set in first octet => read next (byte - 0x80) bytes for length
        int result = 0;
        int count = entry & ~sentry;

        if (count > 4) {
            final String message = "Length field too large (" + count
                    + ") at byte position" + (buffer.position() - 1);
            throw new InvalidEncodingException(message);
        }

        do {
            byte current = buffer.get();
            if (current < 0)
                current += 128;
            final int summand = (int) (current) * (1 << (count - 1) * 8);
            result += summand;

            count -= 1;
        } while (count > 0);

        return result;
    }

    private static BigInteger readBigInteger(final ByteBuffer buffer, int byteLength) {
        byte[] components = new byte[byteLength];
        for (int i = 0; i < byteLength; ++i)
            components[i] = buffer.get();

        return new BigInteger(components);
    }
}
