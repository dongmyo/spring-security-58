package com.nhnent.edu.security;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.springframework.security.crypto.codec.Hex;
import org.springframework.security.crypto.codec.Utf8;
import org.springframework.security.crypto.password.PasswordEncoder;

// TODO #4: SHA-256 hashing password encoder without salt
//      cf.) org.springframework.security.crypto.password.StandardPasswordEncoder
public class Sha256PasswordEncoder implements PasswordEncoder {
    private final Digester digester;


    public Sha256PasswordEncoder() {
        this.digester = new Digester("SHA-256", 1024);
    }


    @Override
    public String encode(CharSequence rawPassword) {
        byte[] digest = digester.digest(Utf8.encode(rawPassword));
        return new String(Hex.encode(digest));
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        byte[] digested = decode(encodedPassword);
        return matches(digested, digester.digest(Utf8.encode(rawPassword)));
    }

    private byte[] decode(CharSequence encodedPassword) {
        return Hex.decode(encodedPassword);
    }

    private boolean matches(byte[] expected, byte[] actual) {
        if (expected.length != actual.length) {
            return false;
        }

        int result = 0;
        for (int i = 0; i < expected.length; i++) {
            result |= expected[i] ^ actual[i];
        }
        return result == 0;
    }


    // cf.) org.springframework.security.crypto.password.Digester
    private static class Digester {
        private final String algorithm;

        private int iterations;

        public Digester(String algorithm, int iterations) {
            createDigest(algorithm);
            this.algorithm = algorithm;
            setIterations(iterations);
        }

        public byte[] digest(byte[] value) {
            MessageDigest messageDigest = createDigest(algorithm);
            for (int i = 0; i < iterations; i++) {
                value = messageDigest.digest(value);
            }
            return value;
        }

        final void setIterations(int iterations) {
            if (iterations <= 0) {
                throw new IllegalArgumentException("Iterations value must be greater than zero");
            }
            this.iterations = iterations;
        }

        private static MessageDigest createDigest(String algorithm) {
            try {
                return MessageDigest.getInstance(algorithm);
            }
            catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException("No such hashing algorithm", e);
            }
        }
    }

}
