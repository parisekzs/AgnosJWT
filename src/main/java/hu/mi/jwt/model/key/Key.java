/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package hu.mi.jwt.model.key;

import java.security.NoSuchAlgorithmException;
import java.util.Objects;
import org.apache.commons.lang3.RandomStringUtils;

/**
 *
 * @author parisek
 */
public class Key {

    private final String secretKey;
    private final long issuedAt;
    private String encodedTokenString;

    public Key() throws NoSuchAlgorithmException {
        this.issuedAt = System.currentTimeMillis();
        this.secretKey = generateRandomSecretKey();
        this.encodedTokenString = null;
    }

    public Key(String keyString) {
        String value = keyString.trim();
        this.issuedAt = parseIssuedAtFromString(value);
        this.secretKey = parseSecretKeyFromString(value);
        this.encodedTokenString = parseEncodedTokenFromString(value);
    }

    public String getEncodedTokenString() {
        return encodedTokenString;
    }

    public void setEncodedTokenString(String encodedTokenString) {
        this.encodedTokenString = encodedTokenString;
    }

    public String getSecretKey() {
        return secretKey;
    }

    public long getIssuedAt() {
        return issuedAt;
    }

    
        
    public boolean isSecretKeyOutOfTime(long periodInMs) {
        return System.currentTimeMillis() > (this.issuedAt + periodInMs);
    }

    private static long parseIssuedAtFromString(String value) {
        return Long.parseLong(value.substring(0, 13));
    }

    public static String parseSecretKeyFromString(String value) {
        return value.substring(13, 23);
    }

    public static String parseEncodedTokenFromString(String value) {
        String result = "";
        if (value.length() > 22) {
            result = value.substring(23);
        }
        return result;
    }

    private static String generateRandomSecretKey() throws NoSuchAlgorithmException {
        return RandomStringUtils.randomAlphanumeric(10);
    }

    @Override
    public int hashCode() {
        int hash = 5;
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final Key other = (Key) obj;
        if (this.issuedAt != other.issuedAt) {
            return false;
        }
        if (!Objects.equals(this.secretKey, other.secretKey)) {
            return false;
        }
        return true;
    }

    
    
    @Override
    public String toString() {
        StringBuilder result = new StringBuilder();
        result
                .append(issuedAt)
                .append(secretKey);
        if (encodedTokenString != null && !encodedTokenString.isEmpty()) {
            result.append(encodedTokenString);
        }
        return result.toString();
    }

}
