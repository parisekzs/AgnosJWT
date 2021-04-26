/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package hu.mi.jwt.model.token;

import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import org.apache.commons.lang3.RandomStringUtils;

/**
 *
 * @author parisek
 */
public class JwtHeader {

    public static String getKeyIdFromEncodedHeader(String encodedHeader) {
        String plainHeader = new String(Base64.getDecoder().decode(encodedHeader));
        String value = plainHeader
                .split(":")[1]
                .trim();
        if (value.endsWith("\"}")) {
            value = value.substring(0, value.length() - 2);
        }
        return value
                .replaceAll("\"", "")
                .trim();
    }

    public static String generateRandomKeyId() throws NoSuchAlgorithmException {
        return RandomStringUtils.randomAlphanumeric(32);
    }

    public static String getEncodedHeader(String keyId) {
        String result = new StringBuilder("{\"kid\":\"")
                .append(keyId)
                .append("\"}")
                .toString();
        return Base64.getEncoder().encodeToString(result.getBytes());
    }
}
