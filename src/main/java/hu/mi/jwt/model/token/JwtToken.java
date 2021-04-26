/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package hu.mi.jwt.model.token;

import hu.mi.jwt.model.key.Key;
import hu.mi.jwt.model.key.KeyRing;
import hu.mi.jwt.model.key.KeyStore;
import hu.mi.jwt.util.AESCipher;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import lombok.Builder;
import lombok.Getter;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/**
 *
 * @author parisek
 */
@Getter
public class JwtToken {

    private String keyStoreName;
    private Collection<? extends GrantedAuthority> claims;
    private String subject;
    private KeyStore keyStore;
    private int keyRingMaxSize;

    public JwtToken(String keyStoreName, KeyStore keyStore, int keyRingMaxSize) {
        this.keyStoreName = keyStoreName;
        this.keyStore = keyStore;
        this.keyRingMaxSize = keyRingMaxSize;
    }

    @Builder
    public JwtToken(String keyStoreName, KeyStore keyStore, int keyRingMaxSize, Collection<? extends GrantedAuthority> claims, String subject) {
        this(keyStoreName, keyStore, keyRingMaxSize);
        this.claims = claims;
        this.subject = subject;
    }

    public String generateToken() {
        try {

            Key customKey = new Key();

            Map keyStoreMap = this.keyStore.getMap(keyStoreName);

            String keyId = getAndBookNewKeyId(keyStoreMap);

            String encodedHeader = JwtHeader.getEncodedHeader(keyId);
            String encodedPayload = doEncodedPayload();

            String encodedToken = doGenerateToken(encodedHeader, encodedPayload, customKey.getSecretKey());

            customKey.setEncodedTokenString(encodedToken);

            KeyRing customKeyRing = new KeyRing(keyRingMaxSize);

            customKeyRing.add(customKey);

            keyStoreMap.replace(keyId, customKeyRing.toString());

            return encodedToken;
        } catch (UnsupportedEncodingException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(JwtToken.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    public String validateToken(String authToken, long jwtExpirationInMs, long jwtUsableInMs) {
        try {
            String[] tokenSegments = authToken.split("\\.");

            if (tokenSegments.length == 3) {
                String encodedHeader = tokenSegments[0];
                String keyId = JwtHeader.getKeyIdFromEncodedHeader(encodedHeader);

                Map<String, String> keyStoreMap = this.keyStore.getMap(keyStoreName);

                if (keyStoreMap.containsKey(keyId)) {

                    String customKeyRingString = keyStoreMap.get(keyId);

                    if (customKeyRingString != null && !customKeyRingString.isEmpty()) {
                        String result = "";

                        String encodedPayload = tokenSegments[1];
                        String signature = tokenSegments[2];

                        KeyRing keyRing = new KeyRing(keyRingMaxSize, customKeyRingString);

                        for (int i = 0; i < keyRing.size(); i++) {
                            Key key = keyRing.get(i);
                            if (!key.isSecretKeyOutOfTime(jwtExpirationInMs)) {
                                if (validateSignature(encodedHeader, encodedPayload, signature, key.getSecretKey())) {

                                    Key latestKey = keyRing.get(0);
                                    if (!latestKey.isSecretKeyOutOfTime(jwtUsableInMs)) {
                                        String latestToken = latestKey.getEncodedTokenString();
                                        if (latestToken != null && !latestToken.isEmpty()) {
                                            result = latestToken;
                                        }
                                        else{
                                            result = refreshToken(encodedHeader, encodedPayload, keyStoreMap,
                                                keyId, keyRing);
                                        }
                                    } else {
                                        result = refreshToken(encodedHeader, encodedPayload, keyStoreMap,
                                                keyId, keyRing);
                                    }
                                    break;
                                }
                            }
                        }
                        return result;
                    }
                }

            }
        } catch (SignatureException | MalformedJwtException | UnsupportedJwtException | IllegalArgumentException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | UnsupportedEncodingException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(JwtToken.class.getName()).log(Level.SEVERE, null, ex);
            throw new BadCredentialsException("INVALID_CREDENTIALS", ex);
        } catch (ExpiredJwtException ex) {
            Logger.getLogger(JwtToken.class.getName()).log(Level.SEVERE, null, ex);
            throw ex;
        }
        throw new SignatureException("INVALID_TOKEN");
    }

    public static String getUsernameFromToken(String authToken) {
        String[] tokenSegments = authToken.split("\\.");
        if (tokenSegments.length != 3) {
            throw new SignatureException("INVALID_TOKEN");
        }
        String encodedencodedPayload = tokenSegments[1];
        String plainPayload = new String(Base64.getDecoder().decode(encodedencodedPayload));
        return JwtPayload.getUsernameFromPlainPayload(plainPayload);

    }

    public static List<SimpleGrantedAuthority> getRolesFromToken(String authToken) {
        String[] tokenSegments = authToken.split("\\.");
        if (tokenSegments.length != 3) {
            throw new SignatureException("INVALID_TOKEN");
        }
        String encodedencodedPayload = tokenSegments[1];
        String plainPayload = new String(Base64.getDecoder().decode(encodedencodedPayload));
        return (List<SimpleGrantedAuthority>) JwtPayload.getAuthoritiesFromPlainPayload(plainPayload);

    }

    private String refreshToken(String encodedHeader, String encodedPayload, Map keyStoreMap, String keyId, KeyRing keyRing) {
        try {

            Key customKey = new Key();
            String encodedToken = doGenerateToken(encodedHeader, encodedPayload, customKey.getSecretKey());
            customKey.setEncodedTokenString(encodedToken);
            keyRing.addKey(customKey);
            keyStoreMap.replace(keyId, keyRing.toString());

            return encodedToken;

        } catch (UnsupportedEncodingException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(JwtToken.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    private String getAndBookNewKeyId(Map keyStoreMap) throws NoSuchAlgorithmException {
        String keyId = JwtHeader.generateRandomKeyId();

        while (keyStoreMap.containsKey(keyId)) {
            keyId = JwtHeader.generateRandomKeyId();
        }
        keyStoreMap.put(keyId, "" + System.currentTimeMillis());
        return keyId;
    }

    private String doGenerateToken(String encodedHeader, String encodedPayload, String secretKey) throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        StringBuilder authTokenBuilder = new StringBuilder();
        return authTokenBuilder
                .append(encodedHeader)
                .append(".")
                .append(encodedPayload)
                .append(".")
                .append(doGenerateEncodedSignature(encodedHeader, encodedPayload, secretKey))
                .toString();
    }

    private String doGenerateEncodedSignature(String encodedHeader, String encodedPayload, String secretKey) throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        AESCipher aesCipher = new AESCipher(secretKey);
        StringBuilder authTokenBuilder = new StringBuilder();
        authTokenBuilder
                .append(encodedHeader)
                .append(".")
                .append(encodedPayload);
        return aesCipher.encryptInBase64Encoding(authTokenBuilder.toString());
    }

    private boolean validateSignature(String encodedHeader, String encodedPayload, String signature, String secretKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
        String calculatedSignature = doGenerateEncodedSignature(encodedHeader, encodedPayload, secretKey);
        return signature.equals(calculatedSignature);
    }

    private String doEncodedPayload() {
        JwtPayload payload = new JwtPayload(this.subject, this.claims);
        return payload.getEncodedPayload();
    }

}
