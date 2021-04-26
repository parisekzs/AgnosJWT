/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package hu.mi.jwt.model.token;

import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/**
 *
 * @author parisek
 */
@Getter
public class JwtPayload {

    private final String userName;
    private final Collection<? extends GrantedAuthority> authorities;

    public JwtPayload(String encodedPayload) {
        String plainPayload = new String(Base64.getDecoder().decode(encodedPayload));
        this.userName = getUsernameFromPlainPayload(plainPayload);
        this.authorities = getAuthoritiesFromPlainPayload(plainPayload);
    }

    public JwtPayload(String userName, Collection<? extends GrantedAuthority> authorities) {
        this.userName = userName;
        this.authorities = authorities;
    }
    
    public String getEncodedPayload() {
        return Base64.getEncoder().encodeToString(this.toString().getBytes());
    }

    public static String getUsernameFromPlainPayload(String plainPayloadJSON) {
        String[] claims = plainPayloadJSON.split(",");
        String subject = claims[0];
        return subject.split(":")[1].replaceAll("\"", "").trim();
    }


    public static Collection<SimpleGrantedAuthority> getAuthoritiesFromPlainPayload(String plainPayload) {
        //plainPayload: {"sub":"parisek","roles": ["LOGIN","demo","USERADMIN"]}
        String[] claims = plainPayload.split("\"roles\"");
        String roles = claims[1]
                .replaceAll("\\:", "")
                .replaceAll("\\[", "")
                .replaceAll("\\]\\}", "");

        String[] authoritiesString = roles.split(",");
        List<SimpleGrantedAuthority> authorities = new ArrayList<>();

        for (String authorityString : authoritiesString) {
            authorities.add(new SimpleGrantedAuthority("ROLE_" + authorityString.replaceAll("\"", "").trim()));
        }
        return authorities;
    }

    @Override
    public String toString() {
        StringBuilder result = new StringBuilder("{\"sub\":\"")
                .append(this.userName).append("\"")
                .append(",\"roles\": [");

        for (GrantedAuthority role : authorities) {
            result.append("\"").append(role.getAuthority()).append("\",");
        }

        if (result.toString().endsWith(",")) {
            result = new StringBuilder(result.subSequence(0, result.length() - 1));
        }
        return result.append("]}").toString();
    }
}
