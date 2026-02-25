package com.github.advancedsecurity.storageservice;

import com.github.advancedsecurity.storageservice.models.Profile;
import com.github.advancedsecurity.storageservice.security.JwtAuthenticationToken;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.lang.Maps;
import io.jsonwebtoken.jackson.io.JacksonDeserializer;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class JwtAuthenticationTokenTest {

    private static final String SECRET = "secretsecret1234secretsecret1234";
    private static final String ISSUER = "OctoGallery";

    private JwtAuthenticationToken buildToken(String login, String name, String email) {
        Map<String, Object> profileMap = new HashMap<>();
        profileMap.put("login", login);
        profileMap.put("name", name);
        profileMap.put("email", email);

        SecretKeySpec key = new SecretKeySpec(SECRET.getBytes(StandardCharsets.UTF_8), "HmacSHA256");

        String jwt = Jwts.builder()
                .setIssuer(ISSUER)
                .setExpiration(new Date(System.currentTimeMillis() + 3600_000))
                .claim("profile", profileMap)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        Jws<Claims> jws = Jwts.parserBuilder()
                .deserializeJsonWith(new JacksonDeserializer(Maps.of("profile", Profile.class).build()))
                .requireIssuer(ISSUER)
                .setSigningKey(key)
                .build()
                .parseClaimsJws(jwt);

        return new JwtAuthenticationToken(jws);
    }

    @Test
    void getNameReturnsLogin() {
        JwtAuthenticationToken token = buildToken("mona", "Mona Lisa", "mona@example.com");
        assertEquals("mona", token.getName());
    }

    @Test
    void getPrincipalReturnsProfile() {
        JwtAuthenticationToken token = buildToken("octocat", "Octo Cat", "octocat@example.com");
        Object principal = token.getPrincipal();
        assertTrue(principal instanceof Profile);
        Profile profile = (Profile) principal;
        assertEquals("octocat", profile.login);
        assertEquals("Octo Cat", profile.name);
        assertEquals("octocat@example.com", profile.email);
    }

    @Test
    void getCredentialsReturnsProfile() {
        JwtAuthenticationToken token = buildToken("user1", "User One", "user1@example.com");
        assertTrue(token.getCredentials() instanceof Profile);
    }

    @Test
    void getDetailsReturnsProfile() {
        JwtAuthenticationToken token = buildToken("user2", "User Two", "user2@example.com");
        assertTrue(token.getDetails() instanceof Profile);
    }

    @Test
    void isAuthenticatedReturnsTrue() {
        JwtAuthenticationToken token = buildToken("user3", "User Three", "user3@example.com");
        assertTrue(token.isAuthenticated());
    }

    @Test
    void getAuthoritiesReturnsEmptyCollection() {
        JwtAuthenticationToken token = buildToken("user4", "User Four", "user4@example.com");
        assertNotNull(token.getAuthorities());
        assertTrue(token.getAuthorities().isEmpty());
    }
}
