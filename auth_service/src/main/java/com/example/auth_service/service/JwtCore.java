package com.example.auth_service.service;

import com.example.auth_service.model.UserDetailsImpl;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import io.jsonwebtoken.*;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;

@Component
public class JwtCore {
    @Value("${auth.app.secret}")
    private String secret;


    // Генерация ключа на основе секрета
    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    public boolean isTokenValid(String jwt, UserDetails userDetails) {
        String username = getNameFromJwt(jwt);
        return username.equals(userDetails.getUsername());
    }

    public String generateToken(Authentication authentication) {
        try {
            UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

            // Validate inputs
            if (userDetails == null || userDetails.getUsername() == null) {
                throw new IllegalArgumentException("User details cannot be null");
            }

            if (secret == null || secret.isEmpty()) {
                throw new IllegalStateException("JWT secret not configured");
            }

            // Ensure lifetime is positive
            long validLifetime = 3600000; // default to 1 hour if invalid

            // Use java.time for more reliable date handling
            Instant now = Instant.now();
            Instant expiration = now.plusMillis(validLifetime);

            return Jwts.builder()
                    .subject(userDetails.getUsername())
                    .issuedAt(Date.from(now))
                    .expiration(Date.from(expiration))
                    .signWith(Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8)))
                    .compact();
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate JWT token", e);
        }
    }


    public String getNameFromJwt(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey()) // Проверяем подпись
                .build()
                .parseSignedClaims(token) // Парсим токен
                .getPayload() // Получаем payload
                .getSubject(); // Извлекаем subject (username)
    }
}
