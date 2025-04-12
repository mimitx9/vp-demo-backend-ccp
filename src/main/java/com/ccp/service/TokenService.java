package com.ccp.service;

import com.ccp.dto.TokenRequest;
import com.ccp.dto.TokenResponse;
import com.ccp.model.Session;
import com.ccp.model.User;
import com.ccp.repository.SessionRepository;
import com.ccp.repository.UserRepository;
import com.ccp.util.CacheUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.time.LocalDateTime;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class TokenService {

    private final SessionRepository sessionRepository;
    private final UserRepository userRepository;
    private final CacheUtil cacheUtil;
    private final RestTemplate restTemplate;

    @Value("${spring.security.oauth2.client.provider.ciam.token-uri}")
    private String tokenUri;

    @Value("${spring.security.oauth2.client.registration.ciam.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.ciam.client-secret}")
    private String clientSecret;

    /**
     * Get cached access token for a user
     */
    public String getAccessToken(Long userId) {
        return cacheUtil.getAccessToken(userId.toString());
    }

    /**
     * Refresh access token using refresh token
     */
    @Transactional
    public String refreshAccessToken(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Find active session with refresh token
        Optional<Session> sessionOpt = sessionRepository.findByUserAndActiveTrue(user).stream()
                .filter(s -> s.getRefreshToken() != null && !s.isExpired())
                .findFirst();

        if (sessionOpt.isEmpty()) {
            throw new RuntimeException("No valid session found for refresh");
        }

        Session session = sessionOpt.get();

        // Use refresh token to get new access token
        TokenResponse tokenResponse = refreshToken(session.getRefreshToken());
        if (tokenResponse == null || tokenResponse.getAccessToken() == null) {
            throw new RuntimeException("Failed to refresh token");
        }

        // Update session with new tokens
        session.setAccessToken(tokenResponse.getAccessToken());
        if (tokenResponse.getRefreshToken() != null) {
            session.setRefreshToken(tokenResponse.getRefreshToken());
        }
        session.setExpiresAt(LocalDateTime.now().plusSeconds(tokenResponse.getExpiresIn()));
        session.updateLastAccessed();
        sessionRepository.save(session);

        // Update cache
        cacheUtil.storeAccessToken(userId.toString(), tokenResponse.getAccessToken());

        return tokenResponse.getAccessToken();
    }

    /**
     * Exchange refresh token for new access token
     */
    private TokenResponse refreshToken(String refreshToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "refresh_token");
        body.add("refresh_token", refreshToken);
        body.add("client_id", clientId);
        body.add("client_secret", clientSecret);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

        try {
            ResponseEntity<TokenResponse> response = restTemplate.postForEntity(tokenUri, request, TokenResponse.class);
            log.debug("Token refresh response: {}", response.getStatusCode());
            return response.getBody();
        } catch (Exception e) {
            log.error("Error refreshing token: {}", e.getMessage(), e);
            return null;
        }
    }

    /**
     * Validate token with CIAM
     */
    public boolean validateToken(String token) {
        // This would typically call CIAM's token introspection endpoint
        // For simplicity in this demo, we'll just check if the token exists and isn't expired
        return sessionRepository.findAll().stream()
                .anyMatch(s -> s.getAccessToken().equals(token) && s.isActive() && !s.isExpired());
    }
}