package com.ccp.service;

import com.ccp.dto.TokenRequest;
import com.ccp.dto.TokenResponse;
import com.ccp.dto.UserInfoDto;
import com.ccp.model.Session;
import com.ccp.model.User;
import com.ccp.repository.SessionRepository;
import com.ccp.repository.UserRepository;
import com.ccp.util.CacheUtil;
import com.ccp.util.JwtUtil;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final UserRepository userRepository;
    private final SessionRepository sessionRepository;
    private final JwtUtil jwtUtil;
    private final CacheUtil cacheUtil;
    private final RestTemplate restTemplate;

    @Value("${spring.security.oauth2.client.provider.ciam.token-uri}")
    private String tokenUri;

    @Value("${spring.security.oauth2.client.provider.ciam.user-info-uri}")
    private String userInfoUri;

    @Value("${spring.security.oauth2.client.registration.ciam.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.ciam.client-secret}")
    private String clientSecret;

    @Value("${cookie.session-token.name}")
    private String cookieName;

    @Value("${cookie.session-token.max-age}")
    private int cookieMaxAge;

    @Value("${cookie.secure}")
    private boolean cookieSecure;

    @Value("${cookie.http-only}")
    private boolean cookieHttpOnly;

    @Value("${cookie.domain}")
    private String cookieDomain;

    @Value("${cookie.path}")
    private String cookiePath;

    @Value("${jwt.expiration}")
    private long jwtExpiration;

    /**
     * Exchange authorization code for access token and user info
     */
    @Transactional
    public String handleAuthorizationCallback(String code, String redirectUri, HttpServletRequest request, HttpServletResponse response) {
        // 1. Exchange code for token
        TokenResponse tokenResponse = exchangeCodeForToken(code, redirectUri);
        if (tokenResponse == null || tokenResponse.getAccessToken() == null) {
            throw new RuntimeException("Failed to exchange code for token");
        }

        // 2. Get user info from token
        UserInfoDto userInfo = getUserInfo(tokenResponse.getAccessToken());
        if (userInfo == null || userInfo.getSub() == null) {
            throw new RuntimeException("Failed to get user info");
        }

        // 3. Create or update user
        User user = createOrUpdateUser(userInfo);

        // 4. Create session
        String sessionToken = createSession(user, tokenResponse, request);

        // 5. Set session cookie
        setSessionCookie(response, sessionToken);

        // 6. Store access token in cache for later use
        cacheUtil.storeAccessToken(user.getId().toString(), tokenResponse.getAccessToken());

        // 7. Return redirect URL to client
        return "/dashboard"; // This will be used by the controller to redirect
    }

    /**
     * Exchange authorization code for access token
     */
    private TokenResponse exchangeCodeForToken(String code, String redirectUri) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "authorization_code");
        body.add("code", code);
        body.add("redirect_uri", redirectUri);
        body.add("client_id", clientId);
        body.add("client_secret", clientSecret);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

        try {
            ResponseEntity<TokenResponse> response = restTemplate.postForEntity(tokenUri, request, TokenResponse.class);
            log.debug("Token exchange response: {}", response.getStatusCode());
            return response.getBody();
        } catch (Exception e) {
            log.error("Error exchanging code for token: {}", e.getMessage(), e);
            return null;
        }
    }

    /**
     * Get user info from access token
     */
    private UserInfoDto getUserInfo(String accessToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);

        HttpEntity<String> request = new HttpEntity<>(headers);

        try {
            ResponseEntity<UserInfoDto> response = restTemplate.getForEntity(userInfoUri, UserInfoDto.class, request);
            log.debug("User info response: {}", response.getStatusCode());
            return response.getBody();
        } catch (Exception e) {
            log.error("Error getting user info: {}", e.getMessage(), e);
            return null;
        }
    }

    /**
     * Create or update user based on user info
     */
    private User createOrUpdateUser(UserInfoDto userInfo) {
        return userRepository.findByCiamId(userInfo.getSub())
                .map(existingUser -> {
                    // Update existing user
                    existingUser.setEmail(userInfo.getEmail());
                    existingUser.setFirstName(userInfo.getGivenName());
                    existingUser.setLastName(userInfo.getFamilyName());
                    existingUser.setLastLogin(LocalDateTime.now());
                    return userRepository.save(existingUser);
                })
                .orElseGet(() -> {
                    // Create new user
                    User newUser = User.builder()
                            .ciamId(userInfo.getSub())
                            .username(userInfo.getPreferredUsername() != null ? userInfo.getPreferredUsername() : userInfo.getEmail())
                            .email(userInfo.getEmail())
                            .firstName(userInfo.getGivenName())
                            .lastName(userInfo.getFamilyName())
                            .lastLogin(LocalDateTime.now())
                            .build();
                    return userRepository.save(newUser);
                });
    }

    /**
     * Create session for user
     */
    private String createSession(User user, TokenResponse tokenResponse, HttpServletRequest request) {
        // Generate a session token using JWT
        String sessionToken = jwtUtil.generateToken(user);

        // Calculate expiration time
        LocalDateTime expiresAt = LocalDateTime.now().plusSeconds(tokenResponse.getExpiresIn());

        // Get client info
        String ipAddress = getClientIp(request);
        String userAgent = request.getHeader("User-Agent");

        // Create session record
        Session session = Session.builder()
                .sessionId(UUID.randomUUID().toString())
                .user(user)
                .accessToken(tokenResponse.getAccessToken())
                .refreshToken(tokenResponse.getRefreshToken())
                .expiresAt(expiresAt)
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .active(true)
                .build();

        sessionRepository.save(session);

        // Optionally deactivate other sessions for this user
        // sessionRepository.deactivateOtherSessions(user, session.getSessionId());

        return sessionToken;
    }

    /**
     * Set session cookie in response
     */
    private void setSessionCookie(HttpServletResponse response, String sessionToken) {
        Cookie cookie = new Cookie(cookieName, sessionToken);
        cookie.setMaxAge(cookieMaxAge);
        cookie.setSecure(cookieSecure);
        cookie.setHttpOnly(cookieHttpOnly);
        cookie.setPath(cookiePath);

        if (cookieDomain != null && !cookieDomain.isEmpty()) {
            cookie.setDomain(cookieDomain);
        }

        response.addCookie(cookie);
    }

    /**
     * Get client IP address
     */
    private String getClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    /**
     * Validate session token
     */
    public boolean validateSessionToken(String token) {
        return jwtUtil.validateToken(token);
    }

    /**
     * Extract user ID from session token
     */
    public Long extractUserIdFromToken(String token) {
        return jwtUtil.extractUserId(token);
    }

    /**
     * Logout user by invalidating session
     */
    @Transactional
    public void logout(String sessionToken, HttpServletResponse response) {
        if (sessionToken != null && jwtUtil.validateToken(sessionToken)) {
            Long userId = jwtUtil.extractUserId(sessionToken);

            // Invalidate access token in cache
            cacheUtil.invalidateAccessToken(userId.toString());

            // Invalidate session cookie
            Cookie cookie = new Cookie(cookieName, null);
            cookie.setMaxAge(0);
            cookie.setPath(cookiePath);

            if (cookieDomain != null && !cookieDomain.isEmpty()) {
                cookie.setDomain(cookieDomain);
            }

            response.addCookie(cookie);

            // Mark session as inactive in database
            User user = userRepository.findById(userId).orElse(null);
            if (user != null) {
                // Instead of trying to find the exact session, we can just invalidate all active sessions
                sessionRepository.findByUserAndActiveTrue(user).forEach(session -> {
                    session.setActive(false);
                    sessionRepository.save(session);
                });
            }
        }
    }
}