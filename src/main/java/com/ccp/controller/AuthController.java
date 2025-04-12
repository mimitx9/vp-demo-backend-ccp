package com.ccp.controller;

import com.ccp.service.AuthService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.view.RedirectView;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthService authService;

    @Value("${spring.security.oauth2.client.registration.ciam.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.provider.ciam.authorization-uri}")
    private String authorizationUri;

    @Value("${cookie.session-token.name}")
    private String cookieName;

    /**
     * Redirect to CIAM login page
     */
    @GetMapping("/login")
    public RedirectView login(@RequestParam(required = false) String redirectUrl) {
        String baseCallbackUrl = "http://localhost:8080/api/v1/auth/callback";

        // Add state parameter with redirectUrl if provided
        String state = redirectUrl != null ? redirectUrl : "/dashboard";

        String authUrl = authorizationUri +
                "?client_id=" + clientId +
                "&response_type=code" +
                "&scope=openid%20profile%20email" +
                "&redirect_uri=" + baseCallbackUrl +
                "&state=" + state;

        return new RedirectView(authUrl);
    }

    /**
     * Handle callback from CIAM with authorization code
     */
    @GetMapping("/callback")
    public RedirectView callback(
            @RequestParam("code") String code,
            @RequestParam(value = "state", required = false) String state,
            HttpServletRequest request,
            HttpServletResponse response) {

        try {
            log.debug("Received callback with code: {} and state: {}", code, state);

            // Base callback URL must match exactly what was sent to CIAM
            String redirectUri = "http://localhost:8080/api/v1/auth/callback";

            // Process authorization code and create session
            String redirectUrl = authService.handleAuthorizationCallback(code, redirectUri, request, response);

            // If state contains a redirect URL, use it instead of the default
            if (state != null && !state.isEmpty() && !state.equals("/dashboard")) {
                redirectUrl = state;
            }

            // Redirect to front-end application
            return new RedirectView("http://localhost:3000" + redirectUrl);

        } catch (Exception e) {
            log.error("Error processing callback: {}", e.getMessage(), e);
            // Redirect to login page with error
            return new RedirectView("http://localhost:3000/login?error=auth_failed");
        }
    }

    /**
     * Logout user
     */
    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(HttpServletRequest request, HttpServletResponse response) {
        Cookie[] cookies = request.getCookies();
        String sessionToken = null;

        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookieName.equals(cookie.getName())) {
                    sessionToken = cookie.getValue();
                    break;
                }
            }
        }

        authService.logout(sessionToken, response);

        Map<String, String> result = new HashMap<>();
        result.put("message", "Logged out successfully");

        return ResponseEntity.ok(result);
    }

    /**
     * Check if user is authenticated
     */
    @GetMapping("/status")
    public ResponseEntity<Map<String, Object>> checkAuthStatus(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        String sessionToken = null;

        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookieName.equals(cookie.getName())) {
                    sessionToken = cookie.getValue();
                    break;
                }
            }
        }

        Map<String, Object> result = new HashMap<>();

        if (sessionToken != null && authService.validateSessionToken(sessionToken)) {
            result.put("authenticated", true);
            result.put("userId", authService.extractUserIdFromToken(sessionToken));
        } else {
            result.put("authenticated", false);
        }

        return ResponseEntity.ok(result);
    }
}