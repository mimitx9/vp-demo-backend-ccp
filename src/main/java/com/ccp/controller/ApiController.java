package com.ccp.controller;

import com.ccp.model.User;
import com.ccp.service.TokenService;
import com.ccp.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import jakarta.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

/**
 * API Controller for handling authenticated API requests
 * This is just a simple example, you would expand this for your actual business logic
 */
@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
@Slf4j
public class ApiController {

    private final UserService userService;
    private final TokenService tokenService;

    /**
     * Get current user profile
     */
    @GetMapping("/profile")
    public ResponseEntity<Map<String, Object>> getUserProfile(HttpServletRequest request) {
        // Get userId from request attribute (set by AuthInterceptor)
        Long userId = (Long) request.getAttribute("userId");
        if (userId == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "User not authenticated");
        }

        // Get user from database
        User user = userService.getUserById(userId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));

        // Create response
        Map<String, Object> profile = new HashMap<>();
        profile.put("id", user.getId());
        profile.put("username", user.getUsername());
        profile.put("email", user.getEmail());
        profile.put("firstName", user.getFirstName());
        profile.put("lastName", user.getLastName());
        profile.put("lastLogin", user.getLastLogin());

        return ResponseEntity.ok(profile);
    }

    /**
     * Example endpoint that demonstrates using the cached access token to call external APIs
     */
    @GetMapping("/example-external-api-call")
    public ResponseEntity<Map<String, String>> callExternalApi(HttpServletRequest request) {
        // Get userId from request attribute (set by AuthInterceptor)
        Long userId = (Long) request.getAttribute("userId");
        if (userId == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "User not authenticated");
        }

        // Get access token from cache
        String accessToken = tokenService.getAccessToken(userId);

        if (accessToken == null) {
            // Try to refresh the token if it's not in cache
            try {
                accessToken = tokenService.refreshAccessToken(userId);
            } catch (Exception e) {
                log.error("Failed to refresh access token: {}", e.getMessage(), e);
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Session expired, please login again");
            }
        }

        // In a real application, you would use this access token to call external APIs
        // For demo purposes, we'll just return a success message
        Map<String, String> response = new HashMap<>();
        response.put("message", "Successfully retrieved access token for external API call");
        response.put("tokenStatus", "valid");

        return ResponseEntity.ok(response);
    }
}