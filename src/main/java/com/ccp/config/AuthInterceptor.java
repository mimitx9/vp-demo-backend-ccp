package com.ccp.config;

import com.ccp.service.AuthService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.util.Arrays;
import java.util.Optional;

@Component
@RequiredArgsConstructor
@Slf4j
public class AuthInterceptor implements HandlerInterceptor {

    private final AuthService authService;

    @Value("${cookie.session-token.name}")
    private String cookieName;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        // Get session token from cookie
        String sessionToken = extractSessionToken(request);

        if (sessionToken == null) {
            log.debug("No session token found in request");
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            return false;
        }

        // Validate session token
        if (!authService.validateSessionToken(sessionToken)) {
            log.debug("Invalid session token");
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            return false;
        }

        // Extract user ID from token and set in request attribute for later use
        Long userId = authService.extractUserIdFromToken(sessionToken);
        request.setAttribute("userId", userId);

        return true;
    }

    private String extractSessionToken(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();

        if (cookies == null) {
            return null;
        }

        Optional<Cookie> sessionCookie = Arrays.stream(cookies)
                .filter(cookie -> cookieName.equals(cookie.getName()))
                .findFirst();

        return sessionCookie.map(Cookie::getValue).orElse(null);
    }
}