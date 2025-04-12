package com.ccp.util;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@Slf4j
public class CacheUtil {

    private final CacheManager cacheManager;
    private static final String TOKEN_CACHE = "tokenCache";

    public void storeAccessToken(String userId, String accessToken) {
        Cache cache = cacheManager.getCache(TOKEN_CACHE);
        if (cache != null) {
            cache.put(userId, accessToken);
            log.debug("Stored access token for user ID: {}", userId);
        } else {
            log.error("Cache '{}' not found", TOKEN_CACHE);
        }
    }

    public String getAccessToken(String userId) {
        Cache cache = cacheManager.getCache(TOKEN_CACHE);
        if (cache != null) {
            Cache.ValueWrapper valueWrapper = cache.get(userId);
            if (valueWrapper != null) {
                String token = (String) valueWrapper.get();
                log.debug("Retrieved access token for user ID: {}", userId);
                return token;
            }
            log.debug("No access token found for user ID: {}", userId);
        } else {
            log.error("Cache '{}' not found", TOKEN_CACHE);
        }
        return null;
    }

    public void invalidateAccessToken(String userId) {
        Cache cache = cacheManager.getCache(TOKEN_CACHE);
        if (cache != null) {
            cache.evict(userId);
            log.debug("Invalidated access token for user ID: {}", userId);
        } else {
            log.error("Cache '{}' not found", TOKEN_CACHE);
        }
    }

    public void clearAllTokens() {
        Cache cache = cacheManager.getCache(TOKEN_CACHE);
        if (cache != null) {
            cache.clear();
            log.debug("Cleared all tokens from cache");
        } else {
            log.error("Cache '{}' not found", TOKEN_CACHE);
        }
    }
}