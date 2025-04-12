package com.ccp.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TokenRequest {
    private String code;
    private String redirectUri;
    private String clientId;
    private String clientSecret;
    private String grantType;
}