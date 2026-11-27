package com.example.ed25519.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("app")
public record AppProperties(String keyId, String operatorId, String privateKey, String rootPublicKey) {
}
