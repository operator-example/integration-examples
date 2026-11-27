package com.example.ed25519.service;

public record SignedData(String keyId, String operatorId, String payload, String signature) {
}
