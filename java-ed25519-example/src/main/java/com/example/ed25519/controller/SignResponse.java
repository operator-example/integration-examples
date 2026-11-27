package com.example.ed25519.controller;

import com.example.ed25519.service.SignedData;
import com.fasterxml.jackson.annotation.JsonProperty;

public record SignResponse(
    @JsonProperty("key_id") String keyId,
    @JsonProperty("operator_id") String operatorId,
    String payload,
    String signature) {

  static SignResponse from(SignedData signed) {
    return new SignResponse(signed.keyId(), signed.operatorId(), signed.payload(), signed.signature());
  }
}
