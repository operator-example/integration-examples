package com.example.ed25519.service;

import java.util.List;

import org.springframework.http.HttpHeaders;

public record VerifyRequest(
    String version,
    String domain,
    String nonce,
    String payload,
    String signature,
    String intermediatePublicKey,
    String intermediateSignature,
    String intermediateNotBefore,
    String intermediateNotAfter) {

  public static VerifyRequest fromHeaders(HttpHeaders headers) {
    return new VerifyRequest(
        singleHeader(headers, "X-Sign-Version"),
        singleHeader(headers, "X-Sign-Domain"),
        singleHeader(headers, "X-Sign-Nonce"),
        singleHeader(headers, "X-Sign-Payload"),
        singleHeader(headers, "X-Sign-Signature"),
        singleHeader(headers, "X-Sign-Intermediate-Public-Key"),
        singleHeader(headers, "X-Sign-Intermediate-Signature"),
        singleHeader(headers, "X-Sign-Intermediate-Not-Before"),
        singleHeader(headers, "X-Sign-Intermediate-Not-After"));
  }

  private static String singleHeader(HttpHeaders headers, String name) {
    List<String> values = headers.get(name);
    return values != null && values.size() == 1 ? values.get(0) : null;
  }
}
