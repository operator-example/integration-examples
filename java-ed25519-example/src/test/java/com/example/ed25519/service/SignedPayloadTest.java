package com.example.ed25519.service;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class SignedPayloadTest {
  private static Optional<SignedPayload> parse(String payload) {
    return SignedPayload.parse(payload.getBytes(StandardCharsets.ISO_8859_1));
  }

  @Test
  void readsStringFields() {
    assertThat(parse("{\"data\":\"d\",\"domain\":\"five-gaming\",\"nonce\":\"n\"}"))
        .contains(new SignedPayload("five-gaming", "n", "d"));
  }

  @Test
  void nonStringFieldsAreNull() {
    assertThat(parse("{\"data\":1,\"domain\":null,\"nonce\":[\"n\"]}"))
        .contains(new SignedPayload(null, null, null));
  }

  @Test
  void lastDuplicateKeyWins() {
    assertThat(parse("{\"data\":\"first\",\"data\":\"last\"}")).map(SignedPayload::data).contains("last");
  }

  @ParameterizedTest
  @ValueSource(strings = {
      "not json",
      "[1,2]",
      "{\"data\":\"\\udcff\"}",
      "{\"x\":\"\\udcff\"}",
      "\u00EF\u00BB\u00BF{}",
      "{\"data\":\"\u00ff\"}" })
  void rejectsMalformedPayloads(String payload) {
    assertThat(parse(payload)).isEmpty();
  }

  @Test
  void acceptsSixtyFourLevelsAndRejectsSixtyFive() {
    assertThat(parse("{\"x\":" + "[".repeat(63) + "]".repeat(63) + "}")).isPresent();
    assertThat(parse("{\"x\":" + "[".repeat(64) + "]".repeat(64) + "}")).isEmpty();
  }
}
