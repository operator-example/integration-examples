package com.example.ed25519.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import com.example.ed25519.TestKeys;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

class AuthServiceSignTest {
  private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-01-01T00:00:00.123Z"), ZoneOffset.UTC);

  private static final JsonMapper JSON = JsonMapper.builder().build();

  private final AuthService authService = new AuthService(TestKeys.credentials(), new NonceStore(CLOCK), CLOCK);

  @TestFactory
  Stream<DynamicTest> payloadPassesAuthService() throws Exception {
    return loadCases().stream().map(testCase -> DynamicTest.dynamicTest(testCase.name(), () -> {
      if (testCase.rejected()) {
        assertThatThrownBy(() -> authService.sign(testCase.body()))
            .isInstanceOf(InvalidBodyException.class)
            .hasMessage("body is not valid UTF-8");
        return;
      }

      SignedData signed = authService.sign(testCase.body());

      assertThat(signed.payload()).matches("[\\x20-\\x7E]*");
      JsonNode document = JSON.readTree(signed.payload());
      assertThat(document.get("data").stringValue()).isEqualTo(new String(testCase.body(), StandardCharsets.UTF_8));
      assertSignedByOperator(signed);
    }));
  }

  @Test
  void returnsConfiguredIds() {
    SignedData signed = authService.sign("{}".getBytes(StandardCharsets.UTF_8));

    assertThat(signed.keyId()).isEqualTo(TestKeys.KEY_ID);
    assertThat(signed.operatorId()).isEqualTo(TestKeys.OPERATOR_ID);
  }

  @Test
  void nonceIsCurrentUuidV7() {
    SignedData signed = authService.sign(new byte[0]);

    String nonce = signed.payload().replaceAll(".*\"nonce\":\"([^\"]+)\".*", "$1");
    assertThat(nonce).matches("[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}");
    long unixMilli = Long.parseLong(nonce.substring(0, 8) + nonce.substring(9, 13), 16);
    assertThat(unixMilli).isEqualTo(CLOCK.millis());
  }

  @Test
  void everySignatureUsesFreshNonce() {
    byte[] body = "same".getBytes(StandardCharsets.UTF_8);

    assertThat(authService.sign(body).payload()).isNotEqualTo(authService.sign(body).payload());
  }

  private static void assertSignedByOperator(SignedData signed) {
    byte[] payload = signed.payload().getBytes(StandardCharsets.US_ASCII);
    byte[] signature = Base64.getDecoder().decode(signed.signature());
    assertThat(TestKeys.verify(TestKeys.OPERATOR.generatePublicKey(), payload, signature)).isTrue();
  }

  private record PayloadCase(String name, byte[] body, boolean rejected) {
  }

  private static List<PayloadCase> loadCases() throws Exception {
    try (InputStream stream = AuthServiceSignTest.class.getResourceAsStream("/payload-escaping-cases.json")) {
      JsonNode root = JSON.readTree(stream);
      List<PayloadCase> cases = new ArrayList<>();
      for (JsonNode node : root.get("cases")) {
        cases.add(new PayloadCase(node.get("name").stringValue(), HexFormat.of().parseHex(node.get("bodyHex").stringValue()),
            node.path("rejected").asBoolean(false)));
      }

      assertThat(cases).hasSizeGreaterThan(100);
      return cases;
    }
  }
}
