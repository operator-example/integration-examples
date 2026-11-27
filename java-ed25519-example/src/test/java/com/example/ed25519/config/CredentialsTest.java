package com.example.ed25519.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Arrays;

import org.junit.jupiter.api.Test;

import com.example.ed25519.TestKeys;

class CredentialsTest {
  private static final String VALID_KEY = TestKeys.base64(TestKeys.ROOT.generatePublicKey().getEncoded());

  private static Credentials load(String keyId, String operatorId, String privateKey, String rootPublicKey) {
    return Credentials.from(new AppProperties(keyId, operatorId, privateKey, rootPublicKey));
  }

  @Test
  void validConfigLoads() {
    Credentials credentials = load("key", "operator", VALID_KEY, VALID_KEY);

    assertThat(credentials.keyId()).isEqualTo("key");
    assertThat(credentials.operatorId()).isEqualTo("operator");
  }

  @Test
  void decodesConfiguredKeys() {
    Credentials credentials = TestKeys.credentials();

    assertThat(credentials.privateKey().getEncoded()).isEqualTo(TestKeys.OPERATOR.getEncoded());
    assertThat(credentials.rootPublicKey().getEncoded())
        .isEqualTo(TestKeys.ROOT.generatePublicKey().getEncoded());
  }

  @Test
  void reportsEveryMissingSettingAtOnce() {
    assertThatThrownBy(() -> load("", " ", "", null))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("KEY_ID is not set")
        .hasMessageContaining("OPERATOR_ID is not set")
        .hasMessageContaining("PRIVATE_KEY is not set")
        .hasMessageContaining("ROOT_PUBLIC_KEY is not set");
  }

  @Test
  void rejectsInvalidBase64() {
    assertThatThrownBy(() -> load("key", "operator", "not base64!!", VALID_KEY))
        .hasMessageContaining("PRIVATE_KEY is not valid base64");
  }

  @Test
  void rejectsBase64WithoutPadding() {
    assertThatThrownBy(() -> load("key", "operator", VALID_KEY.replace("=", ""), VALID_KEY))
        .hasMessageContaining("PRIVATE_KEY is not valid base64");
  }

  @Test
  void rejectsWrongKeyLength() {
    String key31 = TestKeys.base64(new byte[31]);

    assertThatThrownBy(() -> load("key", "operator", VALID_KEY, key31))
        .hasMessageContaining("ROOT_PUBLIC_KEY must be a 32-byte raw Ed25519 key")
        .hasMessageContaining("got 31 bytes");
  }

  @Test
  void rejectsPemOrPkcs8InsteadOfRawKey() {
    String pkcs8 = TestKeys.base64(new byte[48]);

    assertThatThrownBy(() -> load("key", "operator", pkcs8, VALID_KEY))
        .hasMessageContaining("got 48 bytes");
  }

  @Test
  void rejectsRootKeyThatIsNotACurvePoint() {
    byte[] notAPoint = new byte[32];
    Arrays.fill(notAPoint, (byte) 0xFF);

    assertThatThrownBy(() -> load("", "operator", VALID_KEY, TestKeys.base64(notAPoint)))
        .hasMessageContaining("KEY_ID is not set")
        .hasMessageContaining("ROOT_PUBLIC_KEY is not a valid Ed25519 public key");
  }

  @Test
  void errorMessageNeverContainsTheSecret() {
    String secret = TestKeys.base64(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 });

    assertThatThrownBy(() -> load("key", "operator", secret, VALID_KEY))
        .message().doesNotContain(secret);
  }
}
