package com.example.ed25519.encoding;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

class StrictBase64Test {

  @ParameterizedTest
  @ValueSource(strings = { "", "AAAA", "AAE=", "AQ==", "+/+/" })
  void decodesCanonicalBase64(String value) {
    assertThat(StrictBase64.decode(value)).isPresent();
  }

  @ParameterizedTest
  @NullSource
  @ValueSource(strings = { "AQ", "AQ=", "AA AA", "AA-_", "AA\nA", "A===", "not base64!!" })
  void rejectsNonCanonicalBase64(String value) {
    assertThat(StrictBase64.decode(value)).isEmpty();
  }

  @ParameterizedTest
  @ValueSource(ints = { 31, 33 })
  void rejectsUnexpectedLength(int size) {
    assertThat(StrictBase64.decode("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", size)).isEmpty();
  }

  @ParameterizedTest
  @ValueSource(ints = { 32 })
  void acceptsExpectedLength(int size) {
    assertThat(StrictBase64.decode("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", size)).get()
        .extracting(bytes -> bytes.length).isEqualTo(size);
  }
}
