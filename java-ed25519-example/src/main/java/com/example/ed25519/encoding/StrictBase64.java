package com.example.ed25519.encoding;

import java.util.Base64;
import java.util.Optional;
import java.util.regex.Pattern;

public final class StrictBase64 {
  private static final Pattern CANONICAL_PATTERN = Pattern.compile("[A-Za-z0-9+/]*={0,2}");

  private StrictBase64() {
  }

  public static Optional<byte[]> decode(String value) {
    if (value == null || value.length() % 4 != 0 || !CANONICAL_PATTERN.matcher(value).matches()) {
      return Optional.empty();
    }

    return Optional.of(Base64.getDecoder().decode(value));
  }

  public static Optional<byte[]> decode(String value, int size) {
    return decode(value).filter(bytes -> bytes.length == size);
  }
}
