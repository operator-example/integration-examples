package com.example.ed25519.encoding;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;

public final class StrictUtf8 {
  private StrictUtf8() {
  }

  public static String decode(byte[] bytes) throws CharacterCodingException {
    return StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(bytes)).toString();
  }

  public static boolean isWellFormed(String value) {
    return StandardCharsets.UTF_8.newEncoder().canEncode(value);
  }
}
