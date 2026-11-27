package com.example.ed25519.config;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;

import com.example.ed25519.encoding.StrictBase64;

public record Credentials(
    String keyId,
    String operatorId,
    Ed25519PrivateKeyParameters privateKey,
    Ed25519PublicKeyParameters rootPublicKey) {
  private static final int KEY_LENGTH = 32;

  public static Credentials from(AppProperties properties) {
    List<String> errors = new ArrayList<>();
    String keyId = requireNonBlank(errors, "KEY_ID", properties.keyId());
    String operatorId = requireNonBlank(errors, "OPERATOR_ID", properties.operatorId());
    byte[] privateKey = requireKey(errors, "PRIVATE_KEY", properties.privateKey());
    byte[] rootPublicKey = requireKey(errors, "ROOT_PUBLIC_KEY", properties.rootPublicKey());
    Ed25519PublicKeyParameters rootKey = rootPublicKey == null ? null
        : requirePublicKey(errors, "ROOT_PUBLIC_KEY", rootPublicKey);
    if (!errors.isEmpty()) {
      throw new IllegalStateException("Invalid configuration: " + String.join("; ", errors));
    }

    return new Credentials(keyId, operatorId, new Ed25519PrivateKeyParameters(privateKey), rootKey);
  }

  private static String requireNonBlank(List<String> errors, String name, String value) {
    if (value == null || value.isBlank()) {
      errors.add(name + " is not set");
    }

    return value;
  }

  private static byte[] requireKey(List<String> errors, String name, String value) {
    if (value == null || value.isBlank()) {
      errors.add(name + " is not set");
      return null;
    }

    byte[] key = StrictBase64.decode(value).orElse(null);
    if (key == null) {
      errors.add(name + " is not valid base64");
      return null;
    }

    if (key.length != KEY_LENGTH) {
      errors.add(name + " must be a " + KEY_LENGTH + "-byte raw Ed25519 key, got " + key.length + " bytes");
      return null;
    }

    return key;
  }

  private static Ed25519PublicKeyParameters requirePublicKey(List<String> errors, String name, byte[] key) {
    try {
      return new Ed25519PublicKeyParameters(key);
    } catch (IllegalArgumentException exception) {
      errors.add(name + " is not a valid Ed25519 public key");
      return null;
    }
  }
}
