package com.example.ed25519;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

import com.example.ed25519.config.AppProperties;
import com.example.ed25519.config.Credentials;

public final class TestKeys {
  public static final Ed25519PrivateKeyParameters OPERATOR = new Ed25519PrivateKeyParameters(filled(1));
  public static final Ed25519PrivateKeyParameters ROOT = new Ed25519PrivateKeyParameters(filled(2));
  public static final String KEY_ID = "test-key";
  public static final String OPERATOR_ID = "test-operator";

  private static final SecureRandom RANDOM = new SecureRandom();

  private TestKeys() {
  }

  public static AppProperties properties() {
    return new AppProperties(KEY_ID, OPERATOR_ID, base64(OPERATOR.getEncoded()),
        base64(ROOT.generatePublicKey().getEncoded()));
  }

  public static Credentials credentials() {
    return Credentials.from(properties());
  }

  public static Ed25519PrivateKeyParameters randomKey() {
    return new Ed25519PrivateKeyParameters(RANDOM);
  }

  public static byte[] sign(Ed25519PrivateKeyParameters key, byte[] data) {
    Ed25519Signer signer = new Ed25519Signer();
    signer.init(true, key);
    signer.update(data, 0, data.length);
    return signer.generateSignature();
  }

  public static boolean verify(Ed25519PublicKeyParameters key, byte[] data, byte[] signature) {
    Ed25519Signer verifier = new Ed25519Signer();
    verifier.init(false, key);
    verifier.update(data, 0, data.length);
    return verifier.verifySignature(signature);
  }

  public static String base64(byte[] bytes) {
    return Base64.getEncoder().encodeToString(bytes);
  }

  private static byte[] filled(int value) {
    byte[] bytes = new byte[32];
    Arrays.fill(bytes, (byte) value);
    return bytes;
  }
}
