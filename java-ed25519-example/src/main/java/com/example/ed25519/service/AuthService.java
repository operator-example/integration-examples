package com.example.ed25519.service;

import java.nio.charset.CharacterCodingException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.Arrays;
import java.util.Base64;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.UUID;
import java.util.regex.Pattern;

import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.springframework.stereotype.Service;

import com.example.ed25519.config.Credentials;
import com.example.ed25519.encoding.StrictBase64;
import com.example.ed25519.encoding.StrictUtf8;

import tools.jackson.core.json.JsonWriteFeature;
import tools.jackson.databind.ObjectWriter;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

@Service
public class AuthService {
  static final long NONCE_MAX_AGE_SECONDS = 5 * 60;
  static final long CLOCK_SKEW_SECONDS = 60;

  private static final String EXPECTED_DOMAIN = "five-gaming";
  private static final Pattern INTEGER_PATTERN = Pattern.compile("-?[0-9]+");
  private static final Pattern HEX_TIMESTAMP_PATTERN = Pattern.compile("[0-9a-fA-F]{12}");
  private static final int PUBLIC_KEY_LENGTH = 32;
  private static final int SIGNATURE_LENGTH = 64;

  private final JsonMapper jsonMapper = JsonMapper.builder().build();
  private final ObjectWriter payloadWriter = jsonMapper.writer().with(JsonWriteFeature.ESCAPE_NON_ASCII);
  private final SecureRandom secureRandom = new SecureRandom();
  private final Credentials credentials;
  private final NonceStore nonceStore;
  private final Clock clock;

  public AuthService(Credentials credentials, NonceStore nonceStore, Clock clock) {
    this.credentials = credentials;
    this.nonceStore = nonceStore;
    this.clock = clock;
  }

  public SignedData sign(byte[] body) {
    String data;
    try {
      data = StrictUtf8.decode(body);
    } catch (CharacterCodingException exception) {
      throw new InvalidBodyException("body is not valid UTF-8", exception);
    }

    ObjectNode document = jsonMapper.createObjectNode();
    document.put("data", data);
    document.put("nonce", newUuidV7());
    String payload = payloadWriter.writeValueAsString(document).replace("\u007F", "\\u007F");
    byte[] payloadBytes = payload.getBytes(StandardCharsets.US_ASCII);

    Ed25519Signer signer = new Ed25519Signer();
    signer.init(true, credentials.privateKey());
    signer.update(payloadBytes, 0, payloadBytes.length);
    byte[] signature = signer.generateSignature();

    return new SignedData(credentials.keyId(), credentials.operatorId(), payload,
        Base64.getEncoder().encodeToString(signature));
  }

  public boolean verify(VerifyRequest request, byte[] body) {
    if (!"2".equals(request.version())) {
      return false;
    }

    byte[] intermediatePublicKey = StrictBase64.decode(request.intermediatePublicKey(), PUBLIC_KEY_LENGTH)
        .orElse(null);
    byte[] intermediateSignature = StrictBase64.decode(request.intermediateSignature(), SIGNATURE_LENGTH)
        .orElse(null);
    byte[] signature = StrictBase64.decode(request.signature(), SIGNATURE_LENGTH).orElse(null);
    if (intermediatePublicKey == null || intermediateSignature == null || signature == null) {
      return false;
    }

    OptionalLong parsedNotBefore = parseLong(request.intermediateNotBefore());
    OptionalLong parsedNotAfter = parseLong(request.intermediateNotAfter());
    if (parsedNotBefore.isEmpty() || parsedNotAfter.isEmpty()) {
      return false;
    }

    long notBefore = parsedNotBefore.getAsLong();
    long notAfter = parsedNotAfter.getAsLong();
    long now = clock.instant().getEpochSecond();
    String certificate = "{\"not_after\":" + notAfter + ",\"not_before\":" + notBefore
        + ",\"public_key\":\"" + Base64.getEncoder().encodeToString(intermediatePublicKey) + "\"}";
    if (!ed25519Verify(intermediateSignature, credentials.rootPublicKey(),
        certificate.getBytes(StandardCharsets.UTF_8))) {
      return false;
    }

    if (now < notBefore || now > notAfter) {
      return false;
    }

    if (request.payload() == null) {
      return false;
    }

    byte[] payload = request.payload().getBytes(StandardCharsets.ISO_8859_1);
    Ed25519PublicKeyParameters intermediateKey = toPublicKey(intermediatePublicKey).orElse(null);
    if (intermediateKey == null || !ed25519Verify(signature, intermediateKey, payload)) {
      return false;
    }

    SignedPayload signedPayload = SignedPayload.parse(payload).orElse(null);
    if (signedPayload == null) {
      return false;
    }

    if (!EXPECTED_DOMAIN.equals(signedPayload.domain()) || !EXPECTED_DOMAIN.equals(request.domain())) {
      return false;
    }

    String nonce = signedPayload.nonce();
    if (nonce == null || !nonce.equals(request.nonce())) {
      return false;
    }

    if (signedPayload.data() == null
        || !Arrays.equals(signedPayload.data().getBytes(StandardCharsets.UTF_8), body)) {
      return false;
    }

    if (!isNonceFresh(nonce, now)) {
      return false;
    }

    return nonceStore.tryMarkUsed(nonce);
  }

  private String newUuidV7() {
    long unixMilli = clock.millis();
    long mostSignificantBits = (unixMilli << 16) | 0x7000L | (secureRandom.nextLong() & 0x0FFFL);
    long leastSignificantBits = (secureRandom.nextLong() & 0x3FFFFFFFFFFFFFFFL) | 0x8000000000000000L;
    return new UUID(mostSignificantBits, leastSignificantBits).toString();
  }

  private static boolean isNonceFresh(String nonce, long now) {
    if (nonce.length() < 13) {
      return false;
    }

    String hexTimestamp = nonce.substring(0, 8) + nonce.substring(9, 13);
    if (!HEX_TIMESTAMP_PATTERN.matcher(hexTimestamp).matches()) {
      return false;
    }

    long signedAt = Long.parseLong(hexTimestamp, 16) / 1000;
    return now - signedAt <= NONCE_MAX_AGE_SECONDS && signedAt - now <= CLOCK_SKEW_SECONDS;
  }

  private static boolean ed25519Verify(byte[] signature, Ed25519PublicKeyParameters publicKey, byte[] data) {
    Ed25519Signer verifier = new Ed25519Signer();
    verifier.init(false, publicKey);
    verifier.update(data, 0, data.length);
    return verifier.verifySignature(signature);
  }

  private static Optional<Ed25519PublicKeyParameters> toPublicKey(byte[] publicKey) {
    try {
      return Optional.of(new Ed25519PublicKeyParameters(publicKey));
    } catch (IllegalArgumentException exception) {
      return Optional.empty();
    }
  }

  private static OptionalLong parseLong(String value) {
    if (value == null || !INTEGER_PATTERN.matcher(value).matches()) {
      return OptionalLong.empty();
    }

    try {
      return OptionalLong.of(Long.parseLong(value));
    } catch (NumberFormatException exception) {
      return OptionalLong.empty();
    }
  }
}
