package com.example.ed25519.service;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Consumer;

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;

import com.example.ed25519.TestKeys;

import tools.jackson.databind.json.JsonMapper;

class AuthServiceVerifyTest {
  private static final JsonMapper JSON = JsonMapper.builder().build();
  private static final SecureRandom RANDOM = new SecureRandom();
  private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC);
  private static final long NOW_MILLIS = CLOCK.millis();
  private static final long NOW_SECONDS = CLOCK.instant().getEpochSecond();

  private final AuthService authService = new AuthService(TestKeys.credentials(), new NonceStore(CLOCK), CLOCK);

  private static final class Request {
    String body = "{\"amount\":100}";
    Object data;
    String payloadDomain = "five-gaming";
    String headerDomain = "five-gaming";
    String nonce = nonceAt(NOW_MILLIS);
    long notBefore = NOW_SECONDS - 60;
    long notAfter = NOW_SECONDS + 3600;
    Ed25519PrivateKeyParameters root = TestKeys.ROOT;
    Ed25519PrivateKeyParameters payloadSigner;
    byte[] payloadOverride;

    HttpHeaders headers() {
      Ed25519PrivateKeyParameters intermediate = TestKeys.randomKey();
      String intermediatePublicKey = TestKeys.base64(intermediate.generatePublicKey().getEncoded());
      String certificate = "{\"not_after\":" + notAfter + ",\"not_before\":" + notBefore + ",\"public_key\":\""
          + intermediatePublicKey + "\"}";

      byte[] payload = payloadOverride;
      if (payload == null) {
        Map<String, Object> document = new LinkedHashMap<>();
        document.put("data", data != null ? data : body);
        document.put("domain", payloadDomain);
        document.put("nonce", nonce);
        payload = JSON.writeValueAsBytes(document);
      }

      HttpHeaders headers = new HttpHeaders();
      headers.set("X-Sign-Version", "2");
      headers.set("X-Sign-Domain", headerDomain);
      headers.set("X-Sign-Nonce", nonce);
      headers.set("X-Sign-Payload", new String(payload, StandardCharsets.ISO_8859_1));
      headers.set("X-Sign-Signature",
          TestKeys.base64(TestKeys.sign(payloadSigner != null ? payloadSigner : intermediate, payload)));
      headers.set("X-Sign-Intermediate-Public-Key", intermediatePublicKey);
      headers.set("X-Sign-Intermediate-Signature",
          TestKeys.base64(TestKeys.sign(root, certificate.getBytes(StandardCharsets.UTF_8))));
      headers.set("X-Sign-Intermediate-Not-Before", Long.toString(notBefore));
      headers.set("X-Sign-Intermediate-Not-After", Long.toString(notAfter));
      return headers;
    }
  }

  private static String nonceAt(long unixMilli) {
    String hex = String.format("%012x", unixMilli);
    String random = String.format("%016x", RANDOM.nextLong());
    return hex.substring(0, 8) + "-" + hex.substring(8, 12) + "-7" + random.substring(0, 3) + "-8"
        + random.substring(3, 6) + "-" + random.substring(4, 16);
  }

  private boolean verify(Consumer<Request> setup) {
    return verify(setup, headers -> {
    });
  }

  private boolean verify(Consumer<Request> setup, Consumer<HttpHeaders> tamper) {
    Request request = new Request();
    setup.accept(request);
    HttpHeaders headers = request.headers();
    tamper.accept(headers);
    return authService.verify(VerifyRequest.fromHeaders(headers), request.body.getBytes(StandardCharsets.UTF_8));
  }

  private boolean verifyWithHeaders(Consumer<HttpHeaders> tamper) {
    return verify(request -> {
    }, tamper);
  }

  private boolean verifyWithBody(String actualBody) {
    Request request = new Request();
    return authService.verify(VerifyRequest.fromHeaders(request.headers()), actualBody.getBytes(StandardCharsets.UTF_8));
  }

  @Test
  void validRequest() {
    assertThat(verify(request -> {
    })).isTrue();
  }

  @Test
  void unicodeBodyWithRawUtf8Payload() {
    assertThat(verify(request -> request.body = "{\"name\":\"測試會員\",\"emoji\":\"🎰\"}")).isTrue();
  }

  @Test
  void emptyBody() {
    assertThat(verify(request -> request.body = "")).isTrue();
  }

  @Test
  void nonceSlightlyInFutureWithinClockSkew() {
    assertThat(verify(request -> request.nonce = nonceAt(NOW_MILLIS + 30_000))).isTrue();
  }

  @Test
  void replayedRequest() {
    Request request = new Request();
    HttpHeaders headers = request.headers();
    byte[] body = request.body.getBytes(StandardCharsets.UTF_8);

    assertThat(authService.verify(VerifyRequest.fromHeaders(headers), body)).isTrue();
    assertThat(authService.verify(VerifyRequest.fromHeaders(headers), body)).isFalse();
  }

  @Test
  void tamperedBody() {
    assertThat(verifyWithBody("{\"amount\":999}")).isFalse();
  }

  @Test
  void noHeadersAtAll() {
    assertThat(authService.verify(VerifyRequest.fromHeaders(new HttpHeaders()), new byte[0])).isFalse();
  }

  @Test
  void wrongVersion() {
    assertThat(verifyWithHeaders(headers -> headers.set("X-Sign-Version", "1"))).isFalse();
  }

  @Test
  void duplicatedHeader() {
    assertThat(verifyWithHeaders(headers -> headers.add("X-Sign-Signature", headers.getFirst("X-Sign-Signature")))).isFalse();
  }

  @Test
  void missingSignature() {
    assertThat(verifyWithHeaders(headers -> headers.remove("X-Sign-Signature"))).isFalse();
  }

  @Test
  void signatureNotBase64() {
    assertThat(verifyWithHeaders(headers -> headers.set("X-Sign-Signature", "not-base64!!"))).isFalse();
  }

  @Test
  void signatureWrongLength() {
    assertThat(verifyWithHeaders(headers -> headers.set("X-Sign-Signature", TestKeys.base64(new byte[63])))).isFalse();
  }

  @Test
  void payloadSignedByOtherKey() {
    assertThat(verify(request -> request.payloadSigner = TestKeys.randomKey())).isFalse();
  }

  @Test
  void certificateSignedByOtherRoot() {
    assertThat(verify(request -> request.root = TestKeys.randomKey())).isFalse();
  }

  @Test
  void certificateValidityExtendedAfterSigning() {
    assertThat(verifyWithHeaders(headers -> headers.set("X-Sign-Intermediate-Not-After", "9999999999"))).isFalse();
  }

  @Test
  void certificateNotAfterNotANumber() {
    assertThat(verifyWithHeaders(headers -> headers.set("X-Sign-Intermediate-Not-After", "soon"))).isFalse();
  }

  @Test
  void certificateExpired() {
    assertThat(verify(request -> request.notAfter = NOW_SECONDS - 1)).isFalse();
  }

  @Test
  void certificateNotYetValid() {
    assertThat(verify(request -> request.notBefore = NOW_SECONDS + 600)).isFalse();
  }

  @Test
  void missingPayload() {
    assertThat(verifyWithHeaders(headers -> headers.remove("X-Sign-Payload"))).isFalse();
  }

  @Test
  void payloadNotJson() {
    assertThat(verify(request -> request.payloadOverride = "not json".getBytes(StandardCharsets.UTF_8))).isFalse();
  }

  @Test
  void payloadIsJsonArray() {
    assertThat(verify(request -> request.payloadOverride = "[1,2]".getBytes(StandardCharsets.UTF_8))).isFalse();
  }

  @Test
  void dataIsNotString() {
    assertThat(verify(request -> request.data = 100)).isFalse();
  }

  @Test
  void payloadDomainMismatch() {
    assertThat(verify(request -> request.payloadDomain = "evil")).isFalse();
  }

  @Test
  void headerDomainMismatch() {
    assertThat(verify(request -> request.headerDomain = "evil")).isFalse();
  }

  @Test
  void nonceHeaderMismatch() {
    assertThat(verifyWithHeaders(headers -> headers.set("X-Sign-Nonce", nonceAt(NOW_MILLIS)))).isFalse();
  }

  @Test
  void nonceTooOld() {
    assertThat(verify(request -> request.nonce = nonceAt(NOW_MILLIS - 6 * 60_000))).isFalse();
  }

  @Test
  void nonceTooFarInFuture() {
    assertThat(verify(request -> request.nonce = nonceAt(NOW_MILLIS + 2 * 60_000))).isFalse();
  }

  @Test
  void nonceTooShort() {
    assertThat(verify(request -> request.nonce = "abc")).isFalse();
  }

  @Test
  void nonceWithPlusSign() {
    assertThat(verify(request -> request.nonce = "+" + request.nonce.substring(1))).isFalse();
  }

  @Test
  void nonceNotHex() {
    assertThat(verify(request -> request.nonce = "zzzzzzzz-zzzz-7zzz-8zzz-zzzzzzzzzzzz")).isFalse();
  }

  private static void rawPayload(Request request, String json) {
    request.payloadOverride = json.replace("NONCE", request.nonce).getBytes(StandardCharsets.ISO_8859_1);
  }

  @Test
  void payloadKeysDifferInCase() {
    assertThat(verify(request -> rawPayload(request,
        "{\"DATA\":\"{\\\"amount\\\":100}\",\"Domain\":\"five-gaming\",\"Nonce\":\"NONCE\"}"))).isFalse();
  }

  @Test
  void validSurrogatePairInData() {
    assertThat(verify(request -> {
      request.body = "\uD83D\uDE80";
      rawPayload(request, "{\"data\":\"\\ud83d\\ude80\",\"domain\":\"five-gaming\",\"nonce\":\"NONCE\"}");
    })).isTrue();
  }

  @Test
  void loneSurrogateInDataIsRejected() {
    assertThat(verify(request -> {
      request.body = "?";
      rawPayload(request, "{\"data\":\"\\udcff\",\"domain\":\"five-gaming\",\"nonce\":\"NONCE\"}");
    })).isFalse();
  }

  @Test
  void loneSurrogateInUnusedKeyIsRejected() {
    assertThat(verify(request -> rawPayload(request,
        "{\"data\":\"{\\\"amount\\\":100}\",\"domain\":\"five-gaming\",\"nonce\":\"NONCE\",\"x\":\"\\udcff\"}"))).isFalse();
  }

  @Test
  void invalidUtf8ByteInPayload() {
    assertThat(verify(request -> {
      request.body = "\uFFFD";
      rawPayload(request, "{\"data\":\"\u00ff\",\"domain\":\"five-gaming\",\"nonce\":\"NONCE\"}");
    })).isFalse();
  }

  @Test
  void payloadStartsWithByteOrderMark() {
    assertThat(verify(request -> rawPayload(request,
        "\u00EF\u00BB\u00BF{\"data\":\"{\\\"amount\\\":100}\",\"domain\":\"five-gaming\",\"nonce\":\"NONCE\"}"))).isFalse();
  }

  @Test
  void notBeforeWithPlusSign() {
    assertThat(verifyWithHeaders(headers -> headers.set("X-Sign-Intermediate-Not-Before",
        "+" + headers.getFirst("X-Sign-Intermediate-Not-Before")))).isFalse();
  }

  @Test
  void signatureBase64WithSpaceInside() {
    assertThat(verifyWithHeaders(headers -> {
      String signature = headers.getFirst("X-Sign-Signature");
      headers.set("X-Sign-Signature", signature.substring(0, 4) + " " + signature.substring(4));
    })).isFalse();
  }

  @Test
  void signatureBase64WithoutPadding() {
    assertThat(verifyWithHeaders(headers -> headers.set("X-Sign-Signature",
        headers.getFirst("X-Sign-Signature").replaceAll("=+$", "")))).isFalse();
  }

  private static void nestedPayload(Request request, int depth) {
    rawPayload(request, "{\"data\":\"{\\\"amount\\\":100}\",\"domain\":\"five-gaming\",\"nonce\":\"NONCE\",\"x\":"
        + "[".repeat(depth - 1) + "]".repeat(depth - 1) + "}");
  }

  @Test
  void payloadNested64LevelsDeep() {
    assertThat(verify(request -> nestedPayload(request, 64))).isTrue();
  }

  @Test
  void payloadNested65LevelsDeep() {
    assertThat(verify(request -> nestedPayload(request, 65))).isFalse();
  }

  @Test
  void bracketsInsideStringsDoNotCountAsNesting() {
    assertThat(verify(request -> request.body = "[".repeat(100) + "\\\"" + "{".repeat(100))).isTrue();
  }
}
