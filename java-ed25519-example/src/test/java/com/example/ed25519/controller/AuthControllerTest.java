package com.example.ed25519.controller;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.assertj.MockMvcTester;

import com.example.ed25519.config.AppConfiguration;
import com.example.ed25519.service.AuthService;
import com.example.ed25519.service.NonceStore;

@WebMvcTest(AuthController.class)
@Import({ AppConfiguration.class, AuthService.class, NonceStore.class })
class AuthControllerTest {
  @Autowired
  private MockMvcTester mvc;

  @Test
  void signResponseUsesSnakeCaseFieldNames() {
    assertThat(post("/Auth/sign", "{}".getBytes(StandardCharsets.UTF_8)))
        .hasStatusOk()
        .bodyText()
        .startsWith("{\"key_id\":\"test-key\",\"operator_id\":\"test-operator\",\"payload\":");
  }

  @Test
  void signReturnsBadRequestForInvalidUtf8() {
    assertThat(post("/Auth/sign", new byte[] { (byte) 0xFF }))
        .hasStatus(400)
        .hasBodyTextEqualTo("{\"error\":\"body is not valid UTF-8\"}");
  }

  @ParameterizedTest
  @ValueSource(strings = { "/Auth/sign", "/Auth/verify" })
  void returnsContentTooLargeOverTheLimit(String path) {
    assertThat(post(path, body(AuthController.MAX_BODY_SIZE + 1)))
        .hasStatus(413)
        .hasBodyTextEqualTo("{\"error\":\"body is too large\"}");
  }

  @Test
  void signAcceptsBodyAtTheLimit() {
    assertThat(post("/Auth/sign", body(AuthController.MAX_BODY_SIZE))).hasStatusOk();
  }

  @Test
  void verifyRejectsUnsignedRequest() {
    assertThat(post("/Auth/verify", "{}".getBytes(StandardCharsets.UTF_8)))
        .hasStatus(401)
        .hasBodyTextEqualTo("{\"verified\":false}");
  }

  private MockMvcTester.MockMvcRequestBuilder post(String path, byte[] body) {
    return mvc.post().uri(path).content(body);
  }

  private static byte[] body(int size) {
    byte[] body = new byte[size];
    Arrays.fill(body, (byte) 'a');
    return body;
  }
}
