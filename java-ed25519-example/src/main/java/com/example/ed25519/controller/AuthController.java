package com.example.ed25519.controller;

import java.io.IOException;
import java.io.InputStream;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.ed25519.service.AuthService;
import com.example.ed25519.service.InvalidBodyException;
import com.example.ed25519.service.VerifyRequest;

@RestController
@RequestMapping("/Auth")
public class AuthController {
  public static final int MAX_BODY_SIZE = 8 << 20;

  private final AuthService authService;

  public AuthController(AuthService authService) {
    this.authService = authService;
  }

  @PostMapping("/sign")
  public SignResponse sign(InputStream body) throws IOException {
    return SignResponse.from(authService.sign(readBody(body)));
  }

  @PostMapping("/verify")
  public ResponseEntity<VerifyResponse> verify(@RequestHeader HttpHeaders headers, InputStream body)
      throws IOException {
    if (!authService.verify(VerifyRequest.fromHeaders(headers), readBody(body))) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new VerifyResponse(false));
    }

    return ResponseEntity.ok(new VerifyResponse(true));
  }

  @ExceptionHandler(InvalidBodyException.class)
  ResponseEntity<ErrorResponse> invalidBody(InvalidBodyException exception) {
    return ResponseEntity.badRequest().body(new ErrorResponse(exception.getMessage()));
  }

  @ExceptionHandler(BodyTooLargeException.class)
  ResponseEntity<ErrorResponse> bodyTooLarge() {
    return ResponseEntity.status(HttpStatus.CONTENT_TOO_LARGE).body(new ErrorResponse("body is too large"));
  }

  private static byte[] readBody(InputStream body) throws IOException {
    byte[] bytes = body.readNBytes(MAX_BODY_SIZE + 1);
    if (bytes.length > MAX_BODY_SIZE) {
      throw new BodyTooLargeException();
    }

    return bytes;
  }

  private static class BodyTooLargeException extends RuntimeException {
  }
}
