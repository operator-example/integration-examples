package com.example.ed25519.service;

public class InvalidBodyException extends RuntimeException {
  public InvalidBodyException(String message, Throwable cause) {
    super(message, cause);
  }
}
