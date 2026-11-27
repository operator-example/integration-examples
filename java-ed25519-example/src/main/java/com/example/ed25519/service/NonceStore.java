package com.example.ed25519.service;

import java.time.Clock;
import java.util.ArrayDeque;
import java.util.HashMap;
import java.util.Map;

import org.springframework.stereotype.Component;

@Component
public class NonceStore {
  static final long RETENTION_SECONDS = AuthService.NONCE_MAX_AGE_SECONDS + AuthService.CLOCK_SKEW_SECONDS;

  private final Map<String, Long> usedNonces = new HashMap<>();
  private final ArrayDeque<Entry> expiryQueue = new ArrayDeque<>();
  private final Clock clock;

  public NonceStore(Clock clock) {
    this.clock = clock;
  }

  public synchronized boolean tryMarkUsed(String nonce) {
    long now = clock.instant().getEpochSecond();
    while (!expiryQueue.isEmpty() && expiryQueue.peekFirst().expiresAt() < now) {
      usedNonces.remove(expiryQueue.pollFirst().nonce());
    }

    long expiresAt = now + RETENTION_SECONDS;
    if (usedNonces.putIfAbsent(nonce, expiresAt) != null) {
      return false;
    }

    expiryQueue.addLast(new Entry(nonce, expiresAt));
    return true;
  }

  private record Entry(String nonce, long expiresAt) {
  }
}
