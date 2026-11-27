package com.example.ed25519.service;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

import org.junit.jupiter.api.Test;

class NonceStoreTest {
  private static final Instant START = Instant.parse("2026-01-01T00:00:00Z");

  private final MutableClock clock = new MutableClock(START);
  private final NonceStore nonceStore = new NonceStore(clock);

  @Test
  void acceptsFirstUse() {
    assertThat(nonceStore.tryMarkUsed("a")).isTrue();
  }

  @Test
  void rejectsReuse() {
    nonceStore.tryMarkUsed("a");

    assertThat(nonceStore.tryMarkUsed("a")).isFalse();
  }

  @Test
  void tracksNoncesIndependently() {
    assertThat(nonceStore.tryMarkUsed("a")).isTrue();
    assertThat(nonceStore.tryMarkUsed("b")).isTrue();
  }

  @Test
  void stillRejectsReuseAtTheEndOfRetention() {
    nonceStore.tryMarkUsed("a");
    clock.advanceSeconds(NonceStore.RETENTION_SECONDS);

    assertThat(nonceStore.tryMarkUsed("a")).isFalse();
  }

  @Test
  void forgetsNonceAfterRetention() {
    nonceStore.tryMarkUsed("a");
    clock.advanceSeconds(NonceStore.RETENTION_SECONDS + 1);

    assertThat(nonceStore.tryMarkUsed("a")).isTrue();
  }

  @Test
  void expiresOnlyNoncesPastTheirRetention() {
    nonceStore.tryMarkUsed("old");
    clock.advanceSeconds(60);
    nonceStore.tryMarkUsed("new");
    clock.advanceSeconds(NonceStore.RETENTION_SECONDS - 59);

    assertThat(nonceStore.tryMarkUsed("old")).isTrue();
    assertThat(nonceStore.tryMarkUsed("new")).isFalse();
  }

  private static final class MutableClock extends Clock {
    private Instant instant;

    MutableClock(Instant instant) {
      this.instant = instant;
    }

    void advanceSeconds(long seconds) {
      instant = instant.plusSeconds(seconds);
    }

    @Override
    public ZoneId getZone() {
      return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
      return this;
    }

    @Override
    public Instant instant() {
      return instant;
    }
  }
}
