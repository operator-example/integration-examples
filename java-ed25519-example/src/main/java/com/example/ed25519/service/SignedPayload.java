package com.example.ed25519.service;

import java.nio.charset.CharacterCodingException;
import java.util.Map;
import java.util.Optional;

import com.example.ed25519.encoding.StrictUtf8;

import tools.jackson.core.JacksonException;
import tools.jackson.core.StreamReadConstraints;
import tools.jackson.core.json.JsonFactory;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

public record SignedPayload(String domain, String nonce, String data) {
  private static final int MAX_DEPTH = 64;
  private static final JsonMapper MAPPER = JsonMapper.builder(JsonFactory.builder()
      .streamReadConstraints(StreamReadConstraints.builder().maxNestingDepth(MAX_DEPTH).build())
      .build())
      .build();

  public static Optional<SignedPayload> parse(byte[] payload) {
    String text;
    try {
      text = StrictUtf8.decode(payload);
    } catch (CharacterCodingException exception) {
      return Optional.empty();
    }

    if (text.startsWith("\uFEFF")) {
      return Optional.empty();
    }

    JsonNode document;
    try {
      document = MAPPER.readTree(text);
    } catch (JacksonException exception) {
      return Optional.empty();
    }

    if (document == null || !document.isObject() || !isWellFormed(document)) {
      return Optional.empty();
    }

    return Optional.of(new SignedPayload(
        document.path("domain").stringValue(null),
        document.path("nonce").stringValue(null),
        document.path("data").stringValue(null)));
  }

  private static boolean isWellFormed(JsonNode node) {
    if (node.isString()) {
      return StrictUtf8.isWellFormed(node.stringValue());
    }

    if (node.isObject()) {
      for (Map.Entry<String, JsonNode> property : node.properties()) {
        if (!StrictUtf8.isWellFormed(property.getKey()) || !isWellFormed(property.getValue())) {
          return false;
        }
      }
    }

    if (node.isArray()) {
      for (JsonNode element : node) {
        if (!isWellFormed(element)) {
          return false;
        }
      }
    }

    return true;
  }
}
