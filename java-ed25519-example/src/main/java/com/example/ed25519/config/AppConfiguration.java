package com.example.ed25519.config;

import java.time.Clock;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(AppProperties.class)
public class AppConfiguration {

  @Bean
  Credentials credentials(AppProperties properties) {
    return Credentials.from(properties);
  }

  @Bean
  Clock clock() {
    return Clock.systemUTC();
  }
}
