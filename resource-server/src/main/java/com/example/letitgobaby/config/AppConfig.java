package com.example.letitgobaby.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.example.letitgobaby.utils.JWTBuilder;

@Configuration
public class AppConfig {
  
  @Bean
  public PasswordEncoder bCryptPasswordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  public JWTBuilder jwtBuilder(@Value("${app.jwt.secret}") String secret) {
    int aTime = 1; // 1분
    int rTime = 48 * 60; // 48시간
    return new JWTBuilder(secret, aTime, rTime);
  }
}
