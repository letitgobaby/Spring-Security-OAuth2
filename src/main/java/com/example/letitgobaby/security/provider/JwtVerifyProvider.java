package com.example.letitgobaby.security.provider;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import com.example.letitgobaby.model.UserRepository;
import com.example.letitgobaby.security.token.JwtToken;

import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class JwtVerifyProvider implements AuthenticationProvider {
  
  private final UserRepository userRepository;
  private final PasswordEncoder encoder;

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    String token = (String) authentication.getPrincipal();

    return null;
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return JwtToken.class.isAssignableFrom(authentication);
  }

}
