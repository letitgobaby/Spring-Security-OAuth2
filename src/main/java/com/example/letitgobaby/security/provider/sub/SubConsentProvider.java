package com.example.letitgobaby.security.provider.sub;

import java.util.Random;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import com.example.letitgobaby.model.SubLogin;
import com.example.letitgobaby.model.SubLoginRepository;
import com.example.letitgobaby.security.exception.SubAuthenticationException;
import com.example.letitgobaby.security.token.sub.ConsentToken;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
@RequiredArgsConstructor
public class SubConsentProvider implements AuthenticationProvider {

  private final SubLoginRepository subLoginRepository;

  @Override
  public boolean supports(Class<?> authentication) {
    return ConsentToken.class.isAssignableFrom(authentication);
  }

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    ConsentToken token = (ConsentToken) authentication;

    // do validate 

    SubLogin subLogin = this.subLoginRepository.findByClientId(token.getPrincipal())
      .orElseThrow(() -> new SubAuthenticationException("Not registed Client Id"));
      
    String authCode = randomString();
    subLogin.setCode(authCode);
    this.subLoginRepository.save(subLogin);

    token.setCode(subLogin.getCode());

    // do validate 

    return token;
  }

  private String randomString() {
    int targetStringLength = 10;
    Random random = new Random();
    return random.ints(97, 123)
      .limit(targetStringLength)
      .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
      .toString();
  }
  
}
