package com.example.letitgobaby.security.provider.sub;

import java.util.Optional;
import java.util.Random;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import com.example.letitgobaby.model.ClientInfo;
import com.example.letitgobaby.model.ClientInfoRepository;
import com.example.letitgobaby.model.SubLogin;
import com.example.letitgobaby.model.SubLoginRepository;
import com.example.letitgobaby.security.dto.UserInfo;
import com.example.letitgobaby.security.exception.SubAuthenticationException;
import com.example.letitgobaby.security.token.sub.ConsentToken;
import com.example.letitgobaby.utils.JWTBuilder;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
@RequiredArgsConstructor
public class SubConsentProvider implements AuthenticationProvider {

  private final ClientInfoRepository clientRepository;
  private final SubLoginRepository subLoginRepository;

  @Override
  public boolean supports(Class<?> authentication) {
    return ConsentToken.class.isAssignableFrom(authentication);
  }

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    ConsentToken token = (ConsentToken) authentication;

    ClientInfo clientInfo = this.clientRepository.findByClientId(token.getPrincipal())
      .orElseThrow(() -> new SubAuthenticationException("Not registed Client Id"));

    SubLogin subLogin = SubLogin.builder()
      .clientId(clientInfo.getClientId())
      .redirectUri(token.getRedirectUri())
      .allowScope(token.getScope())
      .userToken(token.getUserInfoToken())
      .code(randomString())
      .build();
    this.subLoginRepository.save(subLogin);

    token.setCode(subLogin.getCode());
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
