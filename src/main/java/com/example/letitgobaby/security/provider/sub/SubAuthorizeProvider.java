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
import com.example.letitgobaby.security.exception.SubAuthenticationException;
import com.example.letitgobaby.security.token.sub.AuhorizeToken;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
@RequiredArgsConstructor
public class SubAuthorizeProvider implements AuthenticationProvider {

  private final ClientInfoRepository clientRepository;
  private final SubLoginRepository subLoginRepository;

  @Override
  public boolean supports(Class<?> authentication) {
    return AuhorizeToken.class.isAssignableFrom(authentication);
  }

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    AuhorizeToken token = (AuhorizeToken) authentication;

    if (!token.getResType().equals("code")) {
      throw new SubAuthenticationException("Not Allowed Response Type");
    }

    Optional<ClientInfo> clientInfo = this.clientRepository.findByClientId(token.getPrincipal());
    if (!clientInfo.isPresent()) {
      throw new SubAuthenticationException("Not registed Client Id");
    }

    

    return token.authenticated();
  }

}
