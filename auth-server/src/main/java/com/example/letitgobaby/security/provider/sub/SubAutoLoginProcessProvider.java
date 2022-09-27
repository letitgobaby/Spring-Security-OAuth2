package com.example.letitgobaby.security.provider.sub;

import java.util.Random;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import com.example.letitgobaby.app.tokenStore.TokenStoreService;
import com.example.letitgobaby.model.ClientInfo;
import com.example.letitgobaby.model.ClientInfoRepository;
import com.example.letitgobaby.model.SubLogin;
import com.example.letitgobaby.model.SubLoginRepository;
import com.example.letitgobaby.model.TokenStore;
import com.example.letitgobaby.security.dto.UserInfo;
import com.example.letitgobaby.security.exception.SubAuthenticationException;
import com.example.letitgobaby.security.token.sub.SubAutoLoginToken;
import com.example.letitgobaby.utils.JWTBuilder;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;


@Slf4j
@Component
@RequiredArgsConstructor
public class SubAutoLoginProcessProvider implements AuthenticationProvider {

  private final ClientInfoRepository clientRepository;
  private final SubLoginRepository subLoginRepository;
  private final TokenStoreService tStoreService;
  private final JWTBuilder jwtBuilder;

  @Override
  public boolean supports(Class<?> authentication) {
    return SubAutoLoginToken.class.isAssignableFrom(authentication);
  }

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    SubAutoLoginToken auth = (SubAutoLoginToken) authentication;

    ClientInfo clientInfo = this.clientRepository.findByClientId(auth.getPrincipal())
      .orElseThrow(() -> new SubAuthenticationException("Not registed Client Id"));

    String rToken = this.tStoreService.getToken(auth.getToken());
    if (rToken == null) {
      return auth;
    }

    UserInfo userInfo = this.jwtBuilder.getClaim(rToken, "userInfo").as(UserInfo.class);

    SubLogin subLogin = SubLogin.builder()
      .clientId(clientInfo.getClientId())
      .redirectUri(auth.getRedirectUri())
      .allowScope(userInfo.getUserRole())
      .userToken(rToken)
      .code(randomString())
      .build();
    this.subLoginRepository.save(subLogin);

    auth.setCode(subLogin.getCode());
    return auth.authenticated();
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
