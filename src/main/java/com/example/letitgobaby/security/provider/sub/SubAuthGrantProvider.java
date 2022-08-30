package com.example.letitgobaby.security.provider.sub;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import com.example.letitgobaby.app.tokenStore.TokenStoreService;
import com.example.letitgobaby.model.ClientInfo;
import com.example.letitgobaby.model.ClientInfoRepository;
import com.example.letitgobaby.model.SubLogin;
import com.example.letitgobaby.model.SubLoginRepository;
import com.example.letitgobaby.model.TokenStore;
import com.example.letitgobaby.model.TokenStoreRepository;
import com.example.letitgobaby.model.User;
import com.example.letitgobaby.model.UserRepository;
import com.example.letitgobaby.security.dto.UserInfo;
import com.example.letitgobaby.security.enums.SecurityCode;
import com.example.letitgobaby.security.exception.SubAuthenticationException;
import com.example.letitgobaby.security.token.AuthUserToken;
import com.example.letitgobaby.security.token.LoginToken;
import com.example.letitgobaby.security.token.sub.AuthGrantToken;
import com.example.letitgobaby.utils.JWTBuilder;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
@RequiredArgsConstructor
public class SubAuthGrantProvider implements AuthenticationProvider {
  
  private final UserRepository userRepository;
  private final SubLoginRepository subLoginRepository;
  private final ClientInfoRepository clientRepository;
  private final TokenStoreService tStoreService;
  private final JWTBuilder jwtBuilder;
  private final PasswordEncoder encoder;
  
  @Override
  public boolean supports(Class<?> authentication) {
    return AuthGrantToken.class.isAssignableFrom(authentication);
  }

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    log.info("## do SubLoginProcessProvider ##");
    AuthGrantToken authToken = (AuthGrantToken) authentication;
    if (!authToken.getGrantType().equals("authorization_code")) {
      throw new SubAuthenticationException("Grant Type Not Allowed");
    }

    ClientInfo client = this.clientRepository.findByClientId(authToken.getPrincipal())
      .orElseThrow(() -> new SubAuthenticationException("Not found Client ID"));

    if (!this.encoder.matches(client.getClientSecret(), authToken.getCredentials())) {
      throw new SubAuthenticationException("Not Match ID and Secret");
    }

    SubLogin subLogin = this.subLoginRepository.findByClientId(authToken.getPrincipal())
      .orElseThrow(() -> new SubAuthenticationException("Not found Client ID"));

    if (!subLogin.getClientSecret().equals(authToken.getCode())) {
      throw new SubAuthenticationException("Not Match Authorization Code");
    }
    
    // Should do Encode Data !!!!, it's just for Test
    String userId = authToken.getCode(); // CODE = User ID + role

    User user = this.userRepository.findByUserId(userId)
      .orElseThrow(() -> new SubAuthenticationException("User Not Found"));

    try {
      UserInfo userInfo = new UserInfo().toDto(user);
      userInfo.setUserRole("SUB_USER");

      String refreshToken = this.tStoreService.setToken(userInfo);
      String accessToken = this.jwtBuilder.accessGenerate(userInfo);
      authToken.setAccessRefreshToken(accessToken, refreshToken);
      return authToken;
    } catch (Exception e) {
      log.error(e.getMessage());
      return null;
    }
  }
  
}
