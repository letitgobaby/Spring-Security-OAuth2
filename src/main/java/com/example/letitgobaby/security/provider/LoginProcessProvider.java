package com.example.letitgobaby.security.provider;

import java.util.Optional;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import com.example.letitgobaby.app.tokenStore.TokenStoreService;
import com.example.letitgobaby.model.TokenStore;
import com.example.letitgobaby.model.TokenStoreRepository;
import com.example.letitgobaby.model.User;
import com.example.letitgobaby.model.UserRepository;
import com.example.letitgobaby.security.dto.UserInfo;
import com.example.letitgobaby.security.enums.SecurityCode;
import com.example.letitgobaby.security.token.AuthUserToken;
import com.example.letitgobaby.security.token.LoginToken;
import com.example.letitgobaby.utils.JWTBuilder;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
@RequiredArgsConstructor
public class LoginProcessProvider implements AuthenticationProvider {
  
  private final UserRepository userRepository;
  private final TokenStoreService tStoreService;
  private final JWTBuilder jwtBuilder;
  private final PasswordEncoder encoder;
  
  @Override
  public boolean supports(Class<?> authentication) {
    return LoginToken.class.isAssignableFrom(authentication);
  }

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    log.info("## do LoginProcessProvider ##");
    LoginToken authToken = (LoginToken) authentication;
    String userId = authToken.getPrincipal();
    String pswd = authToken.getCredentials();

    User user = this.userRepository.findByUserId(userId)
      .orElseThrow(() -> new UsernameNotFoundException(SecurityCode.USER_NOT_FOUND.getValue()));

    if (!this.encoder.matches(pswd, user.getPassword())) {
      throw new BadCredentialsException(SecurityCode.BAD_CREDENTIAL.getValue());
    }

    try {
      UserInfo userInfo = new UserInfo().toDto(user);
      userInfo.setLoginIp(authToken.getIp());

      String refreshToken = this.tStoreService.setToken(userInfo);
      String accessToken = this.jwtBuilder.accessGenerate(userInfo);

      AuthUserToken authenticated = new AuthUserToken(user.getUserId(), user.getUserRole());
      authenticated.setToken(accessToken, refreshToken);
      return authenticated;
    } catch (Exception e) {
      log.error(e.getMessage());
      return null;
    }
  }
  
}
