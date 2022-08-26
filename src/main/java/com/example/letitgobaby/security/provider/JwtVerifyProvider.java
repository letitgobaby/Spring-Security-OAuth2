package com.example.letitgobaby.security.provider;

import java.util.Optional;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import com.auth0.jwt.interfaces.Claim;
import com.example.letitgobaby.model.User;
import com.example.letitgobaby.model.UserRepository;
import com.example.letitgobaby.security.dto.UserInfo;
import com.example.letitgobaby.security.exception.JwtAuthenticationException;
import com.example.letitgobaby.security.token.AuthUserToken;
import com.example.letitgobaby.security.token.JwtToken;
import com.example.letitgobaby.utils.JWTBuilder;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtVerifyProvider implements AuthenticationProvider {
  
  private final JWTBuilder jwtBuilder;

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    try {
      String token = (String) authentication.getPrincipal();
      if (token != null && this.jwtBuilder.validate(token)) {
        Claim cliam = this.jwtBuilder.getClaim(token, "userInfo");
        UserInfo userInfo = cliam.as(UserInfo.class);

        return new AuthUserToken(userInfo.getUserId(), userInfo.getUserRole());
      }

      return null;
    } catch (Exception e) {
      log.error(e.getMessage());
      throw new JwtAuthenticationException(e.getMessage());
    }
  }

  @Override
  public boolean supports(Class<?> authentication) {
    return JwtToken.class.isAssignableFrom(authentication);
  }

}
