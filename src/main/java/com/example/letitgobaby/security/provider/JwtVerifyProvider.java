package com.example.letitgobaby.security.provider;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import com.auth0.jwt.exceptions.TokenExpiredException;
import com.example.letitgobaby.security.dto.UserInfo;
import com.example.letitgobaby.security.exception.JwtAuthenticationException;
import com.example.letitgobaby.security.exception.LoginAuthenticationException;
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
  public boolean supports(Class<?> authentication) {
    return JwtToken.class.isAssignableFrom(authentication);
  }

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    try {
      JwtToken jwtToken = (JwtToken) authentication;
      String token = jwtToken.getPrincipal();
      
      log.info(" -- JwtVerifyProvider -- " + token);

      if (this.jwtBuilder.validate(token)) {
        UserInfo userInfo = this.jwtBuilder.getClaim(token, "userInfo").as(UserInfo.class);

        // 로그인 한 곳과 같은 IP만 인증처리
        if (userInfo.getLoginIp().equals(jwtToken.getIp())) {
          List<GrantedAuthority> roles = new ArrayList<GrantedAuthority>();
          roles.add(new SimpleGrantedAuthority("ROLE_USER"));
          return new AuthUserToken(userInfo.getUserId(), roles);
        }
      }

      return null;
    } catch (TokenExpiredException e) {
      throw new LoginAuthenticationException(e.getMessage());
    } catch (Exception e) {
      throw new JwtAuthenticationException(e.getMessage());
    }
  }

}
