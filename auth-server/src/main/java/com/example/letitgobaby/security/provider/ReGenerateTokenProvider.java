package com.example.letitgobaby.security.provider;

import java.util.Calendar;
import java.util.Date;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.letitgobaby.app.tokenStore.TokenStoreService;
import com.example.letitgobaby.security.dto.UserInfo;
import com.example.letitgobaby.security.enums.SecurityCode;
import com.example.letitgobaby.security.exception.JwtAuthenticationException;
import com.example.letitgobaby.security.exception.LoginAuthenticationException;
import com.example.letitgobaby.security.token.AuthUserToken;
import com.example.letitgobaby.security.token.RefreshAuthToken;
import com.example.letitgobaby.utils.JWTBuilder;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
@RequiredArgsConstructor
public class ReGenerateTokenProvider implements AuthenticationProvider {

  private final JWTBuilder jwtBuilder;
  private final TokenStoreService tStoreService;
  
  @Override
  public boolean supports(Class<?> authentication) {
    return RefreshAuthToken.class.isAssignableFrom(authentication);
  }

  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    try {
      RefreshAuthToken payload = (RefreshAuthToken) authentication;
      String refreshToken = this.tStoreService.getToken(payload.getPrincipal());
      if (refreshToken == null) {
        throw new JwtAuthenticationException(SecurityCode.TOKEN_NOT_FOUND.getValue());
      }

      if (this.jwtBuilder.validate(refreshToken)) {
        DecodedJWT decodedJwt = this.jwtBuilder.decode(refreshToken);
        UserInfo userInfo = decodedJwt.getClaim("userInfo").as(UserInfo.class);
  
        // 로그인 한 곳과 같은 IP만 인증처리
        if (!userInfo.getLoginIp().equals(payload.getIp())) {
          throw new LoginAuthenticationException(SecurityCode.LOGIN_IP_NOT_VALID.getValue());
        }
        
        if (isWarningExpiredTime(decodedJwt.getExpiresAt())) {
          refreshToken = this.tStoreService.setToken(userInfo);
        } else {
          refreshToken = payload.getPrincipal();
        }

        String accessToken = this.jwtBuilder.accessGenerate(userInfo);

        AuthUserToken authenticated = new AuthUserToken(userInfo.getUserId(), userInfo.getUserRole());
        authenticated.setToken(accessToken, refreshToken);
        return authenticated;
      }

      return null;
    } catch (Exception e) {
      log.error(e.getMessage());
      throw new JwtAuthenticationException(e.getMessage());
    }
  }

  private boolean isWarningExpiredTime(Date tokenTime) {
    Calendar cal = Calendar.getInstance();
    cal.setTime(tokenTime);
    cal.add(Calendar.DATE, -1);
    return new Date().after(cal.getTime()) ? true : false;
  }
  
}
