package com.example.letitgobaby.security.filter;

import java.io.IOException;
import java.util.Arrays;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

import com.example.letitgobaby.security.token.RefreshAuthToken;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class RefreshTokenFilter extends AbstractAuthenticationProcessingFilter {

  public RefreshTokenFilter(RequestMatcher requestMatcher, AuthenticationManager authenticationManager) {
    super(requestMatcher, authenticationManager);
  }

  @Override
  public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
      throws AuthenticationException, IOException, ServletException {
    String refreshToken = getCookieValue(request, "R_TOKEN");
    RefreshAuthToken authentication = new RefreshAuthToken(refreshToken, request);
    return super.getAuthenticationManager().authenticate(authentication);
  }

  @Override
  public void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
      Authentication authResult) throws IOException, ServletException {
    log.info("# RefreshTokenFilter - successfulAuthentication # " + authResult.getPrincipal());
    super.getSuccessHandler().onAuthenticationSuccess(request, response, authResult);
  }

  @Override
  public void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
      AuthenticationException failed) throws IOException, ServletException {
    log.info("# RefreshTokenFilter - unsuccessfulAuthentication #", failed.getMessage());
    super.getFailureHandler().onAuthenticationFailure(request, response, failed);
  }
  
  private String getCookieValue(HttpServletRequest req, String cookieName) {
    return Arrays.stream(req.getCookies())
      .filter(c -> c.getName().equals(cookieName))
      .findFirst()
      .map(Cookie::getValue)
      .orElse(null);
}

}
