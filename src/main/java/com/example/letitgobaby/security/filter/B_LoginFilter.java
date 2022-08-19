package com.example.letitgobaby.security.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

import com.example.letitgobaby.security.token.AuthUserToken;

import lombok.extern.slf4j.Slf4j;


@Slf4j
public class B_LoginFilter extends AbstractAuthenticationProcessingFilter {

  public B_LoginFilter(RequestMatcher requestMatcher, AuthenticationManager authenticationManager) {
    super(requestMatcher, authenticationManager);
  }

  @Override
  public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
    String id = request.getParameter("id");
    String pw = request.getParameter("pw");

    AuthUserToken authentication = new AuthUserToken(id, pw);
    return super.getAuthenticationManager().authenticate(authentication);
  }

  @Override
  protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
      Authentication authResult) throws IOException, ServletException {
    log.info("# B_LoginFilter - successfulAuthentication #");
    super.successfulAuthentication(request, response, chain, authResult);
  }

  @Override
  protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
      AuthenticationException failed) throws IOException, ServletException {
    log.info("# B_LoginFilter - unsuccessfulAuthentication #", failed.getMessage());
    super.unsuccessfulAuthentication(request, response, failed);
  }
  
}
