package com.example.letitgobaby.security.filter.sub;

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

import com.example.letitgobaby.security.token.sub.AuthGrantToken;

import lombok.extern.slf4j.Slf4j;


@Slf4j
public class SubTokenFilter extends AbstractAuthenticationProcessingFilter {

  public SubTokenFilter(RequestMatcher requestMatcher, AuthenticationManager authenticationManager) {
    super(requestMatcher, authenticationManager);
  }

  @Override
  public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) 
      throws AuthenticationException, IOException, ServletException {
    String client_id = request.getParameter("client_id");
    String client_secret = request.getParameter("client_secret");
    String grant_type = request.getParameter("grant_type");
    String redirect_uri = request.getParameter("redirect_uri");
    String code = request.getParameter("code");

    AuthGrantToken authentication = new AuthGrantToken(client_id, client_secret, grant_type, redirect_uri, code);
    return super.getAuthenticationManager().authenticate(authentication);
  }

  @Override
  public void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
      Authentication authResult) throws IOException, ServletException {
    log.info("# SubLoginFilter - successfulAuthentication # " + authResult.getPrincipal());
    super.getSuccessHandler().onAuthenticationSuccess(request, response, authResult);
  }

  @Override
  public void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
      AuthenticationException failed) throws IOException, ServletException {
    log.info("# SubLoginFilter - unsuccessfulAuthentication #", failed.getMessage());
    super.getFailureHandler().onAuthenticationFailure(request, response, failed);
  }
  
}
