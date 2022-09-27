package com.example.letitgobaby.security.filter.sub;


import java.io.IOException;
import java.nio.charset.Charset;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StreamUtils;

import com.example.letitgobaby.security.dto.LoginInfoPayload;
import com.example.letitgobaby.security.token.LoginToken;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class SubLoginFilter extends AbstractAuthenticationProcessingFilter {
  
  public SubLoginFilter(RequestMatcher requestMatcher, AuthenticationManager authenticationManager) {
    super(requestMatcher, authenticationManager);
  }

  @Override
  public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
      throws AuthenticationException, IOException, ServletException {
    String requestBody = StreamUtils.copyToString(request.getInputStream(), Charset.forName("UTF-8"));
    LoginInfoPayload paylod = new ObjectMapper().readValue(requestBody, LoginInfoPayload.class);

    LoginToken authentication = new LoginToken(paylod.getUserId(), paylod.getPswd(), request);
    return super.getAuthenticationManager().authenticate(authentication);
  }

  @Override
  protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
      Authentication authResult) throws IOException, ServletException {
    log.info("# SubLoginFilter - successfulAuthentication # " + authResult.getPrincipal());
    super.getSuccessHandler().onAuthenticationSuccess(request, response, authResult);
  }

  @Override
  protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
      AuthenticationException failed) throws IOException, ServletException {
    log.info("# SubLoginFilter - unsuccessfulAuthentication #", failed.getMessage());
    super.getFailureHandler().onAuthenticationFailure(request, response, failed);
  }

}
