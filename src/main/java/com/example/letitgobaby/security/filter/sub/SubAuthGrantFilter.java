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

import com.example.letitgobaby.security.dto.SubAuthGrantPayload;
import com.example.letitgobaby.security.token.sub.AuthGrantToken;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.extern.slf4j.Slf4j;


@Slf4j
public class SubAuthGrantFilter extends AbstractAuthenticationProcessingFilter {

  public SubAuthGrantFilter(RequestMatcher requestMatcher, AuthenticationManager authenticationManager) {
    super(requestMatcher, authenticationManager);
  }

  @Override
  public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) 
      throws AuthenticationException, IOException, ServletException {
    String requestBody = StreamUtils.copyToString(request.getInputStream(), Charset.forName("UTF-8"));
    SubAuthGrantPayload paylod = new ObjectMapper().readValue(requestBody, SubAuthGrantPayload.class);

    AuthGrantToken authentication = new AuthGrantToken(paylod);
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
