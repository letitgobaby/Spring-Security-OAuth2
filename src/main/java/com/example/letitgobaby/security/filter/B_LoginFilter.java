package com.example.letitgobaby.security.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;

@Component
// @RequiredArgsConstructor
public class B_LoginFilter extends AbstractAuthenticationProcessingFilter {

  static final String requestMatcher = "/b/login";

  public B_LoginFilter(AuthenticationManager authenticationManager) {
    super(requestMatcher, authenticationManager);
  }

  @Override
  public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
      throws AuthenticationException, IOException, ServletException {
    
        System.out.println("\n\n");
        System.out.println("filter !!!!");
        System.out.println("\n\n");
    // TODO Auto-generated method stub
    return super.getAuthenticationManager().authenticate(null);
  }

  @Override
  protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
      Authentication authResult) throws IOException, ServletException {
    // TODO Auto-generated method stub
    super.successfulAuthentication(request, response, chain, authResult);
  }

  @Override
  protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
      AuthenticationException failed) throws IOException, ServletException {
    // TODO Auto-generated method stub
    super.unsuccessfulAuthentication(request, response, failed);
  }
  
}
