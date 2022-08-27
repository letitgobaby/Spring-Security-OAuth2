package com.example.letitgobaby.security.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.letitgobaby.security.exception.LoginAuthenticationException;
import com.example.letitgobaby.security.token.JwtToken;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class JwtVerifyFilter extends OncePerRequestFilter {

  private AuthenticationManager authenticationManager;
  private AuthenticationEntryPoint authenticationEntryPoint;

  public void setAuthenticationManager(AuthenticationManager authenticationManager) {
    this.authenticationManager = authenticationManager;
  }

  public void setAuthenticationFailureHandler(AuthenticationEntryPoint entryPoint) {
    this.authenticationEntryPoint = entryPoint;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
    log.info("## JwtVerifyFilter ##");
    try {
      String authorization = getAuthorization(request);
      if (authorization != null) {
        JwtToken token = new JwtToken(authorization, request);
        Authentication authentication = this.authenticationManager.authenticate(token);
        SecurityContextHolder.getContext().setAuthentication(authentication);
      }

    } catch (AuthenticationException e) {
      this.authenticationEntryPoint.commence(request, response, e); return;
    }

    chain.doFilter(request, response);
  }

  private String getAuthorization(HttpServletRequest request){
    String token = request.getHeader("Authorization");
    if(token == null) {
        return null;
    }

    return token.substring("Bearer ".length());
  }
}
