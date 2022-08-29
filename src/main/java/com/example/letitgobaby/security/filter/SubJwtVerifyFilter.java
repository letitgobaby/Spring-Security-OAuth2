package com.example.letitgobaby.security.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.letitgobaby.security.token.JwtToken;

import lombok.extern.slf4j.Slf4j;


@Slf4j
public class SubJwtVerifyFilter extends OncePerRequestFilter {

  private AuthenticationManager aManager;

  public SubJwtVerifyFilter(AuthenticationManager aManager) {
    this.aManager = aManager;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
    log.info("## SubJwtVerifyFilter ##");

    JwtToken token = new JwtToken("", request);
    Authentication authentication = this.aManager.authenticate(token);
        System.out.println(authentication.getPrincipal().toString());

    filterChain.doFilter(request, response);
  }
  
}
