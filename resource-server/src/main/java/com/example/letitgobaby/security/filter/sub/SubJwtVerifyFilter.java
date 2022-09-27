package com.example.letitgobaby.security.filter.sub;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.web.filter.OncePerRequestFilter;

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
    
    filterChain.doFilter(request, response);
  }
  
}
