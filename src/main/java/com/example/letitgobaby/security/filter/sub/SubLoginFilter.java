package com.example.letitgobaby.security.filter.sub;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;

import com.example.letitgobaby.security.token.AuthUserToken;
import com.example.letitgobaby.security.token.LoginToken;

import lombok.extern.slf4j.Slf4j;


@Slf4j
public class SubLoginFilter extends AbstractAuthenticationProcessingFilter {

  public SubLoginFilter(RequestMatcher requestMatcher, AuthenticationManager authenticationManager) {
    super(requestMatcher, authenticationManager);
  }

  @Override
  public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) 
      throws AuthenticationException, IOException, ServletException {
    String id = request.getParameter("id");
    String pw = request.getParameter("pw");

    LoginToken authentication = new LoginToken(id, pw, request);
    return super.getAuthenticationManager().authenticate(authentication);
  }

  public void setSuccessHandler(AuthenticationSuccessHandler successHandler) {
    super.setAuthenticationSuccessHandler(successHandler);
  }

  @Override
  public void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
      Authentication authResult) throws IOException, ServletException {
    log.info("# B_LoginFilter - successfulAuthentication # " + authResult.getPrincipal());
    super.getSuccessHandler().onAuthenticationSuccess(request, response, authResult);
  }

  @Override
  public void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
      AuthenticationException failed) throws IOException, ServletException {
    log.info("# B_LoginFilter - unsuccessfulAuthentication #", failed.getMessage());
    super.getFailureHandler().onAuthenticationFailure(request, response, failed);
  }
  
}
