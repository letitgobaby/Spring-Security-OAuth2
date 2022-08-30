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

import com.example.letitgobaby.security.token.sub.AuhorizeToken;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class SubAuthorizeFilter extends AbstractAuthenticationProcessingFilter {

  public SubAuthorizeFilter(RequestMatcher matcher, AuthenticationManager authenticationManager) {
    super(matcher, authenticationManager);
  }

  @Override
  public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
      throws AuthenticationException, IOException, ServletException {
    String resType = request.getParameter("response_type");
    String clientId = request.getParameter("client_id");
    String redirectUri = request.getParameter("redirect_uri");

    AuhorizeToken authentication = new AuhorizeToken(resType, clientId, redirectUri);
    return super.getAuthenticationManager().authenticate(authentication);
  }
  
  @Override
  public void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
      Authentication authResult) throws IOException, ServletException {
    AuhorizeToken authentication = (AuhorizeToken) authResult;
    log.info("# SubAuthorizeFilter - successfulAuthentication # " + authentication.getPrincipal() + " - " + authentication.getRedirectUri());

    String redirectUrl = "/sub/loginpage?client_id=" + authentication.getPrincipal() + "&redirect_uri=" + authentication.getRedirectUri();
    response.sendRedirect(redirectUrl);
  }

  @Override
  public void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
      AuthenticationException failed) throws IOException, ServletException {
    log.info("# SubAuthorizeFilter - unsuccessfulAuthentication #", failed.getMessage());
    super.getFailureHandler().onAuthenticationFailure(request, response, failed);
  }

  private String getAuthorization(HttpServletRequest request){
    String token = request.getHeader("Authorization");
    if(token == null) {
      return null;
    }

    String aToken = token.substring("Bearer ".length());
    return aToken.length() > 1 ? aToken : null;
  }

}
