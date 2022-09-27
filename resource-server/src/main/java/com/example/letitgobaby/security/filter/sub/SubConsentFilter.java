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

import com.example.letitgobaby.security.token.sub.ConsentToken;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class SubConsentFilter extends AbstractAuthenticationProcessingFilter {

  public SubConsentFilter(RequestMatcher requiresAuthenticationRequestMatcher,
      AuthenticationManager authenticationManager) {
    super(requiresAuthenticationRequestMatcher, authenticationManager);
  }

  @Override
  public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
      throws AuthenticationException, IOException, ServletException {
    String clientId = request.getParameter("client_id");
    String redirectUri = request.getParameter("redirect_uri");
    String scope = request.getParameter("scope");
    String userInfo = request.getParameter("at");

    ConsentToken authentication = new ConsentToken(scope, clientId, redirectUri, userInfo);
    return super.getAuthenticationManager().authenticate(authentication);
  }
    
  @Override
  public void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
      Authentication authResult) throws IOException, ServletException {
        ConsentToken authentication = (ConsentToken) authResult;
    log.info("# SubConsentFilter - successfulAuthentication # " + authentication.getPrincipal() + " - " + authentication.getRedirectUri());
    String redirectUrl = authentication.getRedirectUri() + "?code=" + authentication.getCode();
    response.sendRedirect(redirectUrl);
  }

  @Override
  public void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
      AuthenticationException failed) throws IOException, ServletException {
    log.info("# SubConsentFilter - unsuccessfulAuthentication #", failed.getMessage());
    super.getFailureHandler().onAuthenticationFailure(request, response, failed);
  }

}
