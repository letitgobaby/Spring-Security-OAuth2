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

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class SubAuthorizeFilter extends AbstractAuthenticationProcessingFilter {

  public SubAuthorizeFilter(RequestMatcher matcher, AuthenticationManager authenticationManager) {
    super(matcher, authenticationManager);
  }

  @Override
  public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
      throws AuthenticationException, IOException, ServletException {
        // response_type=code
        // client_id=dple3JolZrc9R877kmADdK9J
        // redirect_uri=https://www.oauth.com/playground/authorization-code.html
        // https://velog.io/@0xf4d3c0d3/OAuth-2.0
        // https://auth0.com/blog/refresh-tokens-what-are-they-and-when-to-use-them/
        // https://medium.com/typeforms-engineering-blog/the-beginners-guide-to-oauth-dancing-4b8f3666de10
    return null;
  }
  
  @Override
  public void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
      Authentication authResult) throws IOException, ServletException {
    log.info("# SubAuthorizeFilter - successfulAuthentication # " + authResult.getPrincipal());
    // super.getSuccessHandler().onAuthenticationSuccess(request, response, authResult);
    response.sendRedirect("");
  }

  @Override
  public void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
      AuthenticationException failed) throws IOException, ServletException {
    log.info("# SubAuthorizeFilter - unsuccessfulAuthentication #", failed.getMessage());
    super.getFailureHandler().onAuthenticationFailure(request, response, failed);
  }

}
