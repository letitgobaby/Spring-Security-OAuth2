package com.example.letitgobaby.security.filter.sub;

import java.io.IOException;
import java.util.Arrays;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

import com.example.letitgobaby.security.token.sub.AuhorizeToken;
import com.example.letitgobaby.security.token.sub.SubAutoLoginToken;

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

    // Authentication authentication = null;

    String refreshToken = getCookieValue(request, "R_TOKEN");
    if (refreshToken != null) {
      return super.getAuthenticationManager().authenticate(
        new SubAutoLoginToken(clientId, redirectUri, refreshToken)
      );
    }

    AuhorizeToken authentication = new AuhorizeToken(resType, clientId, redirectUri);
    return super.getAuthenticationManager().authenticate(authentication);
  }
  
  @Override
  public void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
      Authentication authResult) throws IOException, ServletException {
    log.info("# SubAuthorizeFilter - successfulAuthentication # ");
    
    if (authResult instanceof SubAutoLoginToken) {
      SubAutoLoginToken authentication = (SubAutoLoginToken) authResult;
      if (authentication.getCode() == null) {
        clearCookie(response);
        response.sendRedirect(request.getRequestURI() + "?" + request.getQueryString());
        return;
      }

      String redirectUrl = authentication.getRedirectUri() + "?code=" + authentication.getCode();
      response.sendRedirect(redirectUrl);
    }

    if (authResult instanceof AuhorizeToken) {
      AuhorizeToken authentication = (AuhorizeToken) authResult;
      String redirectUrl = "/sub/loginpage?client_id=" 
        + authentication.getPrincipal() 
        + "&redirect_uri=" + authentication.getRedirectUri();
      response.sendRedirect(redirectUrl);
    }
  }

  @Override
  public void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
      AuthenticationException failed) throws IOException, ServletException {
    log.info("# SubAuthorizeFilter - unsuccessfulAuthentication # - " + failed.getMessage());
    clearCookie(response);
    super.getFailureHandler().onAuthenticationFailure(request, response, failed);
  }

  private String getCookieValue(HttpServletRequest req, String cookieName) {
    if (req.getCookies() == null) return null;
    return Arrays.stream(req.getCookies())
      .filter(c -> c.getName().equals(cookieName))
      .findFirst()
      .map(Cookie::getValue)
      .orElse(null);
  }

  private void clearCookie(HttpServletResponse response) {
    Cookie coo = new Cookie("R_TOKEN", null);
    coo.setMaxAge(0);
    response.addCookie(coo);
  }



}
