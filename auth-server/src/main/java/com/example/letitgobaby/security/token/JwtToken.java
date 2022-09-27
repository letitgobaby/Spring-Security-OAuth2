package com.example.letitgobaby.security.token;

import java.util.Collection;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

public class JwtToken extends AbstractAuthenticationToken {

  private String jwtToken;
  private HttpServletRequest request;

  public JwtToken(String token) {
    super(null);
    super.setAuthenticated(false);
    this.jwtToken = token;
  }

  public JwtToken(String token, HttpServletRequest request) {
    super(null);
    super.setAuthenticated(false);
    this.jwtToken = token;
    this.request = request;
  }

  public JwtToken(Collection<? extends GrantedAuthority> authorities) {
    super(authorities);
  }

  @Override
  public String getPrincipal() {
    return this.jwtToken;
  }

  @Override
  public Object getCredentials() {
    return null;
  }
  
  public String getIp() {
    return (null != request.getHeader("X-FORWARDED-FOR")) 
      ? request.getHeader("X-FORWARDED-FOR") 
      : request.getRemoteAddr();
  }

}
