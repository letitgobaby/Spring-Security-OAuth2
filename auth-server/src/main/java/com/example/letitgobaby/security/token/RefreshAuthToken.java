package com.example.letitgobaby.security.token;

import java.util.Collection;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

public class RefreshAuthToken extends AbstractAuthenticationToken {

  private String refreshToken;
  private HttpServletRequest request;

  public RefreshAuthToken(String rToken, HttpServletRequest request) {
    super(null);
    this.refreshToken = rToken;
    this.request = request;
  }

  public RefreshAuthToken(Collection<? extends GrantedAuthority> authorities) {
    super(authorities);
  }

  @Override
  public Object getCredentials() {
    return null;
  }

  @Override
  public String getPrincipal() {
    return this.refreshToken;
  }
  
  public String getIp() {
    return (null != request.getHeader("X-FORWARDED-FOR")) 
      ? request.getHeader("X-FORWARDED-FOR") 
      : request.getRemoteAddr();
  }

}
