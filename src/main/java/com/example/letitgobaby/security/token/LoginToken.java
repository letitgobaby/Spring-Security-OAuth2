package com.example.letitgobaby.security.token;

import java.util.Collection;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

public class LoginToken extends AbstractAuthenticationToken {

  private String id;
  private String pw;
  private HttpServletRequest request;

  public LoginToken(String id, String pw) {
    super(null);
    super.setAuthenticated(false);
    this.id = id;
    this.pw = pw;
  }

  public LoginToken(String id, String pw, HttpServletRequest request) {
    super(null);
    super.setAuthenticated(false);
    this.id = id;
    this.pw = pw;
    this.request = request;
  }

  public LoginToken(String id, Collection<? extends GrantedAuthority> authorities) {
    super(authorities);
    super.setAuthenticated(true);
    this.id = id;
  }

  @Override
  public String getPrincipal() {
    return this.id;
  }

  @Override
  public String getCredentials() {
    return this.pw;
  }

  public String getIp() {
    return (null != request.getHeader("X-FORWARDED-FOR")) 
      ? request.getHeader("X-FORWARDED-FOR") 
      : request.getRemoteAddr();
  }
  
}
