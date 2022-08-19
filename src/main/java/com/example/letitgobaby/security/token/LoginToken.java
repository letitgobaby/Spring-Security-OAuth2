package com.example.letitgobaby.security.token;

import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

public class LoginToken extends AbstractAuthenticationToken {

  private String id;
  private String pw;

  public LoginToken(String id, String pw) {
    super(null);
    super.setAuthenticated(false);
    this.id = id;
    this.pw = pw;
  }

  public LoginToken(String id, Collection<? extends GrantedAuthority> authorities) {
    super(authorities);
    super.setAuthenticated(true);
    this.id = id;
  }

  @Override
  public Object getCredentials() {
    return this.pw;
  }

  @Override
  public Object getPrincipal() {
    return this.id;
  }
  
}
