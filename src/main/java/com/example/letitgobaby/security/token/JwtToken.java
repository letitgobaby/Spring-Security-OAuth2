package com.example.letitgobaby.security.token;

import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

public class JwtToken extends AbstractAuthenticationToken {

  private String jwtToken;

  public JwtToken(String token) {
    super(null);
    super.setAuthenticated(false);
    this.jwtToken = token;
  }

  public JwtToken(Collection<? extends GrantedAuthority> authorities) {
    super(authorities);
    //TODO Auto-generated constructor stub
  }

  @Override
  public Object getCredentials() {
    // TODO Auto-generated method stub
    return null;
  }

  @Override
  public Object getPrincipal() {
    // TODO Auto-generated method stub
    return null;
  }
  
}
